using System.Collections.Concurrent;
using System.Threading.Channels;
using NetHunter.Core.Models;
using NetHunter.Core.Util;

namespace NetHunter.Core.Intel;

public enum IntelStatus { NoProviders, Online, Offline, Disabled }

public sealed record ApiQueryLog(DateTimeOffset Time, string Provider, IocType Type, string Value, ReputationStatus Outcome);

/// <summary>
/// Orchestrates reputation lookups: local lists first (synchronous, offline), then remote providers via one
/// background worker per provider with its own priority queue, rate limiter and cache. Monitoring never waits on this.
/// </summary>
public sealed class ReputationService : IAsyncDisposable
{
    private readonly LocalIocProvider _local;
    private readonly List<ProviderWorker> _workers = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Func<bool> _globallyEnabled;
    private int _consecutiveNetworkFailures;
    private DateTimeOffset _offlineSince;
    private readonly string _disabledReason;

    public ReputationService(LocalIocDatabase localDb, IEnumerable<IRemoteReputationProvider> remote, ReputationCache cache, Func<bool>? globallyEnabled = null, string? disabledReason = null)
    {
        _disabledReason = disabledReason ?? "Threat intelligence disabled (privacy setting)";
        _local = new LocalIocProvider(localDb);
        Cache = cache;
        LocalDb = localDb;
        _globallyEnabled = globallyEnabled ?? (() => true);
        foreach (var p in remote) _workers.Add(new ProviderWorker(this, p));
    }

    public ReputationCache Cache { get; }
    public LocalIocDatabase LocalDb { get; }
    public IReadOnlyList<IRemoteReputationProvider> RemoteProviders => _workers.Select(w => w.Provider).ToList();

    /// <summary>Raised on a worker thread whenever a remote result arrives.</summary>
    public event Action<ReputationResult>? ResultAvailable;
    /// <summary>Raised for every outbound API call, so the UI can show exactly what was sent where.</summary>
    public event Action<ApiQueryLog>? ApiQueried;

    public IntelStatus Status
    {
        get
        {
            if (!_globallyEnabled()) return IntelStatus.Disabled;
            if (!_workers.Any(w => w.Provider.IsEnabled)) return IntelStatus.NoProviders;
            return Volatile.Read(ref _consecutiveNetworkFailures) >= 1 ? IntelStatus.Offline : IntelStatus.Online;
        }
    }

    public string StatusText => Status switch
    {
        IntelStatus.Disabled => _disabledReason,
        IntelStatus.NoProviders => "No reputation providers configured (local IOC lists only)",
        IntelStatus.Offline => $"Threat intelligence unavailable: offline since {_offlineSince.ToLocalTime():T}",
        _ => "Threat intelligence online",
    };

    public int PendingLookups => _workers.Sum(w => w.Pending);

    public void Start()
    {
        foreach (var w in _workers) w.Start(_cts.Token);
    }

    public ReputationResult CheckLocal(IocType type, string value) => _local.Lookup(type, value);

    /// <summary>All known results (local + cached remote) for an indicator.</summary>
    public IReadOnlyList<ReputationResult> GetKnown(IocType type, string value)
    {
        var list = new List<ReputationResult>();
        var local = CheckLocal(type, value);
        if (local.Status == ReputationStatus.Ok) list.Add(local);
        list.AddRange(Cache.GetAll(type, value));
        return list;
    }

    /// <summary>
    /// Queue a remote lookup. Private/reserved addresses are never sent anywhere (privacy + pointless).
    /// Higher priority is served first; duplicates and cached values are ignored.
    /// </summary>
    public void Enqueue(IocType type, string value, int priority, bool allowDocumentationRanges = false)
    {
        if (!_globallyEnabled()) return;
        if (type == IocType.Ip && (!IpUtil.TryParse(value, out var ip) || !IpUtil.IsExternal(ip, allowDocumentationRanges))) return;
        if (type == IocType.Domain && !DomainUtil.IsValid(value)) return;
        foreach (var w in _workers)
        {
            if (!w.Provider.IsEnabled || !w.Provider.Supports(type)) continue;
            if (Cache.TryGet(w.Provider.Name, type, value, out _)) continue;
            w.Enqueue(type, value, priority);
        }
    }

    private void OnResult(IRemoteReputationProvider p, ReputationResult r)
    {
        if (r.Status == ReputationStatus.Offline)
        {
            if (Interlocked.Increment(ref _consecutiveNetworkFailures) == 1) _offlineSince = DateTimeOffset.Now;
        }
        else if (r.Status is ReputationStatus.Ok or ReputationStatus.NotFound or ReputationStatus.Error)
        {
            Interlocked.Exchange(ref _consecutiveNetworkFailures, 0);
        }
        Cache.Put(r);
        ApiQueried?.Invoke(new ApiQueryLog(DateTimeOffset.Now, p.Name, r.Type, r.Value, r.Status));
        ResultAvailable?.Invoke(r);
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        foreach (var w in _workers) await w.StopAsync().ConfigureAwait(false);
        _cts.Dispose();
    }

    private sealed class ProviderWorker
    {
        private const int MaxQueue = 5000;
        private readonly ReputationService _owner;
        private readonly object _lock = new();
        private readonly PriorityQueue<(IocType Type, string Value), int> _queue = new();
        private readonly HashSet<string> _queued = new(StringComparer.OrdinalIgnoreCase);
        private readonly SemaphoreSlim _signal = new(0);
        private Task? _task;

        public ProviderWorker(ReputationService owner, IRemoteReputationProvider provider) { _owner = owner; Provider = provider; }
        public IRemoteReputationProvider Provider { get; }
        public int Pending { get { lock (_lock) return _queue.Count; } }

        public void Enqueue(IocType type, string value, int priority)
        {
            lock (_lock)
            {
                if (!_queued.Add($"{(int)type}|{value}")) return;
                if (_queue.Count >= MaxQueue)
                {
                    // Drop the lowest-priority item rather than grow without bound.
                    var items = new List<((IocType, string), int)>();
                    while (_queue.TryDequeue(out var it, out var pr)) items.Add((it, pr));
                    items.Sort((a, b) => b.Item2.CompareTo(a.Item2));
                    var dropped = items[^1];
                    items.RemoveAt(items.Count - 1);
                    _queued.Remove($"{(int)dropped.Item1.Item1}|{dropped.Item1.Item2}");
                    foreach (var (it, pr) in items) _queue.Enqueue(it, pr);
                }
                _queue.Enqueue((type, value), -priority); // PriorityQueue is a min-heap
            }
            _signal.Release();
        }

        public void Start(CancellationToken ct) => _task = Task.Run(() => RunAsync(ct), ct);

        public async Task StopAsync()
        {
            if (_task is null) return;
            try { await _task.ConfigureAwait(false); } catch (OperationCanceledException) { }
        }

        private async Task RunAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                await _signal.WaitAsync(ct).ConfigureAwait(false);
                (IocType Type, string Value) item;
                lock (_lock)
                {
                    if (!_queue.TryDequeue(out item, out _)) continue;
                    _queued.Remove($"{(int)item.Type}|{item.Value}");
                }
                if (!Provider.IsEnabled || _owner.Cache.TryGet(Provider.Name, item.Type, item.Value, out _)) continue;

                // Wait for the rate limiter instead of dropping work.
                while (!Provider.Limiter.TryAcquire(DateTimeOffset.UtcNow, out var retryAt))
                {
                    var wait = retryAt - DateTimeOffset.UtcNow;
                    await Task.Delay(wait < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : wait > TimeSpan.FromMinutes(5) ? TimeSpan.FromMinutes(5) : wait, ct).ConfigureAwait(false);
                }

                ReputationResult r;
                try { r = await Provider.LookupAsync(item.Type, item.Value, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
                catch (Exception ex)
                {
                    r = new ReputationResult { Provider = Provider.Name, Type = item.Type, Value = item.Value, Status = ReputationStatus.Error, Detail = ex.GetType().Name };
                }
                _owner.OnResult(Provider, r);

                if (r.Status == ReputationStatus.Offline)
                {
                    // Keep the item; retry after a pause so an outage does not burn through the queue.
                    Enqueue(item.Type, item.Value, 0);
                    await Task.Delay(TimeSpan.FromSeconds(60), ct).ConfigureAwait(false);
                }
                else if (r.Status == ReputationStatus.RateLimited)
                {
                    Enqueue(item.Type, item.Value, 0);
                }
            }
        }
    }
}
