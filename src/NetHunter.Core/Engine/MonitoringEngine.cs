using System.Collections.Concurrent;
using System.Net;
using System.Threading.Channels;
using NetHunter.Core.Detection;
using NetHunter.Core.Intel;
using NetHunter.Core.Models;
using NetHunter.Core.Storage;
using NetHunter.Core.Util;

namespace NetHunter.Core.Engine;

/// <summary>What changed since the last batch. Raised about once per second from a background thread.</summary>
public sealed class EngineBatch
{
    public List<ConnectionEvent> Events { get; } = new();
    public List<FlowRecord> Flows { get; } = new();
    public List<DnsEventRecord> Dns { get; } = new();
    public List<AlertRecord> Alerts { get; } = new();
    /// <summary>Alerts whose severity is new or increased and that meet the notification threshold.</summary>
    public List<AlertRecord> Notify { get; } = new();
    public bool IsEmpty => Events.Count == 0 && Flows.Count == 0 && Dns.Count == 0 && Alerts.Count == 0;
}

public sealed class HostnameInfo
{
    public List<string> DnsNames { get; } = new();
    public string? Ptr { get; set; }
    public bool PtrAttempted { get; set; }
    public string? Sni { get; set; }
    public string? Best => DnsNames.Count > 0 ? DnsNames[0] : Sni;
}

public sealed class EngineDependencies
{
    public required AppSettings Settings { get; init; }
    public required Database Database { get; init; }
    public required ReputationService Reputation { get; init; }
    public required IProcessInfoProvider Processes { get; init; }
    public ISignatureVerifier? Signatures { get; init; }
    public IHostnameResolver? Resolver { get; init; }
    public IListeningPortProvider? Listeners { get; init; }
    public IReadOnlyList<IConnectionSource> ConnectionSources { get; init; } = Array.Empty<IConnectionSource>();
    public IReadOnlyList<IDnsSource> DnsSources { get; init; } = Array.Empty<IDnsSource>();
    public FileHasher Hasher { get; init; } = new();
    public Func<DateTimeOffset> Clock { get; init; } = () => DateTimeOffset.Now;
    /// <summary>
    /// Treat RFC 5737 / 3849 documentation ranges as external so behaviour analysis runs on synthetic test data and sample
    /// captures. These ranges never occur in real traffic and are still never sent to reputation providers.
    /// </summary>
    public bool TreatDocumentationRangesAsExternal { get; init; }
}

/// <summary>
/// The pipeline: observation → process attribution → hostname → hash/signature → local IOC → reputation →
/// behaviour (beacon, baseline, DNS) → risk scoring → alerting → storage. All state mutation happens on a
/// single consumer task fed by a channel, so collectors never block and the logic needs no fine-grained locking.
/// </summary>
public sealed class MonitoringEngine : IAsyncDisposable
{
    private readonly EngineDependencies _d;
    private readonly Channel<object> _inbox = Channel.CreateBounded<object>(new BoundedChannelOptions(100_000) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });
    private readonly CancellationTokenSource _cts = new();
    private readonly object _state = new();
    private Task? _consumer;
    private Timer? _flushTimer;
    private Timer? _maintenanceTimer;
    private long _dropped;

    // ---- state (guarded by _state) ----
    private readonly Dictionary<string, TupleState> _tuples = new();
    private readonly Dictionary<string, FlowRecord> _flows = new();
    private readonly Dictionary<string, BaselineVerdict> _novelty = new();
    private readonly Dictionary<string, ProcessInfo> _procByKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, ProcessInfo> _procByPid = new();
    private readonly Dictionary<string, (string? Sha, SignatureInfo? Sig, string? Note)> _fileInfo = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _fileInfoPending = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HostnameInfo> _hosts = new();
    private readonly Dictionary<string, HashSet<string>> _flowsByIp = new();
    private readonly Dictionary<string, HashSet<string>> _flowsByDomain = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _flowsByHash = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _flowsByProcess = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, AlertRecord> _alerts = new();
    private readonly Dictionary<string, UserMarkKind> _marks = new(StringComparer.OrdinalIgnoreCase);
    private EngineBatch _pending = new();
    private readonly List<SourceStatus> _sourceStatus = new();
    private readonly ConcurrentQueue<string> _log = new();

    private readonly BeaconTracker _beacons = new();
    private readonly DomainAnalyzer _domains;
    private readonly DnsBehaviorAnalyzer _dnsBehavior;
    private readonly Baseline _baseline;
    private readonly SemaphoreSlim _ptrGate = new(4);
    private readonly SemaphoreSlim _fileGate = new(2);

    private sealed class TupleState
    {
        public required string FlowKey;
        public DateTimeOffset Opened;
        public DateTimeOffset LastSeen;
        public string State = "";
        public bool Established;
    }

    private sealed record ProcessEnriched(string Path, string? Sha, SignatureInfo? Sig, string? Note);
    private sealed record PtrResolved(string Ip, string? Ptr);
    private sealed record ReputationArrived(ReputationResult Result);

    public MonitoringEngine(EngineDependencies deps)
    {
        _d = deps;
        var s = deps.Settings;
        _domains = new DomainAnalyzer(() => s.SuspiciousTlds, () => s.CdnSuffixes);
        _dnsBehavior = new DnsBehaviorAnalyzer(_domains.IsCdn);
        _baseline = new Baseline(deps.Database, deps.Clock(), TimeSpan.FromHours(s.BaselineLearningHours));
        _beacons.ResolutionSeconds = s.PollIntervalMs / 1000.0;
        foreach (var m in deps.Database.GetMarks()) _marks[$"{m.Kind}|{m.Value}"] = m.Mark;
        foreach (var a in deps.Database.GetAlerts(5000)) _alerts.TryAdd(a.SubjectKey, a);
        // Reload recent flows so history and per-process views survive restarts.
        foreach (var f in deps.Database.QueryFlows(limit: 20_000, since: deps.Clock() - TimeSpan.FromHours(24)))
        {
            _flows[f.Key] = f;
            Index(_flowsByIp, f.RemoteIp, f.Key);
            Index(_flowsByProcess, f.ProcessKey, f.Key);
            if (f.Hostname is not null) Index(_flowsByDomain, f.Hostname, f.Key);
            if (f.Sha256 is not null) Index(_flowsByHash, f.Sha256, f.Key);
        }
        deps.Reputation.ResultAvailable += r => _inbox.Writer.TryWrite(new ReputationArrived(r));
    }

    public bool IsMonitoring { get; private set; }
    public DateTimeOffset? StartedAt { get; private set; }
    public long DroppedObservations => Interlocked.Read(ref _dropped);
    public Baseline Baseline => _baseline;
    public AppSettings Settings => _d.Settings;
    public Database Database => _d.Database;
    public ReputationService Reputation => _d.Reputation;
    public bool HasDnsVisibility => _d.DnsSources.Any(s => s.IsRunning);

    public event Action<EngineBatch>? BatchReady;
    public event Action<string>? Log;

    public IReadOnlyList<SourceStatus> Sources { get { lock (_sourceStatus) return _sourceStatus.ToList(); } }

    // ───────────────────────── lifecycle ─────────────────────────

    public void StartPipeline()
    {
        if (_consumer is not null) return;
        _consumer = Task.Run(() => ConsumeAsync(_cts.Token));
        _flushTimer = new Timer(_ => Flush(), null, 1000, 1000);
        _maintenanceTimer = new Timer(_ => Maintenance(), null, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(10));
        _d.Reputation.Start();
    }

    public void StartMonitoring()
    {
        StartPipeline();
        if (IsMonitoring) return;
        lock (_sourceStatus)
        {
            _sourceStatus.Clear();
            foreach (var src in _d.ConnectionSources)
            {
                bool ok = src.Start(o => Post(o), Emit, out var why);
                _sourceStatus.Add(new SourceStatus { Name = src.Name, Capabilities = src.Capabilities, Running = ok, Problem = why });
                Emit(ok ? $"Collector started: {src.Name}" : $"Collector unavailable: {src.Name}: {why}");
            }
            foreach (var src in _d.DnsSources)
            {
                bool ok = src.Start(o => Post(o), Emit, out var why);
                _sourceStatus.Add(new SourceStatus { Name = src.Name, Capabilities = src.Capabilities, Running = ok, Problem = why });
                Emit(ok ? $"DNS source started: {src.Name}" : $"DNS source unavailable: {src.Name}: {why}");
            }
        }
        IsMonitoring = true;
        StartedAt = _d.Clock();
    }

    public void StopMonitoring()
    {
        if (!IsMonitoring) return;
        foreach (var s in _d.ConnectionSources) s.Stop();
        foreach (var s in _d.DnsSources) s.Stop();
        lock (_sourceStatus) foreach (var s in _sourceStatus) s.Running = false;
        IsMonitoring = false;
        Emit("Monitoring stopped");
    }

    /// <summary>Feed an observation directly (used by sources, PCAP replay and tests).</summary>
    public void Post(object observation)
    {
        if (!_inbox.Writer.TryWrite(observation)) Interlocked.Increment(ref _dropped);
    }

    /// <summary>Waits until everything posted so far has been processed and flushed (tests, CLI).</summary>
    public async Task DrainAsync(TimeSpan timeout)
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Post(tcs);
        await tcs.Task.WaitAsync(timeout).ConfigureAwait(false);
        Flush();
    }

    private void Emit(string message)
    {
        var line = $"{DateTimeOffset.Now:HH:mm:ss} {message}";
        _log.Enqueue(line);
        while (_log.Count > 500) _log.TryDequeue(out _);
        Log?.Invoke(line);
    }

    public IReadOnlyList<string> RecentLog => _log.ToArray();

    private async Task ConsumeAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var msg in _inbox.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                try
                {
                    lock (_state)
                    {
                        switch (msg)
                        {
                            case ConnectionObservation o: HandleConnection(o); break;
                            case DnsObservation d: HandleDns(d); break;
                            case ProcessEnriched p: HandleProcessEnriched(p); break;
                            case PtrResolved p: HandlePtr(p); break;
                            case ReputationArrived r: HandleReputation(r.Result); break;
                            case TaskCompletionSource tcs: tcs.TrySetResult(); break;
                            case Action a: a(); break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    // One bad observation must never stop monitoring.
                    Emit($"Pipeline error ({ex.GetType().Name}): {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    // ───────────────────────── connections ─────────────────────────

    private void HandleConnection(ConnectionObservation o)
    {
        var remote = IpUtil.Normalize(o.RemoteAddress);
        var scope = IpUtil.Classify(remote);
        if (scope == IpScope.Unspecified) return;
        if (scope == IpScope.Loopback && !_d.Settings.IncludeLoopback) return;
        bool external = IpUtil.IsExternal(remote, _d.TreatDocumentationRangesAsExternal || o.IsSynthetic);
        if (!external && scope != IpScope.Loopback && !_d.Settings.IncludeLanTraffic) return;

        var tupleKey = o.TupleKey;
        if (_tuples.TryGetValue(tupleKey, out var ts))
        {
            ts.LastSeen = o.Timestamp;
            if (o.State.Length > 0) ts.State = o.State;
            if (o.State == "ESTABLISHED") ts.Established = true;
            if (_flows.TryGetValue(ts.FlowKey, out var f0))
            {
                if (o.State.Length > 0) f0.LastState = o.State;
                f0.LastSeen = o.Timestamp;
                if (DomainUtil.Normalize(o.Sni) is { } sni0 && f0.Sni is null)
                {
                    GetHost(f0.RemoteIp).Sni ??= sni0;
                    f0.Sni = sni0;
                    if (f0.Hostname is null)
                    {
                        SetFlowHostname(f0, sni0);
                        if (f0.Direction != Direction.Inbound) _beacons.AddContact(BeaconKeyHost(f0), ts.Opened);
                        if (_d.Settings.LookupDomains && !f0.IsSynthetic) _d.Reputation.Enqueue(IocType.Domain, sni0, f0.Assessment.Score);
                    }
                    Reassess(f0);
                }
                if (o.Kind == ObservationKind.Closed)
                {
                    if (!ts.Established && o.Protocol == TransportProtocol.Tcp && ts.State is "SYN_SENT" or "CLOSED")
                    {
                        f0.FailedCount++;
                        Reassess(f0);
                    }
                    else if (o.Timestamp - ts.Opened > TimeSpan.FromHours(1)) Reassess(f0, longLived: o.Timestamp - ts.Opened);
                    _tuples.Remove(tupleKey);
                }
                MarkDirty(f0);
            }
            return;
        }
        if (o.Kind == ObservationKind.Closed) return; // never saw it open; nothing reliable to attribute

        var proc = ResolveProcess(o.Pid, o.IsSynthetic);
        var remoteText = remote.ToString();
        var host = GetHost(remoteText);
        var sni = DomainUtil.Normalize(o.Sni);
        if (sni is not null) host.Sni ??= sni;
        var flowKey = FlowRecord.MakeKey(proc.Key, remoteText, o.RemotePort, o.Protocol, o.Direction);

        if (!_flows.TryGetValue(flowKey, out var flow))
        {
            flow = new FlowRecord
            {
                Key = flowKey, ProcessKey = proc.Key, ProcessName = proc.Name, RemoteIp = remoteText, RemotePort = o.RemotePort,
                Protocol = o.Protocol, Direction = o.Direction, FirstSeen = o.Timestamp, IsSynthetic = o.IsSynthetic,
            };
            _flows[flowKey] = flow;
            Index(_flowsByIp, remoteText, flowKey);
            Index(_flowsByProcess, proc.Key, flowKey);

            if (external && o.Direction != Direction.Inbound)
            {
                var destKey = host.Best is { } h ? "d:" + DomainUtil.RegistrableDomain(h) : "n:" + IpUtil.NetworkKey(remote);
                _novelty[flowKey] = _baseline.Observe(proc.Key, destKey, o.Timestamp);
            }
        }

        flow.ProcessName = proc.Name;
        flow.ProcessPath = proc.Path;
        flow.LastPid = proc.Pid;
        flow.Sha256 ??= proc.Sha256;
        flow.LastSeen = o.Timestamp;
        flow.LastState = o.State;
        flow.Count++;
        if (flow.Hostname is null && host.Best is { } best) SetFlowHostname(flow, best);
        flow.Ptr ??= host.Ptr;
        flow.Sni ??= sni;
        if (flow.Sha256 is not null) Index(_flowsByHash, flow.Sha256, flowKey);

        _tuples[tupleKey] = new TupleState { FlowKey = flowKey, Opened = o.Timestamp, LastSeen = o.Timestamp, State = o.State, Established = o.State == "ESTABLISHED" || o.Protocol == TransportProtocol.Udp };
        if (_tuples.Count > 200_000) PruneTuples(o.Timestamp);

        if (external && o.Direction != Direction.Inbound)
        {
            _beacons.AddContact(BeaconKeyIp(flow), o.Timestamp);
            if (flow.Hostname is not null) _beacons.AddContact(BeaconKeyHost(flow), o.Timestamp);
        }

        // Synthetic test traffic is never sent to external services.
        if (external && !o.IsSynthetic)
        {
            if (!host.PtrAttempted && _d.Settings.ResolvePtr && _d.Resolver is not null && !o.IsSynthetic) StartPtr(remoteText, remote, host);
            // Priority: non-browser/system processes and already-suspicious flows first.
            int prio = flow.Assessment.Score + (proc.Signature.IsTrusted ? 0 : 20);
            _d.Reputation.Enqueue(IocType.Ip, remoteText, prio);
            if (flow.Hostname is not null && _d.Settings.LookupDomains) _d.Reputation.Enqueue(IocType.Domain, flow.Hostname, prio - 5);
        }

        Reassess(flow);

        var ev = new ConnectionEvent
        {
            Timestamp = o.Timestamp, Direction = o.Direction, Protocol = o.Protocol, LocalIp = IpUtil.Normalize(o.LocalAddress).ToString(),
            LocalPort = o.LocalPort, RemoteIp = remoteText, RemotePort = o.RemotePort, State = o.State, Pid = proc.Pid, ProcessName = proc.Name,
            ProcessPath = proc.Path, Sha256 = flow.Sha256, Hostname = flow.Hostname, Ptr = flow.Ptr, FlowKey = flowKey,
            Score = flow.Assessment.Score, Level = flow.Assessment.Level, Source = o.Source, IsSynthetic = o.IsSynthetic,
        };
        _pending.Events.Add(ev);
    }

    private static string BeaconKeyIp(FlowRecord f) => $"{f.ProcessKey}|{f.RemoteIp}|{f.RemotePort}";
    private static string BeaconKeyHost(FlowRecord f) => $"{f.ProcessKey}|{f.Hostname}|{f.RemotePort}";

    private void PruneTuples(DateTimeOffset now)
    {
        foreach (var k in _tuples.Where(kv => now - kv.Value.LastSeen > TimeSpan.FromMinutes(10)).Select(kv => kv.Key).ToList()) _tuples.Remove(k);
    }

    private void SetFlowHostname(FlowRecord flow, string hostname)
    {
        flow.Hostname = hostname;
        Index(_flowsByDomain, hostname, flow.Key);
    }

    private HostnameInfo GetHost(string ip)
    {
        if (!_hosts.TryGetValue(ip, out var h)) _hosts[ip] = h = new HostnameInfo();
        return h;
    }

    private ProcessInfo ResolveProcess(int? pid, bool synthetic)
    {
        if (pid is null) return ProcessInfo.Unknown;
        ProcessInfo p;
        try { p = _d.Processes.Get(pid.Value); }
        catch (Exception ex) { Emit($"Process lookup failed for PID {pid}: {ex.Message}"); return ProcessInfo.Unknown with { Pid = pid, AttributionNote = "lookup failed" }; }

        if (p.Path is { } path && !p.IsSynthetic)
        {
            if (_fileInfo.TryGetValue(path, out var fi)) p = p with { Sha256 = fi.Sha ?? p.Sha256, Signature = fi.Sig ?? p.Signature };
            else if (_fileInfoPending.Add(path)) StartFileEnrichment(path);
        }
        _procByPid[pid.Value] = p;
        if (!_procByKey.TryGetValue(p.Key, out var existing) || existing.Pid != p.Pid || existing.Sha256 is null) _procByKey[p.Key] = p;
        return p;
    }

    private void StartFileEnrichment(string path)
    {
        bool hash = _d.Settings.HashExecutables, sign = _d.Settings.VerifySignatures && _d.Signatures is not null;
        _ = Task.Run(async () =>
        {
            await _fileGate.WaitAsync(_cts.Token).ConfigureAwait(false);
            try
            {
                string? sha = null, note = null;
                if (hash) sha = _d.Hasher.TryHash(path, out note);
                SignatureInfo? sig = null;
                if (sign)
                {
                    try { sig = _d.Signatures!.Verify(path); }
                    catch (Exception ex) { sig = SignatureInfo.Unknown; note = "signature check failed: " + ex.Message; }
                }
                Post(new ProcessEnriched(path, sha, sig, note));
            }
            finally { _fileGate.Release(); }
        });
    }

    private void HandleProcessEnriched(ProcessEnriched e)
    {
        _fileInfo[e.Path] = (e.Sha, e.Sig, e.Note);
        _fileInfoPending.Remove(e.Path);
        var key = e.Path.ToLowerInvariant();
        if (_procByKey.TryGetValue(key, out var p))
            _procByKey[key] = p with { Sha256 = e.Sha ?? p.Sha256, Signature = e.Sig ?? p.Signature, AttributionNote = e.Note ?? p.AttributionNote };
        foreach (var pid in _procByPid.Where(kv => string.Equals(kv.Value.Path, e.Path, StringComparison.OrdinalIgnoreCase)).Select(kv => kv.Key).ToList())
            _procByPid[pid] = _procByPid[pid] with { Sha256 = e.Sha ?? _procByPid[pid].Sha256, Signature = e.Sig ?? _procByPid[pid].Signature };

        if (e.Sha is not null && _d.Settings.LookupFileHashes)
            _d.Reputation.Enqueue(IocType.Sha256, e.Sha, e.Sig?.IsTrusted == true ? 0 : 40);

        if (_flowsByProcess.TryGetValue(key, out var flows))
            foreach (var fk in flows.ToList())
                if (_flows.TryGetValue(fk, out var f))
                {
                    if (e.Sha is not null) { f.Sha256 = e.Sha; Index(_flowsByHash, e.Sha, fk); }
                    Reassess(f);
                }
    }

    private void StartPtr(string ipText, IPAddress ip, HostnameInfo host)
    {
        host.PtrAttempted = true;
        _ = Task.Run(async () =>
        {
            await _ptrGate.WaitAsync(_cts.Token).ConfigureAwait(false);
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                string? ptr = null;
                try { ptr = await _d.Resolver!.ReverseLookupAsync(ip, timeout.Token).ConfigureAwait(false); }
                catch (Exception) { /* no PTR is normal; never fatal */ }
                Post(new PtrResolved(ipText, DomainUtil.Normalize(ptr)));
            }
            finally { _ptrGate.Release(); }
        });
    }

    private void HandlePtr(PtrResolved p)
    {
        var h = GetHost(p.Ip);
        h.Ptr = p.Ptr;
        if (p.Ptr is null) return;
        if (_flowsByIp.TryGetValue(p.Ip, out var flows))
            foreach (var fk in flows)
                if (_flows.TryGetValue(fk, out var f)) { f.Ptr = p.Ptr; MarkDirty(f); }
    }

    // ───────────────────────── DNS ─────────────────────────

    private void HandleDns(DnsObservation d)
    {
        var name = DomainUtil.Normalize(d.Query);
        if (name is null) return;
        _dnsBehavior.Record(d);

        foreach (var ip in d.ResolvedAddresses)
        {
            var ipText = IpUtil.Normalize(ip).ToString();
            var h = GetHost(ipText);
            h.DnsNames.Remove(name);
            h.DnsNames.Insert(0, name);
            if (h.DnsNames.Count > 8) h.DnsNames.RemoveAt(h.DnsNames.Count - 1);

            if (_flowsByIp.TryGetValue(ipText, out var flows))
                foreach (var fk in flows.ToList())
                    if (_flows.TryGetValue(fk, out var f) && f.Hostname is null)
                    {
                        SetFlowHostname(f, name);
                        if (_beacons is not null && f.Direction != Direction.Inbound) _beacons.AddContact(BeaconKeyHost(f), f.LastSeen);
                        Reassess(f);
                    }
        }

        string? procName = d.ProcessName;
        if (procName is null && d.Pid is { } pid && !d.IsSynthetic) procName = ResolveProcess(pid, false).Name;
        else if (procName is null && d.Pid is { } spid) procName = ResolveProcess(spid, true).Name;

        var input = new AssessmentInput { ExternalDestination = true };
        input.AddRange(_domains.Analyze(name));
        input.AddRange(_dnsBehavior.Evaluate(name));
        input.Add(_dnsBehavior.NxDomainBurst());
        input.AddRange(RiskScorer.FromReputation(_d.Reputation.GetKnown(IocType.Domain, name), $"Domain {name}"));
        foreach (var ip in d.ResolvedAddresses)
            input.AddRange(RiskScorer.FromReputation(new[] { _d.Reputation.CheckLocal(IocType.Ip, IpUtil.Normalize(ip).ToString()) }, $"Resolved IP {ip}"));
        ApplyMarks(input, null, name, null, null);
        var a = RiskScorer.Assess(input);

        if (a.Score >= 20 && _d.Settings.LookupDomains && !d.IsSynthetic) _d.Reputation.Enqueue(IocType.Domain, name, a.Score);

        var rec = new DnsEventRecord
        {
            Timestamp = d.Timestamp, Pid = d.Pid, ProcessName = procName, Query = name, RecordType = d.RecordType, Status = d.Status,
            Answers = string.Join(", ", d.Answers.Count > 0 ? d.Answers : d.ResolvedAddresses.Select(x => x.ToString())),
            Source = d.Source, Level = a.Evidence.Count == 0 ? RiskLevel.Low : a.Level, Notes = string.Join("; ", a.Evidence.Where(e => e.Strength > 0).Select(e => e.Text)),
            IsSynthetic = d.IsSynthetic,
        };
        _pending.Dns.Add(rec);

        bool dnsSpecific = a.Evidence.Any(e => e.Category is EvidenceCategory.Dns or EvidenceCategory.LocalIoc or EvidenceCategory.Reputation && e.Strength >= 0.2);
        if (dnsSpecific && !a.Suppressed)
        {
            var subject = "dns:" + DomainUtil.RegistrableDomain(name);
            RaiseAlert(subject, a, procName ?? "Unknown", d.Pid, null, null, null, null, name, d.Timestamp, d.IsSynthetic);
        }
    }

    // ───────────────────────── reputation ─────────────────────────

    private void HandleReputation(ReputationResult r)
    {
        HashSet<string>? keys = r.Type switch
        {
            IocType.Ip => _flowsByIp.GetValueOrDefault(r.Value),
            IocType.Domain => _flowsByDomain.GetValueOrDefault(r.Value),
            IocType.Sha256 => _flowsByHash.GetValueOrDefault(r.Value),
            _ => null,
        };
        if (keys is null) return;
        foreach (var fk in keys.ToList())
            if (_flows.TryGetValue(fk, out var f)) Reassess(f);
    }

    // ───────────────────────── scoring ─────────────────────────

    private void Reassess(FlowRecord flow, TimeSpan? longLived = null)
    {
        var input = new AssessmentInput();
        bool external = IpUtil.TryParse(flow.RemoteIp, out var rip) && IpUtil.IsExternal(rip, _d.TreatDocumentationRangesAsExternal || flow.IsSynthetic);
        input.ExternalDestination = external;

        _procByKey.TryGetValue(flow.ProcessKey, out var proc);
        proc ??= ProcessInfo.Unknown with { Name = flow.ProcessName, Path = flow.ProcessPath, Pid = flow.LastPid };
        input.ProcessAttributed = proc.IsKnown;
        input.AddRange(ProcessHeuristics.Analyze(proc, flow.FirstSeen, external));

        // Local IOC checks happen first and offline.
        input.AddRange(RiskScorer.FromReputation(new[] { _d.Reputation.CheckLocal(IocType.Ip, flow.RemoteIp) }, $"Destination IP {flow.RemoteIp}"));
        if (flow.Hostname is not null) input.AddRange(RiskScorer.FromReputation(new[] { _d.Reputation.CheckLocal(IocType.Domain, flow.Hostname) }, $"Domain {flow.Hostname}"));
        if (flow.Sha256 is not null) input.AddRange(RiskScorer.FromReputation(new[] { _d.Reputation.CheckLocal(IocType.Sha256, flow.Sha256) }, $"Executable hash of {flow.ProcessName}"));

        if (external)
        {
            var remote = new List<ReputationResult>();
            remote.AddRange(_d.Reputation.Cache.GetAll(IocType.Ip, flow.RemoteIp));
            if (flow.Hostname is not null) remote.AddRange(_d.Reputation.Cache.GetAll(IocType.Domain, flow.Hostname));
            if (flow.Sha256 is not null) remote.AddRange(_d.Reputation.Cache.GetAll(IocType.Sha256, flow.Sha256));
            input.IntelConsulted = remote.Any(r => r.Status is ReputationStatus.Ok or ReputationStatus.NotFound);
            input.AddRange(RiskScorer.FromReputation(remote, flow.Hostname is null ? $"Destination IP {flow.RemoteIp}" : $"{flow.RemoteIp} ({flow.Hostname})"));

            if (flow.Direction == Direction.Inbound)
            {
                input.Add(new Evidence(EvidenceCategory.Network, $"Inbound connection from external address {flow.RemoteIp}", PortHeuristics.IsCommon(flow.RemotePort) ? 0.05 : 0.12));
            }
            else
            {
                input.Add(PortHeuristics.Evaluate(flow.RemotePort, flow.Direction));
                input.AddRange(_domains.Analyze(flow.Hostname));
                input.AddRange(_dnsBehavior.Evaluate(flow.Hostname));

                if (flow.Hostname is null && HasDnsVisibility && flow.Protocol == TransportProtocol.Tcp)
                    input.Add(new Evidence(EvidenceCategory.Network, "No DNS resolution was observed for this IP (direct-to-IP connection)", 0.06));

                if (_novelty.TryGetValue(flow.Key, out var nv))
                {
                    if (nv.Learning)
                    {
                        if (nv.NewDestinationForMachine)
                            input.Add(new Evidence(EvidenceCategory.Baseline, "First time this machine contacted this destination (baseline still learning)", 0.03));
                    }
                    else if (nv.FirstExternalForProcess)
                        input.Add(new Evidence(EvidenceCategory.Baseline, $"{flow.ProcessName} had no external connections in the learned baseline: anomalous network behavior", 0.15));
                    else if (nv.NewDestinationForMachine)
                        input.Add(new Evidence(EvidenceCategory.Baseline, "Rare destination: never contacted by this machine before", 0.1));
                    else if (nv.NewDestinationForProcess)
                        input.Add(new Evidence(EvidenceCategory.Baseline, $"Destination is new for {flow.ProcessName} (known to other processes)", 0.05));
                }

                var bIp = _beacons.Analyze(BeaconKeyIp(flow));
                var bHost = flow.Hostname is null ? BeaconResult.None : _beacons.Analyze(BeaconKeyHost(flow));
                input.Beacon = bHost.Confidence > bIp.Confidence ? bHost : bIp;
            }

            if (flow.FailedCount >= 5)
                input.Add(new Evidence(EvidenceCategory.Network, $"{flow.FailedCount} failed connection attempts to this destination", flow.FailedCount >= 20 ? 0.2 : 0.1));
            if (longLived is { } ll && flow.Direction == Direction.Outbound)
                input.Add(new Evidence(EvidenceCategory.Network, $"Long-lived connection ({ll.TotalHours:0.#} h)", 0.05));
        }

        if (!proc.IsKnown)
            input.Add(new Evidence(EvidenceCategory.Process, "Process could not be attributed (Process: Unknown); fewer signals available", 0.0));

        ApplyMarks(input, flow.RemoteIp, flow.Hostname, flow.ProcessKey, flow.Sha256);
        var prev = flow.Assessment;
        flow.Assessment = RiskScorer.Assess(input);
        MarkDirty(flow);

        if (!flow.Assessment.Suppressed && (flow.Assessment.Score != prev.Score || flow.Assessment.Classification != prev.Classification))
            RaiseAlert(flow.Key, flow.Assessment, flow.ProcessName, flow.LastPid, flow.ProcessPath, flow.Sha256, flow.RemoteIp, flow.RemotePort, flow.Hostname, flow.LastSeen, flow.IsSynthetic, flow.FirstSeen);
    }

    private void ApplyMarks(AssessmentInput input, string? ip, string? domain, string? processKey, string? sha)
    {
        var candidates = new List<(string Kind, string? Value)>
        {
            ("ip", ip), ("domain", domain), ("domain", domain is null ? null : DomainUtil.RegistrableDomain(domain)), ("process", processKey), ("hash", sha),
        };
        UserMarkKind best = UserMarkKind.None;
        string? subject = null;
        foreach (var (kind, value) in candidates)
        {
            if (value is null || !_marks.TryGetValue($"{kind}|{value.ToLowerInvariant()}", out var m)) continue;
            // Suspicious wins over Ignored wins over Trusted: an analyst's concern is never silently cancelled.
            int rank(UserMarkKind k) => k switch { UserMarkKind.Suspicious => 3, UserMarkKind.Ignored => 2, UserMarkKind.Trusted => 1, _ => 0 };
            if (rank(m) > rank(best)) { best = m; subject = $"{kind} {value}"; }
        }
        input.Mark = best;
        input.MarkSubject = subject;
    }

    private void RaiseAlert(string subject, RiskAssessment a, string processName, int? pid, string? path, string? sha, string? ip, int? port, string? host, DateTimeOffset seen, bool synthetic, DateTimeOffset? firstSeen = null)
    {
        var min = Enum.Parse<RiskLevel>(_d.Settings.MinimumAlertLevel);
        if (a.Level < min || a.Level == RiskLevel.Unknown) return;
        if (a.Level == RiskLevel.Low && a.Evidence.All(e => e.Strength <= 0)) return;

        var notifyMin = Enum.Parse<RiskLevel>(_d.Settings.MinimumNotificationLevel);
        var now = _d.Clock();
        if (_alerts.TryGetValue(subject, out var existing))
        {
            bool escalated = a.Level > existing.Severity;
            bool stronger = a.Score > existing.Score || (a.Score == existing.Score && a.Classification > existing.Classification);
            if (!escalated && !stronger)
            {
                // Weaker or equal re-assessments (e.g. after a restart, before beaconing is re-learned) never
                // overwrite the evidence that justified the alert.
                existing.LastSeen = seen;
                return;
            }
            // An alert always describes its most severe assessment, with score, title, class and evidence kept consistent.
            existing.Updated = now;
            existing.Severity = (RiskLevel)Math.Max((int)existing.Severity, (int)a.Level);
            existing.Score = a.Score;
            existing.Confidence = a.Confidence;
            existing.Classification = a.Classification;
            existing.Title = a.Title;
            existing.Evidence = a.Evidence;
            existing.Sha256 ??= sha;
            existing.Hostname ??= host;
            existing.LastSeen = seen;
            if (escalated) existing.Acknowledged = false;
            _d.Database.UpsertAlert(existing);
            if (!_pending.Alerts.Contains(existing)) _pending.Alerts.Add(existing);
            if (escalated && a.Level >= notifyMin && !_pending.Notify.Contains(existing)) _pending.Notify.Add(existing);
            return;
        }

        var alert = new AlertRecord
        {
            Created = now, Updated = now, Severity = a.Level, Classification = a.Classification, Title = a.Title, SubjectKey = subject,
            ProcessName = processName, Pid = pid, ProcessPath = path, Sha256 = sha, RemoteIp = ip, RemotePort = port, Hostname = host,
            Score = a.Score, Confidence = a.Confidence, Evidence = a.Evidence, FirstSeen = firstSeen ?? seen, LastSeen = seen, IsSynthetic = synthetic,
        };
        _d.Database.UpsertAlert(alert);
        _alerts[subject] = alert;
        _pending.Alerts.Add(alert);
        if (a.Level >= notifyMin) _pending.Notify.Add(alert);
        Emit($"ALERT [{a.Level.Label()}] {a.Title}: {processName} → {host ?? ip}{(port is null ? "" : ":" + port)} (score {a.Score})");
    }

    private void MarkDirty(FlowRecord f)
    {
        if (!_pending.Flows.Contains(f)) _pending.Flows.Add(f);
    }

    private static void Index(Dictionary<string, HashSet<string>> index, string key, string flowKey)
    {
        if (!index.TryGetValue(key, out var set)) index[key] = set = new HashSet<string>();
        set.Add(flowKey);
    }

    // ───────────────────────── flush & maintenance ─────────────────────────

    private int _flushing;

    private void Flush()
    {
        if (Interlocked.Exchange(ref _flushing, 1) == 1) return;
        try
        {
            EngineBatch batch;
            List<FlowRecord> flowCopies;
            lock (_state)
            {
                if (_pending.IsEmpty) return;
                batch = _pending;
                _pending = new EngineBatch();
                flowCopies = batch.Flows.Select(Clone).ToList();
            }
            try { _d.Database.WriteBatch(batch.Events, flowCopies, batch.Dns); }
            catch (Exception ex) { Emit("Database write failed: " + ex.Message); }
            batch.Flows.Clear();
            batch.Flows.AddRange(flowCopies);
            BatchReady?.Invoke(batch);
        }
        finally { Interlocked.Exchange(ref _flushing, 0); }
    }

    private static FlowRecord Clone(FlowRecord f) => new()
    {
        Key = f.Key, ProcessKey = f.ProcessKey, ProcessName = f.ProcessName, ProcessPath = f.ProcessPath, LastPid = f.LastPid, Sha256 = f.Sha256,
        RemoteIp = f.RemoteIp, RemotePort = f.RemotePort, Protocol = f.Protocol, Direction = f.Direction, Hostname = f.Hostname, Ptr = f.Ptr, Sni = f.Sni,
        FirstSeen = f.FirstSeen, LastSeen = f.LastSeen, Count = f.Count, FailedCount = f.FailedCount, LastState = f.LastState, Assessment = f.Assessment,
        IsSynthetic = f.IsSynthetic,
    };

    private void Maintenance()
    {
        try
        {
            var now = _d.Clock();
            var hours = _d.Settings.RetentionHours;
            int removed = _d.Database.ApplyRetention(hours == 0 ? null : TimeSpan.FromHours(hours), now);
            if (removed > 0) Emit($"Retention: removed {removed} old records");
            _beacons.Prune(now);
            lock (_state)
            {
                PruneTuples(now);
                if (hours > 0)
                    foreach (var k in _flows.Where(kv => now - kv.Value.LastSeen > TimeSpan.FromHours(hours)).Select(kv => kv.Key).ToList())
                        _flows.Remove(k);
            }
        }
        catch (Exception ex) { Emit("Maintenance failed: " + ex.Message); }
    }

    // ───────────────────────── queries for UI / CLI ─────────────────────────

    public List<FlowRecord> SnapshotFlows() { lock (_state) return _flows.Values.Select(Clone).ToList(); }

    public ProcessInfo? GetProcess(string processKey) { lock (_state) return _procByKey.GetValueOrDefault(processKey); }

    public ProcessInfo? GetProcessByPid(int pid) { lock (_state) return _procByPid.GetValueOrDefault(pid); }

    public HostnameInfo? GetHostInfo(string ip)
    {
        lock (_state)
        {
            if (!_hosts.TryGetValue(ip, out var h)) return null;
            var copy = new HostnameInfo { Ptr = h.Ptr, PtrAttempted = h.PtrAttempted, Sni = h.Sni };
            copy.DnsNames.AddRange(h.DnsNames);
            return copy;
        }
    }

    public BeaconResult GetBeacon(FlowRecord f)
    {
        var a = _beacons.Analyze(BeaconKeyIp(f));
        var b = f.Hostname is null ? BeaconResult.None : _beacons.Analyze(BeaconKeyHost(f));
        return b.Confidence > a.Confidence ? b : a;
    }

    public IReadOnlyList<ReputationResult> GetReputation(IocType type, string value) => _d.Reputation.GetKnown(type, value);

    public void RequestLookup(IocType type, string value) => _d.Reputation.Enqueue(type, value, 1000);

    public void SetMark(string kind, string value, UserMarkKind mark, string? note = null)
    {
        _d.Database.SetMark(kind, value, mark, note);
        Post(new Action(() =>
        {
            var key = $"{kind}|{value.ToLowerInvariant()}";
            if (mark == UserMarkKind.None) _marks.Remove(key); else _marks[key] = mark;
            foreach (var f in _flows.Values.ToList()) Reassess(f);
        }));
    }

    public UserMarkKind GetMark(string kind, string value)
    {
        lock (_state) return _marks.GetValueOrDefault($"{kind}|{value.ToLowerInvariant()}");
    }

    /// <summary>Re-run scoring on everything (after IOC import or settings change).</summary>
    public void ReassessAll() => Post(new Action(() => { foreach (var f in _flows.Values.ToList()) Reassess(f); }));

    public List<ListeningPortRecord> GetListeningPorts()
    {
        var list = new List<ListeningPortRecord>();
        if (_d.Listeners is null) return list;
        foreach (var l in _d.Listeners.GetListeners())
        {
            ProcessInfo p;
            lock (_state) p = l.Pid is { } pid ? ResolveProcess(pid, false) : ProcessInfo.Unknown;
            var addr = IpUtil.Normalize(l.LocalAddress);
            bool all = addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any);
            if (IPAddress.IsLoopback(addr) && !_d.Settings.IncludeLoopback) continue;
            var input = new AssessmentInput { ProcessAttributed = p.IsKnown };
            input.AddRange(PortHeuristics.EvaluateListener(l.Port, all, p));
            input.AddRange(ProcessHeuristics.Analyze(p, DateTimeOffset.MaxValue, false));
            if (p.Sha256 is not null) input.AddRange(RiskScorer.FromReputation(_d.Reputation.GetKnown(IocType.Sha256, p.Sha256), $"Executable hash of {p.Name}"));
            lock (_state) ApplyMarks(input, null, null, p.Key, p.Sha256);
            list.Add(new ListeningPortRecord
            {
                Protocol = l.Protocol, Address = addr.ToString(), Port = l.Port, Pid = l.Pid, ProcessName = p.Name, ProcessPath = p.Path,
                Assessment = RiskScorer.Assess(input),
            });
        }
        return list.OrderBy(x => x.Port).ThenBy(x => x.Protocol).ToList();
    }

    public async ValueTask DisposeAsync()
    {
        StopMonitoring();
        _flushTimer?.Dispose();
        _maintenanceTimer?.Dispose();
        Flush();
        _cts.Cancel();
        _inbox.Writer.TryComplete();
        if (_consumer is not null) { try { await _consumer.ConfigureAwait(false); } catch (OperationCanceledException) { } }
        foreach (var s in _d.ConnectionSources) s.Dispose();
        foreach (var s in _d.DnsSources) s.Dispose();
        Flush();
        _cts.Dispose();
    }
}
