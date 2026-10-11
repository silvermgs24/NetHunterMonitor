using System.Collections.Concurrent;
using NetHunter.Core.Models;

namespace NetHunter.Core.Intel;

/// <summary>Optional durable backing for the cache (SQLite in the app) so restarts do not re-spend API quota.</summary>
public interface IReputationStore
{
    IEnumerable<(ReputationResult Result, DateTimeOffset Expires)> LoadReputation(DateTimeOffset now);
    void SaveReputation(ReputationResult result, DateTimeOffset expires);
}

/// <summary>IOC -> reputation -> expiry. Successful/not-found results live for the configured TTL; errors only briefly.</summary>
public sealed class ReputationCache
{
    private readonly ConcurrentDictionary<string, (ReputationResult Result, DateTimeOffset Expires)> _items = new(StringComparer.OrdinalIgnoreCase);
    private readonly IReputationStore? _store;
    private readonly Func<DateTimeOffset> _clock;

    public ReputationCache(TimeSpan ttl, IReputationStore? store = null, Func<DateTimeOffset>? clock = null)
    {
        Ttl = ttl;
        _store = store;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        if (_store is not null)
            foreach (var (r, exp) in _store.LoadReputation(_clock()))
                _items[Key(r.Provider, r.Type, r.Value)] = (r, exp);
    }

    public TimeSpan Ttl { get; set; }
    public TimeSpan ErrorTtl { get; set; } = TimeSpan.FromMinutes(15);
    public int Count => _items.Count;

    public static string Key(string provider, IocType type, string value) => $"{provider}|{(int)type}|{value}";

    public bool TryGet(string provider, IocType type, string value, out ReputationResult result)
    {
        if (_items.TryGetValue(Key(provider, type, value), out var e) && e.Expires > _clock())
        {
            result = e.Result;
            return true;
        }
        result = null!;
        return false;
    }

    public void Put(ReputationResult r)
    {
        // Rate-limit/offline/disabled outcomes are transient and must not mask a later real answer.
        if (r.Status is ReputationStatus.RateLimited or ReputationStatus.Offline or ReputationStatus.Disabled or ReputationStatus.Skipped) return;
        var ttl = r.Status == ReputationStatus.Error ? ErrorTtl : Ttl;
        var exp = _clock() + ttl;
        _items[Key(r.Provider, r.Type, r.Value)] = (r, exp);
        if (r.Status != ReputationStatus.Error) _store?.SaveReputation(r, exp);
    }

    public IReadOnlyList<ReputationResult> GetAll(IocType type, string value)
    {
        var now = _clock();
        var suffix = $"|{(int)type}|{value}";
        return _items.Where(kv => kv.Key.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) && kv.Value.Expires > now)
                     .Select(kv => kv.Value.Result).ToList();
    }
}
