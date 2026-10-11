using System.Collections.Concurrent;

namespace NetHunter.Core.Detection;

public interface IBaselineStore
{
    IEnumerable<(string ProcessKey, string DestKey, DateTimeOffset FirstSeen, long Count)> LoadBaseline();
    void UpsertBaseline(string processKey, string destKey, DateTimeOffset seen);
    DateTimeOffset? GetBaselineStart();
    void SetBaselineStart(DateTimeOffset start);
}

public sealed record BaselineVerdict(bool NewDestinationForProcess, bool NewDestinationForMachine, bool FirstExternalForProcess, int KnownDestinationsForProcess, bool Learning);

/// <summary>
/// Learns which destinations (registrable domain or /24 network) each process normally talks to.
/// Learning only informs "rarity" signals; nothing is ever auto-whitelisted.
/// </summary>
public sealed class Baseline
{
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, long>> _byProcess = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _machine = new(StringComparer.OrdinalIgnoreCase);
    private readonly IBaselineStore? _store;

    public Baseline(IBaselineStore? store, DateTimeOffset now, TimeSpan learningPeriod)
    {
        _store = store;
        LearningPeriod = learningPeriod;
        Started = store?.GetBaselineStart() ?? now;
        if (store is not null)
        {
            if (store.GetBaselineStart() is null) store.SetBaselineStart(now);
            foreach (var (p, d, _, c) in store.LoadBaseline())
            {
                _byProcess.GetOrAdd(p, _ => new(StringComparer.OrdinalIgnoreCase))[d] = c;
                _machine[d] = 0;
            }
        }
    }

    public DateTimeOffset Started { get; }
    public TimeSpan LearningPeriod { get; set; }
    public bool IsLearning(DateTimeOffset now) => now - Started < LearningPeriod;
    public int ProcessCount => _byProcess.Count;

    /// <summary>Checks rarity, then records the contact.</summary>
    public BaselineVerdict Observe(string processKey, string destKey, DateTimeOffset now)
    {
        var dests = _byProcess.GetOrAdd(processKey, _ => new(StringComparer.OrdinalIgnoreCase));
        bool firstExternal = dests.IsEmpty;
        bool newForProcess = !dests.ContainsKey(destKey);
        bool newForMachine = !_machine.ContainsKey(destKey);
        int known = dests.Count;

        dests.AddOrUpdate(destKey, 1, (_, c) => c + 1);
        _machine[destKey] = 0;
        if (newForProcess || dests[destKey] % 50 == 0) _store?.UpsertBaseline(processKey, destKey, now);
        return new BaselineVerdict(newForProcess, newForMachine, firstExternal, known, IsLearning(now));
    }

    public IReadOnlyDictionary<string, long> DestinationsFor(string processKey) =>
        _byProcess.TryGetValue(processKey, out var d) ? new Dictionary<string, long>(d) : new Dictionary<string, long>();
}
