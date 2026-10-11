using System.Collections.Concurrent;

namespace NetHunter.Core.Detection;

public sealed record BeaconResult(
    bool IsBeacon,
    double IntervalSeconds,
    double Confidence,
    int Contacts,
    double Jitter,
    double FitRatio)
{
    public static readonly BeaconResult None = new(false, 0, 0, 0, 0, 0);

    public string Describe() =>
        $"Repeated contact every ~{FormatInterval(IntervalSeconds)} across {Contacts} connections " +
        $"(jitter {Jitter:P0}, {FitRatio:P0} of gaps fit the period); confidence {Confidence:P0}";

    public static string FormatInterval(double s) =>
        s >= 3600 ? $"{s / 3600:0.#} h" : s >= 90 ? $"{s / 60:0.#} min" : $"{s:0} s";
}

/// <summary>
/// Detects periodic ("beacon-like") contact. Works on contact start times only, so it applies equally to
/// live monitoring and PCAP. Tolerates jitter and missed beats (gaps that are whole multiples of the period).
/// </summary>
public static class BeaconDetector
{
    public const int MinContacts = 4;
    public const double MinIntervalSeconds = 5;
    public const double MaxIntervalSeconds = 6 * 3600;
    /// <summary>Contacts closer together than this are one burst (e.g. a browser opening parallel sockets).</summary>
    public const double BurstSeconds = 2;

    /// <param name="timestamps">Connection start times for one (process, destination) pair.</param>
    /// <param name="resolutionSeconds">Sampling resolution of the collector (polling interval) to discount measurement noise.</param>
    public static BeaconResult Analyze(IEnumerable<DateTimeOffset> timestamps, double resolutionSeconds = 1.0)
    {
        var contacts = CollapseBursts(timestamps.OrderBy(t => t).ToList());
        if (contacts.Count < MinContacts) return BeaconResult.None with { Contacts = contacts.Count };

        var gaps = new double[contacts.Count - 1];
        for (int i = 1; i < contacts.Count; i++) gaps[i - 1] = (contacts[i] - contacts[i - 1]).TotalSeconds;

        // Use the median gap as the candidate period, but if many gaps are double (missed beats),
        // the median can land on a multiple; the smallest common-ish gap is a better period estimate.
        var sorted = gaps.OrderBy(g => g).ToArray();
        double period = sorted[sorted.Length / 2];
        var lowerHalf = sorted.Take(Math.Max(1, sorted.Length / 2 + 1)).ToArray();
        double lowMedian = lowerHalf[lowerHalf.Length / 2];
        if (lowMedian > 0 && Math.Abs(period / lowMedian - Math.Round(period / lowMedian)) < 0.15 && Math.Round(period / lowMedian) >= 2)
            period = lowMedian;

        if (period < MinIntervalSeconds || period > MaxIntervalSeconds)
            return BeaconResult.None with { Contacts = contacts.Count, IntervalSeconds = period };

        var normalized = new List<double>();
        foreach (var g in gaps)
        {
            var k = Math.Round(g / period);
            if (k < 1 || k > 4) continue;
            var residual = Math.Abs(g - k * period) / period;
            if (residual <= 0.25) normalized.Add(g / k);
        }

        double fitRatio = (double)normalized.Count / gaps.Length;
        if (normalized.Count < MinContacts - 1)
            return new BeaconResult(false, period, 0, contacts.Count, 1, fitRatio);

        double mean = normalized.Average();
        double variance = normalized.Sum(x => (x - mean) * (x - mean)) / normalized.Count;
        // Remove the variance contributed by sampling resolution (uniform error on both endpoints).
        double samplingVariance = resolutionSeconds * resolutionSeconds / 6.0;
        double sd = Math.Sqrt(Math.Max(0, variance - samplingVariance));
        double jitter = mean > 0 ? sd / mean : 1;

        // Jittered C2 (e.g. 20% jitter) yields CV ~0.12; random traffic has CV near or above 1.
        double regularity = Math.Clamp(1 - jitter / 0.35, 0, 1);
        double countFactor = Math.Min(1.0, 0.55 + 0.05 * normalized.Count);
        double confidence = Math.Round(regularity * fitRatio * countFactor, 3);

        bool isBeacon = confidence >= 0.5;
        return new BeaconResult(isBeacon, Math.Round(mean, 1), confidence, contacts.Count, Math.Round(jitter, 3), Math.Round(fitRatio, 3));
    }

    internal static List<DateTimeOffset> CollapseBursts(List<DateTimeOffset> ordered)
    {
        var result = new List<DateTimeOffset>(ordered.Count);
        foreach (var t in ordered)
        {
            if (result.Count > 0 && (t - result[^1]).TotalSeconds < BurstSeconds) continue;
            result.Add(t);
        }
        return result;
    }
}

/// <summary>Keeps recent contact times per key (process + destination). Thread-safe, bounded.</summary>
public sealed class BeaconTracker
{
    private const int MaxPerKey = 256;
    private const int MaxKeys = 50_000;
    private readonly ConcurrentDictionary<string, List<DateTimeOffset>> _contacts = new();
    private readonly TimeSpan _window;

    public BeaconTracker(TimeSpan? window = null) { _window = window ?? TimeSpan.FromHours(24); }

    public double ResolutionSeconds { get; set; } = 1.0;

    public void AddContact(string key, DateTimeOffset t)
    {
        if (_contacts.Count >= MaxKeys && !_contacts.ContainsKey(key)) Prune(t);
        var list = _contacts.GetOrAdd(key, _ => new List<DateTimeOffset>());
        lock (list)
        {
            list.Add(t);
            if (list.Count > MaxPerKey) list.RemoveRange(0, list.Count - MaxPerKey);
        }
    }

    public BeaconResult Analyze(string key)
    {
        if (!_contacts.TryGetValue(key, out var list)) return BeaconResult.None;
        List<DateTimeOffset> copy;
        lock (list) copy = list.ToList();
        return BeaconDetector.Analyze(copy, ResolutionSeconds);
    }

    public void Prune(DateTimeOffset now)
    {
        foreach (var (k, list) in _contacts)
        {
            lock (list)
            {
                list.RemoveAll(t => now - t > _window);
                if (list.Count == 0) _contacts.TryRemove(k, out _);
            }
        }
    }
}
