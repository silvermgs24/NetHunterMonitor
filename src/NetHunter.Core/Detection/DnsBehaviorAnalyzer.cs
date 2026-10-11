using System.Net;
using NetHunter.Core.Models;
using NetHunter.Core.Util;

namespace NetHunter.Core.Detection;

/// <summary>
/// Stateful DNS behaviour over sliding windows: tunnelling indicators (many unique/long subdomains, TXT volume),
/// DGA indicators (NXDOMAIN bursts), and resolution churn (fast-flux). Thread-safe.
/// </summary>
public sealed class DnsBehaviorAnalyzer
{
    private readonly object _lock = new();
    private readonly Dictionary<string, DomainStats> _byBase = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ChurnStats> _churn = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<(DateTimeOffset T, string Name)> _nxdomain = new();
    private readonly Func<string, bool> _isCdn;

    public DnsBehaviorAnalyzer(Func<string, bool> isCdn) { _isCdn = isCdn; }

    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(10);
    public TimeSpan ChurnWindow { get; set; } = TimeSpan.FromHours(1);

    private sealed class DomainStats
    {
        public readonly Queue<(DateTimeOffset T, string Sub, string Type)> Queries = new();
    }

    private sealed class ChurnStats
    {
        public readonly Dictionary<string, DateTimeOffset> Ips = new();
        public int? MinTtl;
    }

    public void Record(DnsObservation q)
    {
        var name = DomainUtil.Normalize(q.Query);
        if (name is null) return;
        var baseDomain = DomainUtil.RegistrableDomain(name);
        lock (_lock)
        {
            if (!_byBase.TryGetValue(baseDomain, out var s)) _byBase[baseDomain] = s = new DomainStats();
            s.Queries.Enqueue((q.Timestamp, DomainUtil.SubdomainPart(name), q.RecordType.ToUpperInvariant()));
            while (s.Queries.Count > 0 && q.Timestamp - s.Queries.Peek().T > Window) s.Queries.Dequeue();
            while (s.Queries.Count > 2000) s.Queries.Dequeue();

            if (q.Status == 9003 || q.Status == 3) // DNS_ERROR_RCODE_NAME_ERROR (Windows) / RCODE NXDOMAIN (wire)
            {
                _nxdomain.Enqueue((q.Timestamp, name));
                while (_nxdomain.Count > 0 && q.Timestamp - _nxdomain.Peek().T > Window) _nxdomain.Dequeue();
            }

            if (q.ResolvedAddresses.Count > 0)
            {
                if (!_churn.TryGetValue(name, out var c)) _churn[name] = c = new ChurnStats();
                foreach (var ip in q.ResolvedAddresses) c.Ips[IpUtil.Normalize(ip).ToString()] = q.Timestamp;
                foreach (var stale in c.Ips.Where(kv => q.Timestamp - kv.Value > ChurnWindow).Select(kv => kv.Key).ToList()) c.Ips.Remove(stale);
                if (q.Ttl is { } ttl) c.MinTtl = c.MinTtl is null ? ttl : Math.Min(c.MinTtl.Value, ttl);
            }

            if (_byBase.Count > 20_000) Compact(q.Timestamp);
        }
    }

    private void Compact(DateTimeOffset now)
    {
        foreach (var k in _byBase.Where(kv => kv.Value.Queries.Count == 0 || now - kv.Value.Queries.Last().T > Window).Select(kv => kv.Key).ToList())
            _byBase.Remove(k);
        foreach (var k in _churn.Where(kv => kv.Value.Ips.Count == 0 || kv.Value.Ips.Values.Max() < now - ChurnWindow).Select(kv => kv.Key).ToList())
            _churn.Remove(k);
    }

    /// <summary>Evidence about DNS behaviour around a name (and its registrable domain).</summary>
    public IReadOnlyList<Evidence> Evaluate(string? hostname)
    {
        var ev = new List<Evidence>();
        var name = DomainUtil.Normalize(hostname);
        if (name is null) return ev;
        var baseDomain = DomainUtil.RegistrableDomain(name);
        bool cdn = _isCdn(name);
        lock (_lock)
        {
            if (_byBase.TryGetValue(baseDomain, out var s) && s.Queries.Count > 0)
            {
                var subs = s.Queries.Select(x => x.Sub).Where(x => x.Length > 0).Distinct().ToList();
                int txt = s.Queries.Count(x => x.Type == "TXT");
                double avgSubLen = subs.Count == 0 ? 0 : subs.Average(x => x.Length);
                int total = s.Queries.Count;

                if (!cdn && subs.Count >= 30 && avgSubLen >= 20)
                    ev.Add(new Evidence(EvidenceCategory.Dns, $"Possible DNS tunnelling: {subs.Count} unique long subdomains (avg {avgSubLen:0} chars) of {baseDomain} in {Window.TotalMinutes:0} min", 0.45));
                else if (!cdn && subs.Count >= 50)
                    ev.Add(new Evidence(EvidenceCategory.Dns, $"High subdomain churn: {subs.Count} unique subdomains of {baseDomain} in {Window.TotalMinutes:0} min", 0.2));

                if (txt >= 10)
                    ev.Add(new Evidence(EvidenceCategory.Dns, $"Repeated TXT queries for {baseDomain} ({txt} in {Window.TotalMinutes:0} min): TXT is a common tunnelling/C2 channel", cdn ? 0.05 : 0.3));

                if (!cdn && total >= 300)
                    ev.Add(new Evidence(EvidenceCategory.Dns, $"High-volume DNS for {baseDomain} ({total} queries in {Window.TotalMinutes:0} min)", 0.1));
            }

            if (_churn.TryGetValue(name, out var c) && c.Ips.Count >= 10)
            {
                bool lowTtl = c.MinTtl is <= 300;
                ev.Add(new Evidence(EvidenceCategory.Dns,
                    $"Resolution changes frequently: {c.Ips.Count} distinct IPs in {ChurnWindow.TotalMinutes:0} min{(lowTtl ? $", TTL {c.MinTtl}s" : "")}{(cdn ? " (typical of CDNs)" : ": possible fast-flux")}",
                    cdn ? 0.02 : lowTtl ? 0.2 : 0.1));
            }
        }
        return ev;
    }

    /// <summary>Machine-wide NXDOMAIN burst: many failing, distinct names suggest DGA activity.</summary>
    public Evidence? NxDomainBurst()
    {
        lock (_lock)
        {
            var distinct = _nxdomain.Select(x => x.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            return distinct >= 25
                ? new Evidence(EvidenceCategory.Dns, $"{distinct} distinct non-existent domains queried in {Window.TotalMinutes:0} min (possible DGA)", 0.3)
                : null;
        }
    }

    public int DistinctIpsFor(string name)
    {
        lock (_lock) return _churn.TryGetValue(name, out var c) ? c.Ips.Count : 0;
    }
}
