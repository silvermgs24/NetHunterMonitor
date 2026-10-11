using System.Management;
using System.Net;
using NetHunter.Core.Engine;
using NetHunter.Core.Models;
using NetHunter.Core.Pcap;
using NetHunter.Core.Util;

namespace NetHunter.Windows;

public sealed record DnsCacheRecord(string Entry, string Name, int Type, int Status, int Ttl, string? Data);

/// <summary>
/// Unprivileged DNS visibility: periodically reads the Windows DNS client cache through the documented
/// MSFT_DNSClientCache WMI class (the source of Get-DnsClientCache). It cannot tell which process asked, and
/// names whose TTL expires between two polls are missed. Run as administrator for real-time ETW DNS instead.
/// </summary>
public sealed class DnsCacheSource : IDnsSource
{
    private readonly Func<int> _intervalSeconds;
    private Timer? _timer;
    private Action<DnsObservation>? _sink;
    private Action<string>? _log;
    private readonly Dictionary<string, DateTimeOffset> _reported = new(StringComparer.OrdinalIgnoreCase);
    private int _busy;
    private int _errors;

    public DnsCacheSource(Func<int> intervalSeconds) { _intervalSeconds = intervalSeconds; }

    public string Name => "DNS client cache (polling)";
    public string Capabilities => "Hostname ↔ IP mappings from the Windows DNS cache. No admin needed. No process attribution; very short TTLs may be missed.";
    public bool IsRunning => _timer is not null;

    public bool Start(Action<DnsObservation> sink, Action<string> log, out string? reason)
    {
        _sink = sink;
        _log = log;
        try { ReadCache(); }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            reason = "DNS client cache (WMI MSFT_DNSClientCache) unavailable: " + ex.Message;
            return false;
        }
        reason = null;
        _timer = new Timer(_ => Poll(), null, 0, Math.Max(2, _intervalSeconds()) * 1000);
        return true;
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    public void Dispose() => Stop();

    public static List<DnsCacheRecord> ReadCache()
    {
        var list = new List<DnsCacheRecord>();
        using var searcher = new ManagementObjectSearcher(@"root\StandardCimv2", "SELECT Entry, Name, Type, Status, TimeToLive, Data FROM MSFT_DNSClientCache");
        searcher.Options.Timeout = TimeSpan.FromSeconds(10);
        using var results = searcher.Get();
        foreach (ManagementBaseObject o in results)
        {
            using (o)
            {
                var entry = o["Entry"] as string;
                if (string.IsNullOrWhiteSpace(entry)) continue;
                list.Add(new DnsCacheRecord(
                    entry,
                    o["Name"] as string ?? entry,
                    Convert.ToInt32(o["Type"] ?? 0),
                    Convert.ToInt32(o["Status"] ?? 0),
                    Convert.ToInt32(o["TimeToLive"] ?? 0),
                    o["Data"] as string));
            }
        }
        return list;
    }

    /// <summary>Groups raw cache records into one observation per queried name.</summary>
    public static List<DnsObservation> ToObservations(IEnumerable<DnsCacheRecord> records, DateTimeOffset now)
    {
        var list = new List<DnsObservation>();
        foreach (var g in records.GroupBy(r => r.Entry.ToLowerInvariant()))
        {
            var name = DomainUtil.Normalize(g.Key);
            if (name is null || !name.Contains('.') || name.EndsWith(".arpa")) continue;
            var addrs = new List<IPAddress>();
            var answers = new List<string>();
            foreach (var r in g)
            {
                if (r.Status != 0 || r.Data is null) continue;
                if (r.Type is 1 or 28 && IpUtil.TryParse(r.Data, out var ip)) { addrs.Add(ip); answers.Add($"{DnsMessageParser.TypeName(r.Type)} {ip}"); }
                else answers.Add($"{DnsMessageParser.TypeName(r.Type)} {r.Data}");
            }
            int status = addrs.Count > 0 || answers.Count > 0 ? 0 : g.Select(r => r.Status).FirstOrDefault(s => s != 0);
            if (status == 9501) continue; // "no records of this type" (e.g. AAAA on an IPv4-only name): not a failure
            list.Add(new DnsObservation
            {
                Timestamp = now, Query = name, RecordType = g.Any(r => r.Type == 1) || !g.Any(r => r.Type == 28) ? "A" : "AAAA",
                Status = status, Answers = answers.Distinct().ToList(), ResolvedAddresses = addrs.Distinct().ToList(),
                Ttl = g.Where(r => r.Status == 0).Select(r => (int?)r.Ttl).Min(), Source = "DNS-CACHE",
            });
        }
        return list;
    }

    private void Poll()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var now = DateTimeOffset.Now;
            foreach (var obs in ToObservations(ReadCache(), now))
            {
                var sig = obs.Query + "|" + string.Join(",", obs.ResolvedAddresses.Select(x => x.ToString()).OrderBy(x => x)) + "|" + obs.Status;
                // Report an unchanged mapping at most every 30 minutes; changes are reported immediately.
                if (_reported.TryGetValue(sig, out var last) && now - last < TimeSpan.FromMinutes(30)) continue;
                _reported[sig] = now;
                _sink?.Invoke(obs);
            }
            if (_reported.Count > 50_000)
                foreach (var k in _reported.Where(kv => now - kv.Value > TimeSpan.FromHours(1)).Select(kv => kv.Key).ToList()) _reported.Remove(k);
            _errors = 0;
        }
        catch (Exception ex)
        {
            if (++_errors <= 3) _log?.Invoke("DNS cache poll failed: " + ex.Message);
        }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }
}
