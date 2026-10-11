using System.Net;
using NetHunter.Core.Engine;
using NetHunter.Core.Models;

namespace NetHunter.Core.Synthetic;

/// <summary>
/// CONTROLLED TEST MODE. Generates clearly-labelled synthetic events to exercise the detection engine without
/// real malware. Every event has IsSynthetic=true, processes are named "SYNTHETIC-*" (or carry synthetic PIDs),
/// IP addresses come from RFC 5737 documentation ranges and domains from the reserved ".example" TLD, so nothing
/// can be confused with, or sent to, real infrastructure. Synthetic data is stored in a separate database.
/// </summary>
public static class SyntheticScenario
{
    public const int PidBase = 0x7FFF0000;
    public const string TestIocList = "synthetic-test-iocs.txt";

    public static readonly IReadOnlyDictionary<int, ProcessInfo> Processes = new Dictionary<int, ProcessInfo>
    {
        [PidBase + 1] = new()
        {
            Pid = PidBase + 1, Name = "SYNTHETIC-beacon.exe", Path = @"C:\Users\Public\AppData\Local\Temp\SYNTHETIC-beacon.exe",
            ParentPid = PidBase + 9, ParentName = "explorer.exe", Signature = new SignatureInfo(SignatureStatus.Unsigned, null), IsSynthetic = true,
            Sha256 = "5f2b9a0c6e1d4f7a8b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f10",
        },
        [PidBase + 2] = new()
        {
            Pid = PidBase + 2, Name = "powershell.exe", Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ParentPid = PidBase + 8, ParentName = "winword.exe", Signature = new SignatureInfo(SignatureStatus.CatalogSigned, "Microsoft Windows (SYNTHETIC)"), IsSynthetic = true,
        },
        [PidBase + 3] = new()
        {
            Pid = PidBase + 3, Name = "SYNTHETIC-browser.exe", Path = @"C:\Program Files\SyntheticBrowser\SYNTHETIC-browser.exe",
            ParentPid = PidBase + 9, ParentName = "explorer.exe", Signature = new SignatureInfo(SignatureStatus.Signed, "Example Corp (SYNTHETIC)"), IsSynthetic = true,
        },
        [PidBase + 4] = new()
        {
            Pid = PidBase + 4, Name = "SYNTHETIC-updater.exe", Path = @"C:\ProgramData\SYNTHETIC-updater.exe",
            ParentPid = PidBase + 9, ParentName = "explorer.exe", Signature = new SignatureInfo(SignatureStatus.Unsigned, null), IsSynthetic = true,
        },
        [PidBase + 5] = new()
        {
            Pid = PidBase + 5, Name = "SYNTHETIC-dnstunnel.exe", Path = @"C:\Users\Public\SYNTHETIC-dnstunnel.exe",
            ParentPid = PidBase + 9, ParentName = "explorer.exe", Signature = new SignatureInfo(SignatureStatus.Unsigned, null), IsSynthetic = true,
        },
    };

    /// <summary>Lines for the synthetic IOC list (documentation-range IP and a reserved domain).</summary>
    public static readonly string[] IocLines =
    {
        "# Synthetic test indicators (RFC 5737 / reserved .example). Safe to delete.",
        "203.0.113.66 # SYNTHETIC known-bad IP",
        "evil-c2.example # SYNTHETIC known-bad domain",
    };

    /// <summary>Builds a deterministic timeline of synthetic observations over <paramref name="duration"/>.</summary>
    public static List<object> Build(DateTimeOffset start, TimeSpan duration, int seed = 7)
    {
        var rnd = new Random(seed);
        var events = new List<object>();
        var local = IPAddress.Parse("192.0.2.200");
        int port = 50000;
        ConnectionObservation Conn(DateTimeOffset t, int pid, string ip, int rport, string state = "ESTABLISHED") => new()
        {
            Timestamp = t, Protocol = TransportProtocol.Tcp, Direction = Direction.Outbound, LocalAddress = local, LocalPort = port++ % 65000 + 1024,
            RemoteAddress = IPAddress.Parse(ip), RemotePort = rport, Pid = pid, State = state, Source = "SYNTHETIC", IsSynthetic = true,
        };
        DnsObservation Dns(DateTimeOffset t, int pid, string q, string ip, string type = "A", int status = 0) => new()
        {
            Timestamp = t, Query = q, RecordType = type, Pid = pid, Status = status,
            ResolvedAddresses = ip.Length == 0 ? Array.Empty<IPAddress>() : new[] { IPAddress.Parse(ip) },
            Answers = ip.Length == 0 ? Array.Empty<string>() : new[] { $"{type} {ip}" }, Ttl = 60, Source = "SYNTHETIC", IsSynthetic = true,
        };

        // 1) Unsigned binary in a temp directory beaconing every ~10 s with ±8% jitter.
        events.Add(Dns(start, PidBase + 1, "cdn-sync-update.example", "203.0.113.50"));
        for (var t = start.AddSeconds(1); t < start + duration; t = t.AddSeconds(10 * (1 + (rnd.NextDouble() - 0.5) * 0.16)))
            events.Add(Conn(t, PidBase + 1, "203.0.113.50", 443));

        // 2) PowerShell started by Word, polling an unusual port every ~15 s.
        for (var t = start.AddSeconds(3); t < start + duration; t = t.AddSeconds(15 * (1 + (rnd.NextDouble() - 0.5) * 0.1)))
            events.Add(Conn(t, PidBase + 2, "198.51.100.23", 8080));

        // 3) Benign-looking browser: irregular contact with several destinations.
        var t3 = start.AddSeconds(2);
        while (t3 < start + duration)
        {
            int n = rnd.Next(10, 31);
            events.Add(Dns(t3, PidBase + 3, $"site{n}.example", $"192.0.2.{n}"));
            events.Add(Conn(t3.AddMilliseconds(50), PidBase + 3, $"192.0.2.{n}", 443));
            t3 = t3.AddSeconds(rnd.Next(1, 40));
        }

        // 4) One connection to an IP on the synthetic local IOC list, on a Metasploit-default port.
        events.Add(Dns(start.AddSeconds(20), PidBase + 4, "evil-c2.example", "203.0.113.66"));
        events.Add(Conn(start.AddSeconds(21), PidBase + 4, "203.0.113.66", 4444));

        // 5) DNS tunnelling pattern: many long random TXT queries under one domain.
        const string alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < 45; i++)
        {
            var label = new string(Enumerable.Range(0, 40).Select(_ => alphabet[rnd.Next(alphabet.Length)]).ToArray());
            events.Add(Dns(start.AddSeconds(30 + i * 0.5), PidBase + 5, $"{label}.t.tunnel-data.example", "", "TXT"));
        }

        return events.OrderBy(e => e switch { ConnectionObservation c => c.Timestamp, DnsObservation d => d.Timestamp, _ => start }).ToList();
    }
}

/// <summary>Answers process lookups for synthetic PIDs and delegates everything else to the real provider.</summary>
public sealed class SyntheticProcessProvider : IProcessInfoProvider
{
    private readonly IProcessInfoProvider? _inner;
    public SyntheticProcessProvider(IProcessInfoProvider? inner) { _inner = inner; }

    public ProcessInfo Get(int pid) =>
        SyntheticScenario.Processes.TryGetValue(pid, out var p) ? p : _inner?.Get(pid) ?? ProcessInfo.Unknown with { Pid = pid };
}

/// <summary>Replays the synthetic timeline in real time (UI test mode). Implements both source interfaces.</summary>
public sealed class SyntheticSource : IConnectionSource, IDnsSource
{
    private readonly TimeSpan _duration;
    private CancellationTokenSource? _cts;
    private Action<ConnectionObservation>? _connSink;
    private Action<DnsObservation>? _dnsSink;

    public SyntheticSource(TimeSpan duration) { _duration = duration; }

    public string Name => "SYNTHETIC test generator";
    public string Capabilities => "Controlled synthetic events for testing detections. NOT real traffic.";
    public bool IsRunning { get; private set; }

    bool IConnectionSource.Start(Action<ConnectionObservation> sink, Action<string> log, out string? reason)
    {
        _connSink = sink;
        reason = null;
        EnsureRunning(log);
        return true;
    }

    bool IDnsSource.Start(Action<DnsObservation> sink, Action<string> log, out string? reason)
    {
        _dnsSink = sink;
        reason = null;
        EnsureRunning(log);
        return true;
    }

    private void EnsureRunning(Action<string> log)
    {
        if (IsRunning) return;
        IsRunning = true;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        var start = DateTimeOffset.Now;
        var timeline = SyntheticScenario.Build(start, _duration, Environment.TickCount);
        log("SYNTHETIC test mode: replaying generated events (not real traffic)");
        _ = Task.Run(async () =>
        {
            foreach (var e in timeline)
            {
                var at = e is ConnectionObservation c ? c.Timestamp : ((DnsObservation)e).Timestamp;
                var wait = at - DateTimeOffset.Now;
                if (wait > TimeSpan.Zero) await Task.Delay(wait, ct).ConfigureAwait(false);
                if (ct.IsCancellationRequested) return;
                if (e is ConnectionObservation co) _connSink?.Invoke(co);
                else if (e is DnsObservation dn) _dnsSink?.Invoke(dn);
            }
        }, ct);
    }

    public void Stop()
    {
        _cts?.Cancel();
        IsRunning = false;
    }

    public void Dispose() => Stop();
}
