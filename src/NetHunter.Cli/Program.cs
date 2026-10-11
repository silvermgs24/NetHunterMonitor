using System.Net;
using NetHunter.Core.Engine;
using NetHunter.Core.Export;
using NetHunter.Core.Intel;
using NetHunter.Core.Models;
using NetHunter.Core.Pcap;
using NetHunter.Core.Synthetic;
using NetHunter.Windows;

namespace NetHunter.Cli;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        var cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "help";
        try
        {
            return cmd switch
            {
                "snapshot" => Snapshot(),
                "listeners" => Listeners(),
                "dns-cache" => DnsCache(),
                "watch" => await Watch(ParseSeconds(args, 60)),
                "synthetic" => await Synthetic(),
                "pcap" when args.Length > 1 => await Pcap(args[1]),
                "check" when args.Length > 1 => CheckIoc(args[1]),
                "hash" when args.Length > 1 => Hash(args[1]),
                "make-sample-pcap" when args.Length > 1 => MakeSamplePcap(args[1]),
                "status" => Status(),
                _ => Help(),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static int ParseSeconds(string[] args, int def) => args.Length > 1 && int.TryParse(args[1], out var s) ? Math.Clamp(s, 1, 86400) : def;

    private static int Help()
    {
        Console.WriteLine("""
            NetHunter Monitor CLI

              nethunter status            Privileges and which collectors can run
              nethunter snapshot          Current TCP connections with process attribution, path, SHA-256, signature
              nethunter listeners         Listening TCP/UDP ports with owning process and risk
              nethunter dns-cache         Hostname/IP mappings currently in the Windows DNS cache
              nethunter watch [seconds]   Run the full live detection pipeline and print alerts (default 60 s)
              nethunter synthetic         Run the SYNTHETIC test scenario through the detection engine (fast, offline)
              nethunter pcap <file>       Analyze a .pcap/.pcapng with the same detection pipeline
              nethunter check <ioc>       Check an IP/domain/SHA-256 against local IOC lists and cached reputation
              nethunter hash <file>       SHA-256 and Authenticode signature of a file
              nethunter make-sample-pcap <file>  Write a SYNTHETIC sample capture (documentation IPs) to try PCAP import
            """);
        return 0;
    }

    private static int Status()
    {
        Console.WriteLine($"Elevated: {Elevation.IsElevated}");
        Console.WriteLine("Available without administrator:");
        foreach (var f in Elevation.FeaturesWithoutAdmin) Console.WriteLine("  ✓ " + f);
        Console.WriteLine(Elevation.IsElevated ? "Enabled because running as administrator:" : "Requires administrator (not available now):");
        foreach (var f in Elevation.FeaturesRequiringAdmin) Console.WriteLine((Elevation.IsElevated ? "  ✓ " : "  ✗ ") + f);
        return 0;
    }

    private static int Snapshot()
    {
        var procs = new WindowsProcessInfoProvider();
        var sig = new AuthenticodeVerifier();
        var hasher = new NetHunter.Core.Util.FileHasher();
        var rows = IpHelperTables.GetTcp().Where(r => r.State != TcpState.Listen).OrderBy(r => r.Pid).ToList();
        Console.WriteLine($"{rows.Count} TCP connections (elevated: {Elevation.IsElevated})\n");
        foreach (var g in rows.GroupBy(r => r.Pid))
        {
            var p = g.Key == 0 ? ProcessInfo.Unknown : procs.Get(g.Key);
            string? sha = p.Path is null ? null : hasher.TryHash(p.Path, out _);
            var signature = p.Path is null ? SignatureInfo.Unknown : sig.Verify(p.Path);
            Console.WriteLine($"{p.Name}  PID {(g.Key == 0 ? "-" : g.Key)}  parent {p.ParentName ?? "?"}");
            Console.WriteLine($"   path: {p.Path ?? "(unknown) " + p.AttributionNote}");
            Console.WriteLine($"   sha256: {sha ?? "(unavailable)"}  signature: {signature}");
            foreach (var r in g) Console.WriteLine($"   {r.LocalAddress}:{r.LocalPort} → {r.RemoteAddress}:{r.RemotePort}  {IpHelperTables.StateName(r.State)}");
        }
        return 0;
    }

    private static int Listeners()
    {
        var src = new IpHelperConnectionSource(() => 1000);
        var procs = new WindowsProcessInfoProvider();
        foreach (var l in src.GetListeners().OrderBy(l => l.Port))
        {
            var p = l.Pid is { } pid ? procs.Get(pid) : ProcessInfo.Unknown;
            Console.WriteLine($"{l.Protocol,-4} {l.LocalAddress,-28} {l.Port,6}  {p.Name} (PID {l.Pid?.ToString() ?? "-"})");
        }
        return 0;
    }

    private static int DnsCache()
    {
        var obs = DnsCacheSource.ToObservations(DnsCacheSource.ReadCache(), DateTimeOffset.Now);
        Console.WriteLine($"{obs.Count} names in the DNS client cache");
        foreach (var o in obs.Take(200))
            Console.WriteLine($"  {o.Query} → {(o.Status == 0 ? string.Join(", ", o.Answers) : "status " + o.Status)}  (TTL {o.Ttl})");
        return 0;
    }

    private static void PrintBatch(EngineBatch b, bool verbose)
    {
        if (verbose)
            foreach (var e in b.Events)
                Console.WriteLine($"{e.Timestamp:HH:mm:ss} {(e.Direction == Direction.Inbound ? "IN " : "OUT")} {e.ProcessName,-22} {e.RemoteIp,-40} {e.Hostname ?? "",-35} {e.RemotePort}/{e.Protocol} {e.Level.Label()}");
        foreach (var a in b.Alerts)
        {
            Console.WriteLine($"\n=== {a.Severity.Label()}  {a.Title}{(a.IsSynthetic ? "  [SYNTHETIC]" : "")} ===");
            Console.WriteLine($"Process:     {a.ProcessName} (PID {a.Pid?.ToString() ?? "?"})  {a.ProcessPath}");
            Console.WriteLine($"Destination: {a.RemoteIp}{(a.RemotePort is null ? "" : ":" + a.RemotePort)}  {a.Hostname}");
            Console.WriteLine($"Score {a.Score}/100, confidence {a.Confidence}%  ({a.Classification.Describe()})");
            foreach (var e in a.Evidence) Console.WriteLine($"   {(e.Strength < 0 ? "-" : e.Strength >= 0.1 ? "✓" : "·")} {e.Text}");
        }
    }

    private static async Task<int> Watch(int seconds)
    {
        await using var host = AppHost.Create(HostMode.Live);
        host.Engine.BatchReady += b => PrintBatch(b, true);
        host.Engine.Log += Console.WriteLine;
        host.Engine.StartMonitoring();
        foreach (var s in host.Engine.Sources) Console.WriteLine($"[{(s.Running ? "running" : "off")}] {s.Name}{(s.Problem is null ? "" : " — " + s.Problem)}");
        Console.WriteLine($"Threat intel: {host.Reputation.StatusText}\nWatching for {seconds} s...\n");
        await Task.Delay(TimeSpan.FromSeconds(seconds));
        host.Engine.StopMonitoring();
        await host.Engine.DrainAsync(TimeSpan.FromSeconds(10));
        var flows = host.Engine.SnapshotFlows();
        Console.WriteLine($"\n{flows.Count} flows, {flows.Count(f => f.Assessment.Level >= RiskLevel.Medium)} at SUSPICIOUS or above.");
        foreach (var f in flows.OrderByDescending(f => f.Assessment.Score).ThenBy(f => f.ProcessName).Take(40))
            Console.WriteLine($"  {f.Assessment.Level.Label(),-10} {f.Assessment.Score,3}  {f.ProcessName,-24} {f.RemoteIp}:{f.RemotePort}  host={f.Hostname ?? "-"} ptr={f.Ptr ?? "-"} x{f.Count}");
        return 0;
    }

    private static async Task<int> Synthetic()
    {
        var root = Path.Combine(Path.GetTempPath(), "nethunter-synthetic-" + Guid.NewGuid().ToString("N")[..8]);
        await using (var host = AppHost.Create(HostMode.Synthetic, root))
        {
            host.Engine.StartPipeline();
            Console.WriteLine("Running the SYNTHETIC scenario (generated events, not real traffic)...");
            foreach (var e in SyntheticScenario.Build(DateTimeOffset.Now.AddMinutes(-10), TimeSpan.FromMinutes(10))) host.Engine.Post(e);
            await host.Engine.DrainAsync(TimeSpan.FromSeconds(30));
            var final = new EngineBatch();
            final.Alerts.AddRange(host.Database.GetAlerts().OrderByDescending(a => a.Severity));
            PrintBatch(final, false);
            var flows = host.Engine.SnapshotFlows().OrderByDescending(f => f.Assessment.Score).ToList();
            Console.WriteLine("\nFlow risk summary:");
            foreach (var f in flows.Take(12))
                Console.WriteLine($"  {f.Assessment.Level.Label(),-10} {f.Assessment.Score,3}  {f.ProcessName,-24} → {f.RemoteIp}:{f.RemotePort} {f.Hostname}  ({f.Assessment.Classification.Describe()})");
        }
        try { Directory.Delete(root, true); } catch (IOException) { }
        return 0;
    }

    private static async Task<int> Pcap(string file)
    {
        var name = Path.GetFileNameWithoutExtension(file);
        await using var host = AppHost.Create(HostMode.Pcap, databaseFile: Path.Combine("pcap", $"{name}-{DateTime.Now:yyyyMMdd-HHmmss}.db"));
        host.Engine.BatchReady += b => PrintBatch(b, false);
        host.Engine.StartPipeline();
        var summary = PcapAnalyzer.Analyze(file, host.Engine.Post, host.Reputation.LocalDb);
        await host.Engine.DrainAsync(TimeSpan.FromSeconds(60));
        Console.WriteLine($"\n{summary.File}: {summary.Packets} packets ({summary.Decoded} decoded), {summary.Connections} connections, {summary.DnsMessages} DNS messages, {summary.TlsSni} TLS SNI, {summary.HttpRequests} HTTP requests");
        foreach (var w in summary.Warnings) Console.WriteLine("warning: " + w);
        foreach (var u in summary.UrlIocMatches) Console.WriteLine("URL IOC: " + u);
        foreach (var f in host.Engine.SnapshotFlows().OrderByDescending(f => f.Assessment.Score).Take(25))
            Console.WriteLine($"  {f.Assessment.Level.Label(),-10} {f.Assessment.Score,3}  {f.RemoteIp}:{f.RemotePort}/{f.Protocol} {f.Hostname} x{f.Count}");
        Console.WriteLine($"\nResults stored in {host.Database.Path}");
        return 0;
    }

    private static int CheckIoc(string value)
    {
        var host = AppHost.Create(HostMode.Live);
        try
        {
            var type = LocalIocDatabase.Classify(value, out var normalized);
            if (type is null) { Console.WriteLine("Not a recognised IP, domain, SHA-256 or URL."); return 2; }
            var results = host.Reputation.GetKnown(type.Value, normalized);
            Console.WriteLine($"{type}: {normalized}");
            if (results.Count == 0) Console.WriteLine("  No local IOC match and no cached reputation.");
            foreach (var r in results) Console.WriteLine("  " + r.Summary());
            return 0;
        }
        finally { host.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
    }

    private static int MakeSamplePcap(string file)
    {
        File.WriteAllBytes(file, NetHunter.Core.Synthetic.SyntheticCapture.Build(DateTimeOffset.Now.AddMinutes(-20), TimeSpan.FromMinutes(20)));
        Console.WriteLine($"Wrote SYNTHETIC sample capture {Path.GetFullPath(file)} ({new FileInfo(file).Length:N0} bytes). Not real traffic.");
        return 0;
    }

    private static int Hash(string file)
    {
        var sha = new NetHunter.Core.Util.FileHasher().TryHash(file, out var err);
        Console.WriteLine($"SHA-256:   {sha ?? "(" + err + ")"}");
        Console.WriteLine($"Signature: {new AuthenticodeVerifier().Verify(Path.GetFullPath(file))}");
        return 0;
    }
}
