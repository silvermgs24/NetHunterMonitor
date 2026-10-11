using System.Net.Http.Headers;
using NetHunter.Core.Engine;
using NetHunter.Core.Intel;
using NetHunter.Core.Storage;
using NetHunter.Core.Synthetic;

namespace NetHunter.Windows;

public enum HostMode { Live, Synthetic, Pcap }

/// <summary>
/// Composition root shared by the desktop app and the CLI. Keeps everything portable: config, database,
/// logs and IOC lists live next to the executable (falls back to %LOCALAPPDATA% if that folder is read-only).
/// </summary>
public sealed class AppHost : IAsyncDisposable
{
    private AppHost(string root, AppSettings settings, Database db, ReputationService rep, MonitoringEngine engine, FileLog log, HostMode mode, VirusTotalProvider vt)
    {
        Root = root; Settings = settings; Database = db; Reputation = rep; Engine = engine; LogFile = log; Mode = mode; VirusTotal = vt;
    }

    public string Root { get; }
    public string ConfigPath => Path.Combine(Root, "config", "settings.json");
    public string IocDirectory => Path.Combine(Root, "config", "ioc");
    public string ExportDirectory => Path.Combine(Root, "exports");
    public AppSettings Settings { get; }
    public Database Database { get; }
    public ReputationService Reputation { get; }
    public MonitoringEngine Engine { get; }
    public FileLog LogFile { get; }
    public HostMode Mode { get; }
    public VirusTotalProvider VirusTotal { get; }
    public bool IsElevated { get; } = Elevation.IsElevated;
    public IReadOnlyList<Core.Intel.IocImportResult> IocLoadResults { get; private set; } = Array.Empty<IocImportResult>();

    public static string ResolveRoot()
    {
        var exeDir = AppContext.BaseDirectory;
        try
        {
            var probe = Path.Combine(exeDir, ".write-test");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return exeDir;
        }
        catch (Exception)
        {
            var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetHunterMonitor");
            Directory.CreateDirectory(fallback);
            return fallback;
        }
    }

    private static readonly HttpClient Http = CreateHttp();

    private static HttpClient CreateHttp()
    {
        // Default certificate validation is kept; TLS is enforced by the providers (https-only URIs).
        var handler = new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(10), AutomaticDecompression = System.Net.DecompressionMethods.All };
        var c = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("NetHunterMonitor", "1.0"));
        return c;
    }

    public static AppHost Create(HostMode mode = HostMode.Live, string? root = null, string? databaseFile = null)
    {
        root ??= ResolveRoot();
        foreach (var d in new[] { "config", "database", "logs", Path.Combine("config", "ioc") }) Directory.CreateDirectory(Path.Combine(root, d));
        var log = new FileLog(Path.Combine(root, "logs"));
        var settings = AppSettings.Load(Path.Combine(root, "config", "settings.json"), new DpapiProtector());
        if (!File.Exists(Path.Combine(root, "config", "settings.json"))) settings.Save(Path.Combine(root, "config", "settings.json"));

        var dbName = databaseFile ?? mode switch { HostMode.Synthetic => "synthetic-test.db", _ => "nethunter.db" };
        var db = new Database(Path.Combine(root, "database", dbName));

        var iocDb = new LocalIocDatabase();
        var loadResults = iocDb.LoadDirectory(Path.Combine(root, "config", "ioc"));
        if (mode == HostMode.Synthetic) iocDb.AddLines(SyntheticScenario.IocLines, SyntheticScenario.TestIocList);

        var cache = new ReputationCache(TimeSpan.FromHours(settings.ReputationCacheHours), db);
        var abuse = new AbuseIpDbProvider(Http, () => settings.GetApiKey(settings.AbuseIpDb), () => settings.ThreatIntelEnabled && settings.AbuseIpDb.Enabled,
            new RateLimiter(settings.AbuseIpDb.RequestsPerMinute, settings.AbuseIpDb.RequestsPerDay));
        var vt = new VirusTotalProvider(Http, () => settings.GetApiKey(settings.VirusTotal), () => settings.ThreatIntelEnabled && settings.VirusTotal.Enabled,
            new RateLimiter(settings.VirusTotal.RequestsPerMinute, settings.VirusTotal.RequestsPerDay));
        var rep = new ReputationService(iocDb, new IRemoteReputationProvider[] { abuse, vt }, cache, () => settings.ThreatIntelEnabled && mode != HostMode.Synthetic,
            mode == HostMode.Synthetic ? "Threat intelligence off in synthetic test mode (test data is never sent out)" : null);
        rep.ApiQueried += q => log.Write($"Threat intel query: {q.Provider} {q.Type} {q.Value} → {q.Outcome}");

        var processes = new WindowsProcessInfoProvider();
        var ipHelper = new IpHelperConnectionSource(() => settings.PollIntervalMs);
        var connSources = new List<IConnectionSource>();
        var dnsSources = new List<IDnsSource>();
        IProcessInfoProvider procProvider = processes;
        switch (mode)
        {
            case HostMode.Live:
                if (settings.UseEtwWhenElevated) connSources.Add(new EtwNetworkSource());
                connSources.Add(ipHelper);
                if (settings.UseEtwWhenElevated) dnsSources.Add(new EtwDnsSource());
                dnsSources.Add(new DnsCacheSource(() => settings.DnsCachePollSeconds));
                break;
            case HostMode.Synthetic:
                var syn = new SyntheticSource(TimeSpan.FromMinutes(10));
                connSources.Add(syn);
                dnsSources.Add(syn);
                procProvider = new SyntheticProcessProvider(processes);
                break;
            case HostMode.Pcap:
                break; // observations are posted by the PCAP analyzer
        }

        var engine = new MonitoringEngine(new EngineDependencies
        {
            Settings = settings, Database = db, Reputation = rep, Processes = procProvider, Signatures = new AuthenticodeVerifier(),
            Resolver = mode == HostMode.Live ? new SystemHostnameResolver() : null, Listeners = ipHelper,
            ConnectionSources = connSources, DnsSources = dnsSources, TreatDocumentationRangesAsExternal = mode is HostMode.Synthetic or HostMode.Pcap,
        });
        engine.Log += log.Write;
        var host = new AppHost(root, settings, db, rep, engine, log, mode, vt) { IocLoadResults = loadResults };
        log.Write($"NetHunter Monitor starting: mode={mode}, root={root}, elevated={host.IsElevated}, iocs={iocDb.Count}");
        return host;
    }

    public void SaveSettings() => Settings.Save(ConfigPath);

    public async ValueTask DisposeAsync()
    {
        await Engine.DisposeAsync().ConfigureAwait(false);
        await Reputation.DisposeAsync().ConfigureAwait(false);
        Database.Dispose();
        LogFile.Write("NetHunter Monitor stopped");
        LogFile.Dispose();
    }
}

/// <summary>Daily-rolling text log in logs/. Thread-safe; never throws into callers.</summary>
public sealed class FileLog : IDisposable
{
    private readonly string _dir;
    private readonly object _lock = new();
    private StreamWriter? _writer;
    private DateOnly _day;

    public FileLog(string dir) { _dir = dir; }

    public void Write(string message)
    {
        try
        {
            lock (_lock)
            {
                var today = DateOnly.FromDateTime(DateTime.Now);
                if (_writer is null || today != _day)
                {
                    _writer?.Dispose();
                    _day = today;
                    _writer = new StreamWriter(new FileStream(Path.Combine(_dir, $"nethunter-{today:yyyyMMdd}.log"), FileMode.Append, FileAccess.Write, FileShare.ReadWrite)) { AutoFlush = true };
                }
                var clean = new string(message.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
                _writer.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {clean}");
            }
        }
        catch (Exception) { /* logging must never break monitoring */ }
    }

    public void Dispose()
    {
        lock (_lock) { _writer?.Dispose(); _writer = null; }
    }
}
