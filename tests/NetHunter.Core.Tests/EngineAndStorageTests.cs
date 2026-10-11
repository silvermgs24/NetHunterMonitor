using System.Net;
using NetHunter.Core.Engine;
using NetHunter.Core.Export;
using NetHunter.Core.Intel;
using NetHunter.Core.Models;
using NetHunter.Core.Storage;
using NetHunter.Core.Synthetic;

namespace NetHunter.Core.Tests;

internal sealed class TempDb : IDisposable
{
    public string Dir { get; } = Path.Combine(Path.GetTempPath(), "nh-test-" + Guid.NewGuid().ToString("N"));
    public Database Db { get; }
    public TempDb() { Directory.CreateDirectory(Dir); Db = new Database(Path.Combine(Dir, "t.db")); }
    public void Dispose()
    {
        Db.Dispose();
        try { Directory.Delete(Dir, true); } catch (IOException) { }
    }
}

internal sealed class FakeProcesses : IProcessInfoProvider
{
    public Dictionary<int, ProcessInfo> Map { get; } = new();
    public ProcessInfo Get(int pid) => Map.TryGetValue(pid, out var p) ? p : ProcessInfo.Unknown with { Pid = pid };
}

/// <summary>A remote provider that is always unreachable, to prove monitoring works offline.</summary>
internal sealed class OfflineProvider : IRemoteReputationProvider
{
    public int Calls;
    public string Name => "OfflineTest";
    public bool IsLocal => false;
    public bool IsEnabled => true;
    public RateLimiter Limiter { get; } = new(1000, 100000);
    public bool Supports(IocType type) => true;
    public Task<ReputationResult> LookupAsync(IocType type, string value, CancellationToken ct)
    {
        Interlocked.Increment(ref Calls);
        return Task.FromResult(new ReputationResult { Provider = Name, Type = type, Value = value, Status = ReputationStatus.Offline, Detail = "test" });
    }
}

public class EngineTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 11, 12, 0, 0, TimeSpan.Zero);

    private static (MonitoringEngine Engine, ReputationService Rep, LocalIocDatabase Iocs) Build(TempDb tmp, FakeProcesses procs, IRemoteReputationProvider[]? remote = null, AppSettings? settings = null)
    {
        settings ??= new AppSettings { BaselineLearningHours = 0, Protector = new PassthroughProtector() };
        var iocs = new LocalIocDatabase();
        var rep = new ReputationService(iocs, remote ?? Array.Empty<IRemoteReputationProvider>(), new ReputationCache(TimeSpan.FromHours(1), tmp.Db));
        var engine = new MonitoringEngine(new EngineDependencies
        {
            Settings = settings, Database = tmp.Db, Reputation = rep, Processes = procs, Clock = () => T0,
        });
        engine.StartPipeline();
        return (engine, rep, iocs);
    }

    private static ConnectionObservation Conn(DateTimeOffset t, int? pid, string ip, int port, int lport, string state = "ESTABLISHED") => new()
    {
        Timestamp = t, Protocol = TransportProtocol.Tcp, Direction = Direction.Outbound, LocalAddress = IPAddress.Parse("192.168.1.20"), LocalPort = lport,
        RemoteAddress = IPAddress.Parse(ip), RemotePort = port, Pid = pid, State = state, Source = "TEST",
    };

    [Fact]
    public async Task Beaconing_unsigned_temp_binary_raises_possible_c2_alert_with_reasons()
    {
        using var tmp = new TempDb();
        var procs = new FakeProcesses();
        procs.Map[500] = new ProcessInfo { Pid = 500, Name = "updater.exe", Path = @"C:\Users\Bob\AppData\Local\Temp\updater.exe", Signature = new SignatureInfo(SignatureStatus.Unsigned, null), IsSynthetic = true };
        var (engine, rep, _) = Build(tmp, procs);
        await using (rep)
        await using (engine)
        {
            for (int i = 0; i < 12; i++) engine.Post(Conn(T0.AddSeconds(i * 60 + (i % 3)), 500, "8.8.8.8", 443, 50000 + i));
            await engine.DrainAsync(TimeSpan.FromSeconds(10));

            var flow = Assert.Single(engine.SnapshotFlows());
            Assert.Equal(12, flow.Count);
            Assert.Equal(DetectionClass.PossibleC2, flow.Assessment.Classification);
            Assert.Contains(flow.Assessment.Evidence, e => e.Category == EvidenceCategory.Beacon);
            Assert.Contains(flow.Assessment.Evidence, e => e.Text.Contains("temporary directory"));

            var alert = Assert.Single(tmp.Db.GetAlerts());
            Assert.Equal("updater.exe", alert.ProcessName);
            Assert.Equal("8.8.8.8", alert.RemoteIp);
            Assert.True(alert.Severity >= RiskLevel.High);
            Assert.NotEmpty(alert.Evidence);
        }
    }

    [Fact]
    public async Task Alert_keeps_its_strongest_evidence_after_restart()
    {
        using var tmp = new TempDb();
        var procs = new FakeProcesses();
        procs.Map[500] = new ProcessInfo { Pid = 500, Name = "updater.exe", Path = @"C:\Users\Bob\AppData\Local\Temp\updater.exe", Signature = new SignatureInfo(SignatureStatus.Unsigned, null), IsSynthetic = true };
        var (engine, rep, _) = Build(tmp, procs);
        await using (rep)
        await using (engine)
        {
            for (int i = 0; i < 12; i++) engine.Post(Conn(T0.AddSeconds(i * 60), 500, "8.8.8.8", 443, 50000 + i));
            await engine.DrainAsync(TimeSpan.FromSeconds(10));
        }
        var before = Assert.Single(tmp.Db.GetAlerts());
        Assert.Contains(before.Evidence, e => e.Category == EvidenceCategory.Beacon);

        // Restart: the beacon history is gone, so the next contact scores lower. The alert must not be downgraded.
        var (engine2, rep2, _) = Build(tmp, procs);
        await using (rep2)
        await using (engine2)
        {
            engine2.Post(Conn(T0.AddSeconds(13 * 60), 500, "8.8.8.8", 443, 50100));
            await engine2.DrainAsync(TimeSpan.FromSeconds(10));
        }
        var after = Assert.Single(tmp.Db.GetAlerts());
        Assert.Equal(before.Score, after.Score);
        Assert.Equal(before.Title, after.Title);
        Assert.Contains(after.Evidence, e => e.Category == EvidenceCategory.Beacon);
    }

    [Fact]
    public async Task Unattributed_connection_is_reported_as_unknown_process()
    {
        using var tmp = new TempDb();
        var (engine, rep, _) = Build(tmp, new FakeProcesses());
        await using (rep)
        await using (engine)
        {
            engine.Post(Conn(T0, null, "1.1.1.1", 443, 51000, "TIME_WAIT"));
            await engine.DrainAsync(TimeSpan.FromSeconds(10));
            var ev = Assert.Single(tmp.Db.QueryEvents(new EventFilter()));
            Assert.Equal("Unknown", ev.ProcessName);
            Assert.Null(ev.Pid);
            Assert.Null(ev.ProcessPath);
        }
    }

    [Fact]
    public async Task Local_ioc_detection_and_monitoring_continue_while_threat_intel_is_offline()
    {
        using var tmp = new TempDb();
        var procs = new FakeProcesses();
        procs.Map[42] = new ProcessInfo { Pid = 42, Name = "app.exe", Path = @"C:\Program Files\App\app.exe", Signature = new SignatureInfo(SignatureStatus.Signed, "Vendor") };
        var offline = new OfflineProvider();
        var (engine, rep, iocs) = Build(tmp, procs, new IRemoteReputationProvider[] { offline });
        iocs.AddLines(new[] { "45.77.1.2 # test C2" }, "case-123.txt");
        await using (rep)
        await using (engine)
        {
            rep.Start();
            engine.Post(Conn(T0, 42, "45.77.1.2", 443, 52000));
            engine.Post(Conn(T0.AddSeconds(1), 42, "1.0.0.1", 443, 52001));
            await engine.DrainAsync(TimeSpan.FromSeconds(10));
            for (int i = 0; i < 50 && offline.Calls < 2; i++) await Task.Delay(100);

            Assert.Equal(2, tmp.Db.QueryEvents(new EventFilter()).Count);
            var bad = engine.SnapshotFlows().Single(f => f.RemoteIp == "45.77.1.2");
            Assert.Equal(DetectionClass.KnownMalicious, bad.Assessment.Classification);
            Assert.Equal(RiskLevel.Critical, bad.Assessment.Level);
            Assert.Contains(bad.Assessment.Evidence, e => e.Text.Contains("case-123.txt"));
            Assert.Equal(IntelStatus.Offline, rep.Status);
        }
    }

    [Fact]
    public async Task Dns_observation_supplies_hostname_and_trusted_mark_suppresses_alert()
    {
        using var tmp = new TempDb();
        var procs = new FakeProcesses();
        procs.Map[7] = new ProcessInfo { Pid = 7, Name = "tool.exe", Path = @"C:\Users\Public\tool.exe", Signature = new SignatureInfo(SignatureStatus.Unsigned, null) };
        var (engine, rep, _) = Build(tmp, procs);
        await using (rep)
        await using (engine)
        {
            engine.SetMark("process", @"c:\users\public\tool.exe", UserMarkKind.Trusted);
            engine.Post(new DnsObservation { Timestamp = T0, Query = "api.vendor.example.com", ResolvedAddresses = new[] { IPAddress.Parse("93.184.216.34") }, Source = "TEST" });
            engine.Post(Conn(T0.AddSeconds(1), 7, "93.184.216.34", 4444, 53000));
            await engine.DrainAsync(TimeSpan.FromSeconds(10));
            var f = Assert.Single(engine.SnapshotFlows());
            Assert.Equal("api.vendor.example.com", f.Hostname);
            Assert.True(f.Assessment.Suppressed);
            Assert.Empty(tmp.Db.GetAlerts());
            Assert.Single(tmp.Db.QueryDns(null));
        }
    }

    [Fact]
    public async Task Synthetic_scenario_produces_expected_detections()
    {
        using var tmp = new TempDb();
        var settings = new AppSettings { BaselineLearningHours = 24, Protector = new PassthroughProtector() };
        var iocs = new LocalIocDatabase();
        iocs.AddLines(SyntheticScenario.IocLines, SyntheticScenario.TestIocList);
        await using var rep = new ReputationService(iocs, Array.Empty<IRemoteReputationProvider>(), new ReputationCache(TimeSpan.FromHours(1)));
        await using var engine = new MonitoringEngine(new EngineDependencies
        {
            Settings = settings, Database = tmp.Db, Reputation = rep, Processes = new SyntheticProcessProvider(null), TreatDocumentationRangesAsExternal = true,
        });
        engine.StartPipeline();
        foreach (var e in SyntheticScenario.Build(T0, TimeSpan.FromMinutes(10))) engine.Post(e);
        await engine.DrainAsync(TimeSpan.FromSeconds(20));

        var flows = engine.SnapshotFlows();
        Assert.All(flows, f => Assert.True(f.IsSynthetic));
        Assert.Equal(DetectionClass.PossibleC2, flows.Single(f => f.ProcessName == "SYNTHETIC-beacon.exe").Assessment.Classification);
        Assert.Equal(DetectionClass.PossibleC2, flows.Single(f => f.ProcessName == "powershell.exe").Assessment.Classification);
        Assert.Equal(DetectionClass.KnownMalicious, flows.Single(f => f.ProcessName == "SYNTHETIC-updater.exe").Assessment.Classification);
        Assert.All(flows.Where(f => f.ProcessName == "SYNTHETIC-browser.exe"), f => Assert.Equal(RiskLevel.Low, f.Assessment.Level));
        Assert.Contains(tmp.Db.GetAlerts(), a => a.SubjectKey == "dns:tunnel-data.example");
        Assert.All(tmp.Db.GetAlerts(), a => Assert.True(a.IsSynthetic));
    }
}

public class DatabaseTests
{
    [Fact]
    public void Stores_and_queries_events_flows_dns_alerts_marks()
    {
        using var tmp = new TempDb();
        var now = DateTimeOffset.UtcNow;
        var ev = new ConnectionEvent { Timestamp = now, RemoteIp = "1.2.3.4", RemotePort = 8443, ProcessName = "evil.exe", Hostname = "bad.example", Level = RiskLevel.High, Score = 70, FlowKey = "k" };
        var flow = new FlowRecord { Key = "k", ProcessKey = "evil.exe", ProcessName = "evil.exe", RemoteIp = "1.2.3.4", RemotePort = 8443, FirstSeen = now, LastSeen = now, Count = 3, Sha256 = new string('a', 64),
            Assessment = new RiskAssessment { Score = 70, Level = RiskLevel.High, Evidence = new[] { new Evidence(EvidenceCategory.Network, "why", 0.5) } } };
        var dns = new DnsEventRecord { Timestamp = now, Query = "bad.example", RecordType = "A", Answers = "A 1.2.3.4" };
        tmp.Db.WriteBatch(new[] { ev }, new[] { flow }, new[] { dns });

        Assert.Single(tmp.Db.QueryEvents(new EventFilter { Text = "evil" }));
        Assert.Single(tmp.Db.QueryEvents(new EventFilter { Text = "8443" }));
        Assert.Single(tmp.Db.QueryEvents(new EventFilter { MinLevel = RiskLevel.High }));
        Assert.Empty(tmp.Db.QueryEvents(new EventFilter { Text = "%" })); // LIKE wildcards are escaped
        Assert.Empty(tmp.Db.QueryEvents(new EventFilter { Text = "x' OR '1'='1" }));
        var f = Assert.Single(tmp.Db.QueryFlows());
        Assert.Equal("why", Assert.Single(f.Assessment.Evidence).Text);
        Assert.Single(tmp.Db.QueryDns("bad"));
        var iocs = tmp.Db.QueryIocs();
        Assert.Contains(iocs, i => i.Type == IocType.Ip && i.Value == "1.2.3.4");
        Assert.Contains(iocs, i => i.Type == IocType.Sha256);
        Assert.Single(tmp.Db.QueryProcesses());

        var alert = new AlertRecord { Created = now, Updated = now, Severity = RiskLevel.High, Title = "t", SubjectKey = "k", Evidence = flow.Assessment.Evidence };
        tmp.Db.UpsertAlert(alert);
        alert.Score = 80;
        tmp.Db.UpsertAlert(alert);
        Assert.Equal(80, Assert.Single(tmp.Db.GetAlerts()).Score);
        tmp.Db.AcknowledgeAlert(alert.Id, true);
        Assert.Empty(tmp.Db.GetAlerts(includeAcknowledged: false));

        tmp.Db.SetMark("ip", "1.2.3.4", UserMarkKind.Suspicious, "note");
        Assert.Equal(UserMarkKind.Suspicious, Assert.Single(tmp.Db.GetMarks()).Mark);
        tmp.Db.SetMark("ip", "1.2.3.4", UserMarkKind.None, null);
        Assert.Empty(tmp.Db.GetMarks());
    }

    [Fact]
    public void Retention_removes_old_records_and_unlimited_keeps_them()
    {
        using var tmp = new TempDb();
        var old = DateTimeOffset.UtcNow.AddHours(-30);
        tmp.Db.WriteBatch(new[] { new ConnectionEvent { Timestamp = old, RemoteIp = "1.1.1.1" } }, Array.Empty<FlowRecord>(), Array.Empty<DnsEventRecord>());
        tmp.Db.ApplyRetention(null, DateTimeOffset.UtcNow);
        Assert.Single(tmp.Db.QueryEvents(new EventFilter()));
        tmp.Db.ApplyRetention(TimeSpan.FromHours(24), DateTimeOffset.UtcNow);
        Assert.Empty(tmp.Db.QueryEvents(new EventFilter()));
    }

    [Fact]
    public void Reputation_cache_persists_across_restarts()
    {
        using var tmp = new TempDb();
        var c1 = new ReputationCache(TimeSpan.FromHours(1), tmp.Db);
        c1.Put(new ReputationResult { Provider = "VirusTotal", Type = IocType.Ip, Value = "1.2.3.4", Status = ReputationStatus.Ok, Malicious = 3, TotalEngines = 90 });
        var c2 = new ReputationCache(TimeSpan.FromHours(1), tmp.Db);
        Assert.True(c2.TryGet("VirusTotal", IocType.Ip, "1.2.3.4", out var r));
        Assert.Equal(3, r.Malicious);
    }
}

public class ExportTests
{
    [Fact]
    public void Csv_neutralises_formula_injection_and_quotes()
    {
        Assert.StartsWith("\"'=HYPERLINK", Exporter.Csv("=HYPERLINK(\"x\")"));
        Assert.StartsWith("'", Exporter.Csv("+cmd"));
        Assert.Equal("\"a,b\"", Exporter.Csv("a,b"));
        Assert.Equal("plain", Exporter.Csv("plain"));
    }

    [Fact]
    public void Html_report_encodes_untrusted_values()
    {
        var a = new AlertRecord
        {
            Created = DateTimeOffset.Now, Updated = DateTimeOffset.Now, Severity = RiskLevel.High, Title = "<script>alert(1)</script>",
            ProcessName = "x\"><img src=x onerror=alert(1)>.exe", Hostname = "<b>evil</b>",
            Evidence = new[] { new Evidence(EvidenceCategory.Network, "<iframe>", 0.3) },
        };
        var html = Exporter.HtmlReport("HOST<1>", new[] { a }, Array.Empty<FlowRecord>());
        Assert.DoesNotContain("<script>alert", html);
        Assert.DoesNotContain("<img src=x", html);
        Assert.DoesNotContain("<iframe>", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("Content-Security-Policy", html);
    }

    [Fact]
    public void Json_export_round_trips_enums_as_text()
    {
        var json = Exporter.ToJson(new[] { new AlertRecord { Severity = RiskLevel.Critical, Classification = DetectionClass.PossibleC2 } });
        Assert.Contains("\"Critical\"", json);
        Assert.Contains("\"PossibleC2\"", json);
    }
}

public class SettingsTests
{
    [Fact]
    public void Settings_round_trip_sanitize_and_never_store_plain_keys()
    {
        var path = Path.Combine(Path.GetTempPath(), "nh-settings-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var protector = new ReversingProtector();
            var s = AppSettings.Load(path, protector);
            s.SetApiKey(s.VirusTotal, "SECRET-KEY-123");
            s.PollIntervalMs = 5;
            s.Save(path);
            var text = File.ReadAllText(path);
            Assert.DoesNotContain("SECRET-KEY-123", text);
            var s2 = AppSettings.Load(path, protector);
            Assert.Equal("SECRET-KEY-123", s2.GetApiKey(s2.VirusTotal));
            Assert.Equal(250, s2.PollIntervalMs);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Corrupt_settings_fall_back_to_defaults()
    {
        var path = Path.Combine(Path.GetTempPath(), "nh-settings-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, "{ this is not json");
        try
        {
            var s = AppSettings.Load(path, new PassthroughProtector());
            Assert.Equal(1000, s.PollIntervalMs);
            Assert.True(File.Exists(path + ".corrupt"));
        }
        finally { File.Delete(path); File.Delete(path + ".corrupt"); }
    }

    private sealed class ReversingProtector : ISecretProtector
    {
        public string Protect(string plain) => "enc:" + new string(plain.Reverse().ToArray());
        public string? Unprotect(string v) => v.StartsWith("enc:") ? new string(v[4..].Reverse().ToArray()) : null;
    }
}
