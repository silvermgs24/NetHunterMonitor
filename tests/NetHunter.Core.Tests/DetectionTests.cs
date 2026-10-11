using NetHunter.Core.Detection;
using NetHunter.Core.Models;

namespace NetHunter.Core.Tests;

public class BeaconDetectorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 11, 12, 0, 0, TimeSpan.Zero);

    private static List<DateTimeOffset> Series(params double[] offsets) => offsets.Select(o => T0.AddSeconds(o)).ToList();

    [Fact]
    public void Prompt_example_is_a_possible_beacon_of_about_60s()
    {
        // 12:00:01, 12:01:02, 12:02:01, 12:03:03
        var r = BeaconDetector.Analyze(Series(1, 62, 121, 183));
        Assert.True(r.IsBeacon);
        Assert.InRange(r.IntervalSeconds, 59, 62);
        Assert.True(r.Confidence >= 0.5);
    }

    [Fact]
    public void Jittered_beacon_is_detected()
    {
        var rnd = new Random(1);
        var t = new List<double>();
        double x = 0;
        for (int i = 0; i < 30; i++) { t.Add(x); x += 30 * (1 + (rnd.NextDouble() - 0.5) * 0.4); } // ±20 % jitter
        var r = BeaconDetector.Analyze(Series(t.ToArray()));
        Assert.True(r.IsBeacon, r.Describe());
        Assert.InRange(r.IntervalSeconds, 27, 33);
    }

    [Fact]
    public void Missed_beats_still_fit_the_period()
    {
        var r = BeaconDetector.Analyze(Series(0, 300, 600, 1200, 1500, 1800, 2400, 2700));
        Assert.True(r.IsBeacon, r.Describe());
        Assert.InRange(r.IntervalSeconds, 295, 305);
    }

    [Fact]
    public void Random_human_traffic_is_not_a_beacon()
    {
        var rnd = new Random(42);
        var t = new List<double>();
        double x = 0;
        for (int i = 0; i < 40; i++) { t.Add(x); x += rnd.Next(3, 600); }
        var r = BeaconDetector.Analyze(Series(t.ToArray()));
        Assert.False(r.IsBeacon, r.Describe());
    }

    [Fact]
    public void Too_few_contacts_or_too_fast_is_not_a_beacon()
    {
        Assert.False(BeaconDetector.Analyze(Series(0, 60, 120)).IsBeacon);
        Assert.False(BeaconDetector.Analyze(Series(0, 2.5, 5, 7.5, 10, 12.5, 15)).IsBeacon); // below 5 s minimum
    }

    [Fact]
    public void Parallel_bursts_collapse_into_one_contact()
    {
        // A browser opening 4 sockets at once every 60 s is still periodic, not 4x denser.
        var list = new List<double>();
        for (int i = 0; i < 6; i++) list.AddRange(new[] { i * 60.0, i * 60 + 0.1, i * 60 + 0.2, i * 60 + 0.3 });
        var r = BeaconDetector.Analyze(Series(list.ToArray()));
        Assert.Equal(6, r.Contacts);
        Assert.True(r.IsBeacon);
    }

    [Fact]
    public void Tracker_analyzes_per_key()
    {
        var tr = new BeaconTracker();
        for (int i = 0; i < 8; i++) tr.AddContact("a", T0.AddSeconds(i * 20));
        tr.AddContact("b", T0);
        Assert.True(tr.Analyze("a").IsBeacon);
        Assert.False(tr.Analyze("b").IsBeacon);
        Assert.False(tr.Analyze("missing").IsBeacon);
    }
}

public class RiskScorerTests
{
    [Fact]
    public void Single_weak_signal_stays_low()
    {
        var input = new AssessmentInput();
        input.Add(new Evidence(EvidenceCategory.Network, "Unusual destination port 8443", 0.08));
        var a = RiskScorer.Assess(input);
        Assert.Equal(RiskLevel.Low, a.Level);
        Assert.Equal(DetectionClass.None, a.Classification);
    }

    [Fact]
    public void Port_443_cloud_no_ptr_unknown_to_vt_is_not_malware()
    {
        // The prompt's "do not claim malware merely because..." list: none of these alone should alert.
        var input = new AssessmentInput { ExternalDestination = true, ProcessAttributed = true, IntelConsulted = true };
        input.AddRange(RiskScorer.FromReputation(new[]
        {
            new ReputationResult { Provider = "VirusTotal", Type = IocType.Sha256, Value = new string('a', 64), Status = ReputationStatus.NotFound },
            new ReputationResult { Provider = "VirusTotal", Type = IocType.Ip, Value = "52.1.1.1", Status = ReputationStatus.Ok, Malicious = 0, TotalEngines = 90 },
        }, "x"));
        var a = RiskScorer.Assess(input);
        Assert.True(a.Score < 35, $"score {a.Score}");
        Assert.Equal(DetectionClass.None, a.Classification);
    }

    [Fact]
    public void Multiple_independent_signals_reinforce()
    {
        var one = new AssessmentInput();
        one.Add(new Evidence(EvidenceCategory.Reputation, "AbuseIPDB 80%", 0.5));
        var many = new AssessmentInput();
        many.Add(new Evidence(EvidenceCategory.Reputation, "AbuseIPDB 80%", 0.5));
        many.Add(new Evidence(EvidenceCategory.Process, "Temp dir", 0.3));
        many.Add(new Evidence(EvidenceCategory.Process, "Unsigned", 0.15));
        var a1 = RiskScorer.Assess(one);
        var a2 = RiskScorer.Assess(many);
        Assert.True(a2.Score > a1.Score);
        Assert.True(a2.Confidence > a1.Confidence);
        Assert.Equal(DetectionClass.PossibleC2, a2.Classification);
        Assert.Equal(3, a2.Evidence.Count);
    }

    [Fact]
    public void Beacon_plus_process_signals_is_possible_c2_never_confirmed()
    {
        var input = new AssessmentInput
        {
            Beacon = new BeaconResult(true, 60, 0.9, 20, 0.02, 1),
        };
        input.Add(new Evidence(EvidenceCategory.Process, "Executable runs from a temporary directory", 0.3));
        var a = RiskScorer.Assess(input);
        Assert.Equal(DetectionClass.PossibleC2, a.Classification);
        Assert.Contains(a.Evidence, e => e.Text.StartsWith("Possible C2 beacon"));
        Assert.Equal("Possible C2 beacon", a.Title);
    }

    [Fact]
    public void Local_ioc_match_is_critical_and_cannot_be_trusted_away()
    {
        var input = new AssessmentInput { Mark = UserMarkKind.Trusted };
        input.AddRange(RiskScorer.FromReputation(new[]
        {
            new ReputationResult { Provider = "Local IOC", Type = IocType.Ip, Value = "1.2.3.4", Status = ReputationStatus.Ok, ListName = "apt.txt", Detail = "matched 1.2.3.4" },
        }, "Destination IP 1.2.3.4"));
        var a = RiskScorer.Assess(input);
        Assert.Equal(RiskLevel.Critical, a.Level);
        Assert.Equal(DetectionClass.KnownMalicious, a.Classification);
        Assert.False(a.Suppressed);
    }

    [Fact]
    public void Trusted_mark_reduces_and_suppresses_behavioural_alerts()
    {
        var input = new AssessmentInput { Mark = UserMarkKind.Trusted, MarkSubject = "process x" };
        input.Add(new Evidence(EvidenceCategory.Process, "Temp dir", 0.3));
        input.Add(new Evidence(EvidenceCategory.Network, "Port 4444", 0.25));
        var a = RiskScorer.Assess(input);
        Assert.True(a.Suppressed);
        Assert.True(a.Score < 35);
        Assert.Contains(a.Evidence, e => e.IsMitigating);
    }

    [Fact]
    public void Virustotal_hash_consensus_is_known_malicious_single_engine_is_weak()
    {
        Assessment(10, out var strong);
        Assessment(1, out var weak);
        Assert.Equal(DetectionClass.KnownMalicious, strong.Classification);
        Assert.Equal(RiskLevel.Low, weak.Level);

        static void Assessment(int engines, out RiskAssessment a)
        {
            var input = new AssessmentInput();
            input.AddRange(RiskScorer.FromReputation(new[]
            {
                new ReputationResult { Provider = "VirusTotal", Type = IocType.Sha256, Value = new string('c', 64), Status = ReputationStatus.Ok, Malicious = engines, TotalEngines = 72 },
            }, "hash"));
            a = RiskScorer.Assess(input);
        }
    }

    [Fact]
    public void Abuseipdb_grades_and_whitelist_mitigates()
    {
        static int Score(int conf, bool white = false)
        {
            var i = new AssessmentInput();
            i.Add(new Evidence(EvidenceCategory.Process, "x", 0.3));
            i.AddRange(RiskScorer.FromReputation(new[] { new ReputationResult { Provider = "AbuseIPDB", Type = IocType.Ip, Value = "1.1.1.1", Status = ReputationStatus.Ok, AbuseConfidence = conf, TotalReports = 10, IsWhitelisted = white } }, "ip"));
            return RiskScorer.Assess(i).Score;
        }
        Assert.True(Score(90) > Score(40));
        Assert.True(Score(40) > Score(5));
        Assert.True(Score(90, white: true) < Score(5));
    }

    [Fact]
    public void Every_non_trivial_assessment_explains_itself()
    {
        var input = new AssessmentInput();
        input.Add(new Evidence(EvidenceCategory.Domain, "Random-looking domain", 0.25));
        input.Add(new Evidence(EvidenceCategory.Network, "Port 4444", 0.25));
        var a = RiskScorer.Assess(input);
        Assert.NotEmpty(a.Title);
        Assert.All(a.Evidence, e => Assert.False(string.IsNullOrWhiteSpace(e.Text)));
        Assert.InRange(a.Score, 0, 100);
        Assert.InRange(a.Confidence, 0, 99);
    }
}

public class DomainAndDnsAnalyzerTests
{
    private static DomainAnalyzer Analyzer() => new(() => new[] { "top", "xyz" }, () => new[] { "cloudfront.net", "akamaiedge.net" });

    [Theory]
    [InlineData("www.google.com")]
    [InlineData("login.microsoftonline.com")]
    [InlineData("github.com")]
    [InlineData("api.anthropic.com")]
    public void Ordinary_domains_have_no_randomness_evidence(string d)
    {
        Assert.DoesNotContain(Analyzer().Analyze(d), e => e.Text.Contains("Random"));
    }

    [Theory]
    [InlineData("xk7q2zp9vbt4m1rw.com")]
    [InlineData("qwrtzpsdfghjklmnb.net")]
    public void Dga_like_domains_are_flagged(string d)
    {
        Assert.Contains(Analyzer().Analyze(d), e => e.Text.Contains("DGA") && e.Strength >= 0.2);
    }

    [Fact]
    public void Cdn_names_are_discounted_not_whitelisted()
    {
        var ev = Analyzer().Analyze("d3k8x7q2zp9vbt4m1rw.cloudfront.net");
        var e = Assert.Single(ev, x => x.Text.Contains("Random"));
        Assert.True(e.Strength < 0.05);
    }

    [Fact]
    public void Suspicious_tld_and_dynamic_dns_are_signals()
    {
        Assert.Contains(Analyzer().Analyze("update.top"), e => e.Text.Contains(".top"));
        Assert.Contains(Analyzer().Analyze("myhome.duckdns.org"), e => e.Text.Contains("Dynamic DNS"));
    }

    [Fact]
    public void Dns_tunnelling_pattern_is_detected()
    {
        var a = new DnsBehaviorAnalyzer(_ => false);
        var t = DateTimeOffset.UtcNow;
        var rnd = new Random(3);
        for (int i = 0; i < 40; i++)
        {
            var label = new string(Enumerable.Range(0, 32).Select(_ => (char)('a' + rnd.Next(26))).ToArray());
            a.Record(new DnsObservation { Timestamp = t.AddSeconds(i), Query = $"{label}.tunnel.example.org", RecordType = "TXT" });
        }
        var ev = a.Evaluate("zzz.tunnel.example.org");
        Assert.Contains(ev, e => e.Text.Contains("tunnelling"));
        Assert.Contains(ev, e => e.Text.Contains("TXT"));
    }

    [Fact]
    public void Normal_dns_has_no_behaviour_evidence()
    {
        var a = new DnsBehaviorAnalyzer(_ => false);
        var t = DateTimeOffset.UtcNow;
        foreach (var n in new[] { "www.example.com", "mail.example.com", "www.example.com" })
            a.Record(new DnsObservation { Timestamp = t, Query = n, ResolvedAddresses = new[] { System.Net.IPAddress.Parse("93.184.216.34") } });
        Assert.Empty(a.Evaluate("www.example.com"));
        Assert.Null(a.NxDomainBurst());
    }

    [Fact]
    public void Nxdomain_burst_indicates_dga()
    {
        var a = new DnsBehaviorAnalyzer(_ => false);
        var t = DateTimeOffset.UtcNow;
        for (int i = 0; i < 30; i++) a.Record(new DnsObservation { Timestamp = t, Query = $"x{i}qz{i * 7}k.com", Status = 9003 });
        Assert.NotNull(a.NxDomainBurst());
    }
}

public class ProcessHeuristicTests
{
    private static ProcessInfo P(string name, string path, SignatureStatus sig = SignatureStatus.Signed, string? parent = null) =>
        new() { Pid = 100, Name = name, Path = path, Signature = new SignatureInfo(sig, "Microsoft Windows"), ParentName = parent };

    [Fact]
    public void Masquerading_system_binary_is_flagged()
    {
        var ev = ProcessHeuristics.Analyze(P("svchost.exe", @"C:\Users\Bob\AppData\Roaming\svchost.exe", SignatureStatus.Unsigned), DateTimeOffset.Now, true);
        Assert.Contains(ev, e => e.Text.Contains("masquerading"));
        Assert.Contains(ev, e => e.Text.Contains("Unsigned"));
    }

    [Fact]
    public void Genuine_svchost_is_clean()
    {
        var ev = ProcessHeuristics.Analyze(P("svchost.exe", @"C:\Windows\System32\svchost.exe", SignatureStatus.CatalogSigned, "services.exe"), DateTimeOffset.Now, true);
        Assert.Empty(ev);
    }

    [Fact]
    public void Office_spawning_powershell_and_temp_paths_are_flagged()
    {
        var ev = ProcessHeuristics.Analyze(P("powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", parent: "WINWORD.EXE"), DateTimeOffset.Now, true);
        Assert.Contains(ev, e => e.Text.Contains("Office"));
        Assert.Contains(ev, e => e.Text.Contains("living-off-the-land"));
        var ev2 = ProcessHeuristics.Analyze(P("x.exe", @"C:\Users\Bob\AppData\Local\Temp\x.exe", SignatureStatus.Unsigned), DateTimeOffset.Now, true);
        Assert.Contains(ev2, e => e.Text.Contains("temporary"));
    }

    [Fact]
    public void Unknown_process_produces_no_fabricated_evidence()
    {
        Assert.Empty(ProcessHeuristics.Analyze(ProcessInfo.Unknown, DateTimeOffset.Now, true));
    }

    [Fact]
    public void Port_heuristics()
    {
        Assert.Null(PortHeuristics.Evaluate(443, Direction.Outbound));
        Assert.Contains("Metasploit", PortHeuristics.Evaluate(4444, Direction.Outbound)!.Text);
        Assert.Contains("Unusual", PortHeuristics.Evaluate(8765, Direction.Outbound)!.Text);
    }
}

public class BaselineTests
{
    [Fact]
    public void Learns_destinations_and_reports_novelty_without_whitelisting()
    {
        var t = DateTimeOffset.UtcNow;
        var b = new Baseline(null, t.AddDays(-2), TimeSpan.FromHours(24));
        var v1 = b.Observe("powershell.exe", "n:1.2.3.0/24", t);
        Assert.True(v1.FirstExternalForProcess);
        Assert.True(v1.NewDestinationForMachine);
        Assert.False(v1.Learning);
        var v2 = b.Observe("powershell.exe", "n:1.2.3.0/24", t);
        Assert.False(v2.NewDestinationForProcess);
        var v3 = b.Observe("chrome.exe", "n:1.2.3.0/24", t);
        Assert.True(v3.NewDestinationForProcess);
        Assert.False(v3.NewDestinationForMachine);
    }
}
