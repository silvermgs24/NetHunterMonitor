using System.Net;
using NetHunter.Core.Intel;
using NetHunter.Core.Models;

namespace NetHunter.Core.Tests;

public class AbuseIpDbParsingTests
{
    private const string Sample = """
        {"data":{"ipAddress":"185.220.101.1","isPublic":true,"ipVersion":4,"isWhitelisted":false,"abuseConfidenceScore":92,
        "countryCode":"DE","usageType":"Data Center/Web Hosting/Transit","isp":"Example ISP","domain":"example.net","hostnames":[],
        "isTor":true,"totalReports":34,"numDistinctUsers":12,"lastReportedAt":"2026-10-10T08:15:00+00:00"}}
        """;

    [Fact]
    public void Parses_all_fields()
    {
        var r = AbuseIpDbProvider.ParseResponse("185.220.101.1", Sample);
        Assert.Equal(ReputationStatus.Ok, r.Status);
        Assert.Equal(92, r.AbuseConfidence);
        Assert.Equal(34, r.TotalReports);
        Assert.Equal(12, r.DistinctReporters);
        Assert.Equal("DE", r.CountryCode);
        Assert.Equal("Example ISP", r.Isp);
        Assert.Equal("Data Center/Web Hosting/Transit", r.UsageType);
        Assert.Equal(new DateTimeOffset(2026, 10, 10, 8, 15, 0, TimeSpan.Zero), r.LastReported);
        Assert.False(r.IsWhitelisted);
    }

    [Fact]
    public void Error_payload_maps_to_rate_limited()
    {
        var r = AbuseIpDbProvider.ParseResponse("1.2.3.4", """{"errors":[{"detail":"Daily rate limit of 1000 requests exceeded","status":429}]}""");
        Assert.Equal(ReputationStatus.RateLimited, r.Status);
        Assert.Contains("rate limit", r.Detail);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("""{"data":{"abuseConfidenceScore":"high"}}""")]
    [InlineData("""{"data":[]}""")]
    public void Malformed_or_incomplete_json_is_an_error_not_an_exception(string json)
    {
        var r = AbuseIpDbProvider.ParseResponse("1.2.3.4", json);
        Assert.Equal(ReputationStatus.Error, r.Status);
    }

    [Fact]
    public void Out_of_range_values_are_clamped_and_control_chars_stripped()
    {
        var r = AbuseIpDbProvider.ParseResponse("1.2.3.4", """{"data":{"ipAddress":"1.2.3.4","abuseConfidenceScore":250,"isp":"Evil\u0007\nISP"}}""");
        Assert.Equal(100, r.AbuseConfidence);
        Assert.Equal("EvilISP", r.Isp);
    }

    [Fact]
    public void Response_for_a_different_ip_is_rejected()
    {
        var r = AbuseIpDbProvider.ParseResponse("1.2.3.4", """{"data":{"ipAddress":"5.6.7.8","abuseConfidenceScore":99}}""");
        Assert.Equal(ReputationStatus.Error, r.Status);
    }
}

public class VirusTotalParsingTests
{
    [Fact]
    public void Parses_file_report()
    {
        var json = """
            {"data":{"id":"abc","type":"file","attributes":{"meaningful_name":"evil.exe","reputation":-12,
            "last_analysis_stats":{"harmless":0,"type-unsupported":4,"suspicious":1,"confirmed-timeout":0,"timeout":0,"failure":0,"malicious":12,"undetected":55}}}}
            """;
        var r = VirusTotalProvider.ParseResponse(IocType.Sha256, new string('a', 64), json);
        Assert.Equal(ReputationStatus.Ok, r.Status);
        Assert.Equal(12, r.Malicious);
        Assert.Equal(1, r.Suspicious);
        Assert.Equal(72, r.TotalEngines);
        Assert.Equal(-12, r.CommunityReputation);
        Assert.Equal("evil.exe", r.Detail);
    }

    [Fact]
    public void Parses_ip_report()
    {
        var json = """{"data":{"attributes":{"country":"NL","as_owner":"Hosting BV","last_analysis_stats":{"harmless":60,"malicious":8,"suspicious":2,"undetected":25,"timeout":0}}}}""";
        var r = VirusTotalProvider.ParseResponse(IocType.Ip, "185.1.1.1", json);
        Assert.Equal(8, r.Malicious);
        Assert.Equal(95, r.TotalEngines);
        Assert.Equal("NL", r.CountryCode);
        Assert.Equal("Hosting BV", r.Isp);
    }

    [Fact]
    public void Not_found_error_maps_to_not_found()
    {
        var r = VirusTotalProvider.ParseResponse(IocType.Sha256, new string('b', 64), """{"error":{"code":"NotFoundError","message":"File not found"}}""");
        Assert.Equal(ReputationStatus.NotFound, r.Status);
    }

    [Fact]
    public void Quota_error_maps_to_rate_limited()
    {
        var r = VirusTotalProvider.ParseResponse(IocType.Ip, "1.1.1.1", """{"error":{"code":"QuotaExceededError","message":"Quota exceeded"}}""");
        Assert.Equal(ReputationStatus.RateLimited, r.Status);
    }

    [Fact]
    public void Missing_stats_is_error()
    {
        var r = VirusTotalProvider.ParseResponse(IocType.Domain, "example.com", """{"data":{"attributes":{}}}""");
        Assert.Equal(ReputationStatus.Error, r.Status);
    }
}

/// <summary>HTTP behaviour of providers using a fake handler: TLS-only URIs, failures, rate limits.</summary>
public class ProviderHttpTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
        public int Calls;
        public HttpRequestMessage? Last;
        public FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) { _respond = respond; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            Last = request;
            return Task.FromResult(_respond(request));
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string body) =>
        new(code) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };

    [Fact]
    public async Task AbuseIpDb_sends_key_header_over_https()
    {
        var h = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":0,"totalReports":0}}"""));
        var p = new AbuseIpDbProvider(new HttpClient(h), () => "KEY123", () => true, new RateLimiter(10, 100));
        var r = await p.LookupAsync(IocType.Ip, "8.8.8.8", default);
        Assert.Equal(ReputationStatus.Ok, r.Status);
        Assert.Equal("https", h.Last!.RequestUri!.Scheme);
        Assert.Equal("KEY123", h.Last.Headers.GetValues("Key").Single());
        Assert.Contains("ipAddress=8.8.8.8", h.Last.RequestUri.Query);
    }

    [Fact]
    public async Task Http_429_blocks_the_limiter()
    {
        var h = new FakeHandler(_ =>
        {
            var m = Json(HttpStatusCode.TooManyRequests, "{}");
            m.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromMinutes(2));
            return m;
        });
        var limiter = new RateLimiter(100, 1000);
        var p = new VirusTotalProvider(new HttpClient(h), () => "k", () => true, limiter);
        var r = await p.LookupAsync(IocType.Ip, "8.8.8.8", default);
        Assert.Equal(ReputationStatus.RateLimited, r.Status);
        Assert.False(limiter.TryAcquire(DateTimeOffset.UtcNow, out var retry));
        Assert.True(retry > DateTimeOffset.UtcNow.AddSeconds(100));
    }

    [Fact]
    public async Task Unauthorized_is_reported_as_bad_key()
    {
        var h = new FakeHandler(_ => Json(HttpStatusCode.Unauthorized, """{"error":{"code":"WrongCredentialsError"}}"""));
        var p = new VirusTotalProvider(new HttpClient(h), () => "bad", () => true, new RateLimiter(10, 10));
        var r = await p.LookupAsync(IocType.Domain, "example.com", default);
        Assert.Equal(ReputationStatus.Error, r.Status);
        Assert.Contains("rejected", r.Detail);
    }

    [Fact]
    public async Task Network_failure_is_offline_not_exception()
    {
        var h = new FakeHandler(_ => throw new HttpRequestException("no route to host"));
        var p = new AbuseIpDbProvider(new HttpClient(h), () => "k", () => true, new RateLimiter(10, 10));
        var r = await p.LookupAsync(IocType.Ip, "8.8.4.4", default);
        Assert.Equal(ReputationStatus.Offline, r.Status);
    }

    [Fact]
    public async Task Disabled_or_keyless_provider_never_calls_network()
    {
        var h = new FakeHandler(_ => Json(HttpStatusCode.OK, "{}"));
        var p1 = new AbuseIpDbProvider(new HttpClient(h), () => null, () => true, new RateLimiter(10, 10));
        var p2 = new AbuseIpDbProvider(new HttpClient(h), () => "k", () => false, new RateLimiter(10, 10));
        Assert.Equal(ReputationStatus.Disabled, (await p1.LookupAsync(IocType.Ip, "8.8.8.8", default)).Status);
        Assert.Equal(ReputationStatus.Disabled, (await p2.LookupAsync(IocType.Ip, "8.8.8.8", default)).Status);
        Assert.Equal(0, h.Calls);
    }

    [Fact]
    public async Task Service_uses_cache_and_never_sends_private_addresses()
    {
        var h = new FakeHandler(_ => Json(HttpStatusCode.OK, """{"data":{"ipAddress":"9.9.9.9","abuseConfidenceScore":5}}"""));
        var p = new AbuseIpDbProvider(new HttpClient(h), () => "k", () => true, new RateLimiter(100, 1000));
        var cache = new ReputationCache(TimeSpan.FromHours(1));
        await using var svc = new ReputationService(new LocalIocDatabase(), new IRemoteReputationProvider[] { p }, cache);
        var got = new TaskCompletionSource<ReputationResult>();
        svc.ResultAvailable += r => got.TrySetResult(r);
        svc.Start();
        svc.Enqueue(IocType.Ip, "192.168.1.10", 10);  // private: must be ignored
        svc.Enqueue(IocType.Ip, "127.0.0.1", 10);     // loopback: must be ignored
        svc.Enqueue(IocType.Ip, "9.9.9.9", 10);
        var result = await got.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(5, result.AbuseConfidence);
        svc.Enqueue(IocType.Ip, "9.9.9.9", 10);       // cached: no second call
        await Task.Delay(300);
        Assert.Equal(1, h.Calls);
        Assert.True(cache.TryGet(AbuseIpDbProvider.ProviderName, IocType.Ip, "9.9.9.9", out _));
    }

    [Fact]
    public async Task Service_reports_offline_after_repeated_network_failures()
    {
        var h = new FakeHandler(_ => throw new HttpRequestException("offline"));
        var p = new AbuseIpDbProvider(new HttpClient(h), () => "k", () => true, new RateLimiter(100, 1000));
        await using var svc = new ReputationService(new LocalIocDatabase(), new IRemoteReputationProvider[] { p }, new ReputationCache(TimeSpan.FromHours(1)));
        var failure = new TaskCompletionSource();
        svc.ResultAvailable += _ => failure.TrySetResult();
        svc.Start();
        Assert.Equal(IntelStatus.Online, svc.Status);
        svc.Enqueue(IocType.Ip, "9.9.9.9", 10);
        svc.Enqueue(IocType.Ip, "8.8.8.8", 5);
        await failure.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(IntelStatus.Offline, svc.Status);
        Assert.Contains("unavailable", svc.StatusText);
    }
}

public class CacheAndLimiterTests
{
    [Fact]
    public void Cache_entries_expire()
    {
        var now = DateTimeOffset.UtcNow;
        var cache = new ReputationCache(TimeSpan.FromHours(1), clock: () => now);
        cache.Put(new ReputationResult { Provider = "X", Type = IocType.Ip, Value = "1.1.1.1", Status = ReputationStatus.Ok, AbuseConfidence = 1 });
        Assert.True(cache.TryGet("X", IocType.Ip, "1.1.1.1", out _));
        now = now.AddMinutes(61);
        Assert.False(cache.TryGet("X", IocType.Ip, "1.1.1.1", out _));
    }

    [Fact]
    public void Transient_failures_are_not_cached_errors_only_briefly()
    {
        var now = DateTimeOffset.UtcNow;
        var cache = new ReputationCache(TimeSpan.FromHours(24), clock: () => now);
        cache.Put(new ReputationResult { Provider = "X", Type = IocType.Ip, Value = "1.1.1.1", Status = ReputationStatus.Offline });
        cache.Put(new ReputationResult { Provider = "X", Type = IocType.Ip, Value = "2.2.2.2", Status = ReputationStatus.RateLimited });
        cache.Put(new ReputationResult { Provider = "X", Type = IocType.Ip, Value = "3.3.3.3", Status = ReputationStatus.Error });
        Assert.False(cache.TryGet("X", IocType.Ip, "1.1.1.1", out _));
        Assert.False(cache.TryGet("X", IocType.Ip, "2.2.2.2", out _));
        Assert.True(cache.TryGet("X", IocType.Ip, "3.3.3.3", out _));
        now = now.AddMinutes(16);
        Assert.False(cache.TryGet("X", IocType.Ip, "3.3.3.3", out _));
    }

    [Fact]
    public void Limiter_enforces_per_minute_and_per_day()
    {
        var l = new RateLimiter(perMinute: 4, perDay: 6);
        var t = DateTimeOffset.UtcNow;
        for (int i = 0; i < 4; i++) Assert.True(l.TryAcquire(t, out _));
        Assert.False(l.TryAcquire(t, out var retry));
        Assert.Equal(t.AddMinutes(1), retry);
        t = t.AddMinutes(1);
        Assert.True(l.TryAcquire(t, out _));
        Assert.True(l.TryAcquire(t, out _));
        Assert.False(l.TryAcquire(t.AddMinutes(5), out var dayRetry)); // daily budget of 6 used
        Assert.True(dayRetry > t.AddHours(23));
    }
}

public class LocalIocTests
{
    private static LocalIocDatabase Db()
    {
        var db = new LocalIocDatabase();
        db.AddLines(new[]
        {
            "# comment",
            "185.220.101.1",
            "10.66.0.0/16 internal-c2-range",
            "evil.example.com",
            "hxxp://bad[.]example/payload.exe",
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855,empty-file",
            "bad[.]org",
            "not a valid thing!!",
        }, "test.txt");
        return db;
    }

    [Fact]
    public void Matches_exact_ip_and_cidr()
    {
        var db = Db();
        Assert.NotNull(db.MatchIp(IPAddress.Parse("185.220.101.1")));
        Assert.NotNull(db.MatchIp(IPAddress.Parse("10.66.200.7")));
        Assert.Null(db.MatchIp(IPAddress.Parse("10.67.0.1")));
        Assert.NotNull(db.MatchIp(IPAddress.Parse("::ffff:185.220.101.1"))); // IPv4-mapped
    }

    [Fact]
    public void Domain_matches_self_and_subdomains_only()
    {
        var db = Db();
        Assert.NotNull(db.MatchDomain("evil.example.com"));
        Assert.NotNull(db.MatchDomain("a.b.evil.example.com."));
        Assert.Null(db.MatchDomain("example.com"));
        Assert.Null(db.MatchDomain("notevil.example.com"));
        Assert.NotNull(db.MatchDomain("www.bad.org")); // defanged entry
    }

    [Fact]
    public void Hash_and_url_matching_is_normalised()
    {
        var db = Db();
        Assert.NotNull(db.MatchHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        Assert.Equal("empty-file", db.MatchHash("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")!.Comment);
        Assert.NotNull(db.MatchUrl("http://BAD.example/payload.exe"));
        Assert.Null(db.MatchUrl("http://bad.example/other"));
    }

    [Fact]
    public void Import_counts_by_type_and_rejects_garbage()
    {
        var r = new LocalIocDatabase().AddLines(new[] { "1.2.3.4", "1.2.3.0/24", "a.com", new string('f', 64), "https://x.com/a", "???" }, "l.txt");
        Assert.Equal((1, 1, 1, 1, 1, 1), (r.Ips, r.Cidrs, r.Domains, r.Hashes, r.Urls, r.Rejected));
    }

    [Fact]
    public void Loads_and_imports_files_from_directory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nh-ioc-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllLines(Path.Combine(dir, "malicious_ips.txt"), new[] { "203.0.113.9" });
            var db = new LocalIocDatabase();
            db.LoadDirectory(dir);
            Assert.NotNull(db.MatchIp(IPAddress.Parse("203.0.113.9")));
            var src = Path.Combine(Path.GetTempPath(), "nh-domains-" + Guid.NewGuid().ToString("N") + ".txt");
            File.WriteAllLines(src, new[] { "c2.example" });
            var res = db.Import(src);
            Assert.Equal(1, res.Domains);
            Assert.NotNull(db.MatchDomain("x.c2.example"));
            Assert.NotNull(db.MatchIp(IPAddress.Parse("203.0.113.9"))); // existing list still loaded
            File.Delete(src);
        }
        finally { Directory.Delete(dir, true); }
    }
}
