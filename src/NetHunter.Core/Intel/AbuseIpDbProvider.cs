using System.Text.Json;
using NetHunter.Core.Models;
using NetHunter.Core.Util;

namespace NetHunter.Core.Intel;

/// <summary>AbuseIPDB v2 /check. IP addresses only. https://docs.abuseipdb.com/#check-endpoint</summary>
public sealed class AbuseIpDbProvider : HttpReputationProvider
{
    public const string ProviderName = "AbuseIPDB";
    private static readonly Uri Base = new("https://api.abuseipdb.com/api/v2/");

    public AbuseIpDbProvider(HttpClient http, Func<string?> apiKey, Func<bool> enabled, RateLimiter limiter)
        : base(http, apiKey, enabled, limiter) { }

    public override string Name => ProviderName;
    public override bool Supports(IocType type) => type == IocType.Ip;

    protected override HttpRequestMessage BuildRequest(IocType type, string value, string apiKey)
    {
        if (!IpUtil.TryParse(value, out var ip)) throw new ArgumentException("not an IP address", nameof(value));
        var req = new HttpRequestMessage(HttpMethod.Get, new Uri(Base, $"check?ipAddress={Uri.EscapeDataString(ip.ToString())}&maxAgeInDays=90"));
        req.Headers.Add("Key", apiKey);
        return req;
    }

    protected override ReputationResult Parse(IocType type, string value, string json) => ParseResponse(value, json);

    public static ReputationResult ParseResponse(string ip, string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
            var root = doc.RootElement;
            if (root.Prop("errors") is { ValueKind: JsonValueKind.Array } errs && errs.GetArrayLength() > 0)
            {
                var first = errs[0];
                var status = first.Prop("status").Int();
                return new ReputationResult
                {
                    Provider = ProviderName, Type = IocType.Ip, Value = ip,
                    Status = status == 429 ? ReputationStatus.RateLimited : ReputationStatus.Error,
                    Detail = first.Prop("detail").Str(200) ?? "API error",
                };
            }

            if (root.Prop("data") is not { ValueKind: JsonValueKind.Object } data)
                return Invalid(ip, "missing 'data' object");

            var score = data.Prop("abuseConfidenceScore").Int(0, 100);
            if (score is null) return Invalid(ip, "missing abuseConfidenceScore");

            // The response must be about the IP we asked for.
            var returnedIp = data.Prop("ipAddress").Str(64);
            if (returnedIp is not null && IpUtil.TryParse(returnedIp, out var r) && IpUtil.TryParse(ip, out var q) && !r.Equals(q))
                return Invalid(ip, "response IP mismatch");

            return new ReputationResult
            {
                Provider = ProviderName,
                Type = IocType.Ip,
                Value = ip,
                Status = ReputationStatus.Ok,
                AbuseConfidence = score,
                TotalReports = data.Prop("totalReports").Int(),
                DistinctReporters = data.Prop("numDistinctUsers").Int(),
                CountryCode = data.Prop("countryCode").Str(8),
                Isp = data.Prop("isp").Str(),
                UsageType = data.Prop("usageType").Str(),
                Domain = data.Prop("domain").Str(),
                LastReported = data.Prop("lastReportedAt").Date(),
                IsWhitelisted = data.Prop("isWhitelisted").Bool(),
            };
        }
        catch (JsonException ex)
        {
            return Invalid(ip, "malformed JSON: " + ex.Message);
        }
    }

    private static ReputationResult Invalid(string ip, string why) =>
        new() { Provider = ProviderName, Type = IocType.Ip, Value = ip, Status = ReputationStatus.Error, Detail = why };
}
