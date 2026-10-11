using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetHunter.Core.Models;
using NetHunter.Core.Util;

namespace NetHunter.Core.Intel;

/// <summary>
/// VirusTotal API v3 lookups for IPs, domains and SHA-256 hashes. Hash lookups never upload the file;
/// <see cref="UploadFileAsync"/> is a separate, explicitly user-initiated action.
/// </summary>
public sealed partial class VirusTotalProvider : HttpReputationProvider
{
    public const string ProviderName = "VirusTotal";
    private static readonly Uri Base = new("https://www.virustotal.com/api/v3/");
    private readonly Func<string?> _key;

    public VirusTotalProvider(HttpClient http, Func<string?> apiKey, Func<bool> enabled, RateLimiter limiter)
        : base(http, apiKey, enabled, limiter) { _key = apiKey; }

    public override string Name => ProviderName;
    public override bool Supports(IocType type) => type is IocType.Ip or IocType.Domain or IocType.Sha256;

    [GeneratedRegex("^[0-9a-fA-F]{64}$")] public static partial Regex Sha256Regex();

    protected override HttpRequestMessage BuildRequest(IocType type, string value, string apiKey)
    {
        string path = type switch
        {
            IocType.Ip when IpUtil.TryParse(value, out var ip) => "ip_addresses/" + Uri.EscapeDataString(ip.ToString()),
            IocType.Domain when DomainUtil.Normalize(value) is { } d => "domains/" + Uri.EscapeDataString(d),
            IocType.Sha256 when Sha256Regex().IsMatch(value) => "files/" + value.ToLowerInvariant(),
            _ => throw new ArgumentException($"invalid {type} value", nameof(value)),
        };
        var req = new HttpRequestMessage(HttpMethod.Get, new Uri(Base, path));
        req.Headers.Add("x-apikey", apiKey);
        return req;
    }

    protected override ReputationResult Parse(IocType type, string value, string json) => ParseResponse(type, value, json);

    public static ReputationResult ParseResponse(IocType type, string value, string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 64 });
            var root = doc.RootElement;
            if (root.Prop("error") is { ValueKind: JsonValueKind.Object } err)
            {
                var code = err.Prop("code").Str(64) ?? "Error";
                var status = code switch
                {
                    "NotFoundError" => ReputationStatus.NotFound,
                    "QuotaExceededError" or "TooManyRequestsError" => ReputationStatus.RateLimited,
                    _ => ReputationStatus.Error,
                };
                return new ReputationResult { Provider = ProviderName, Type = type, Value = value, Status = status, Detail = err.Prop("message").Str(200) ?? code };
            }

            var attrs = root.Prop("data").Prop("attributes");
            if (attrs is not { ValueKind: JsonValueKind.Object } a) return Invalid(type, value, "missing data.attributes");
            var stats = a.Prop("last_analysis_stats");
            if (stats is not { ValueKind: JsonValueKind.Object })
                return Invalid(type, value, "missing last_analysis_stats");

            int mal = stats.Prop("malicious").Int() ?? 0;
            int sus = stats.Prop("suspicious").Int() ?? 0;
            int harmless = stats.Prop("harmless").Int() ?? 0;
            int undetected = stats.Prop("undetected").Int() ?? 0;
            int timeout = stats.Prop("timeout").Int() ?? 0;
            int unsupported = stats.Prop("type-unsupported").Int() ?? 0;
            int failure = stats.Prop("failure").Int() ?? 0;
            int total = mal + sus + harmless + undetected + timeout + unsupported + failure;

            return new ReputationResult
            {
                Provider = ProviderName,
                Type = type,
                Value = value,
                Status = ReputationStatus.Ok,
                Malicious = mal,
                Suspicious = sus,
                Harmless = harmless,
                Undetected = undetected,
                TotalEngines = total,
                CommunityReputation = a.Prop("reputation").Int(int.MinValue, int.MaxValue),
                CountryCode = a.Prop("country").Str(8),
                Isp = a.Prop("as_owner").Str(),
                Detail = type == IocType.Sha256 ? a.Prop("meaningful_name").Str() : null,
            };
        }
        catch (JsonException ex)
        {
            return Invalid(type, value, "malformed JSON: " + ex.Message);
        }
    }

    private static ReputationResult Invalid(IocType t, string v, string why) =>
        new() { Provider = ProviderName, Type = t, Value = v, Status = ReputationStatus.Error, Detail = why };

    /// <summary>
    /// Uploads a file to VirusTotal. PRIVACY: the file becomes available to VirusTotal and its partners.
    /// Only call after the user explicitly confirmed. Returns the analysis id or an error message.
    /// </summary>
    public async Task<(bool Ok, string Message)> UploadFileAsync(string path, CancellationToken ct)
    {
        var key = _key();
        if (string.IsNullOrWhiteSpace(key)) return (false, "No VirusTotal API key configured.");
        var fi = new FileInfo(path);
        if (!fi.Exists) return (false, "File not found.");
        if (fi.Length > 32 * 1024 * 1024) return (false, "Files over 32 MB require VirusTotal's large-file upload URL; not supported here.");
        if (!Limiter.TryAcquire(DateTimeOffset.UtcNow, out var retry)) return (false, $"Rate limit reached; retry after {retry.ToLocalTime():T}.");

        await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var content = new MultipartFormDataContent();
        var fileContent = new StreamContent(fs);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "file", fi.Name);
        using var req = new HttpRequestMessage(HttpMethod.Post, new Uri(Base, "files")) { Content = content };
        req.Headers.Add("x-apikey", key);
        try
        {
            using var resp = await Http.SendAsync(req, ct).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return (false, $"Upload failed: HTTP {(int)resp.StatusCode}");
            using var doc = JsonDocument.Parse(body);
            var id = doc.RootElement.Prop("data").Prop("id").Str(200);
            return (id is not null, id is not null ? $"Uploaded. Analysis id: {id}" : "Upload response missing analysis id.");
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException)
        {
            return (false, "Upload failed: " + ex.Message);
        }
    }
}
