using System.Net;
using System.Net.Http.Headers;
using NetHunter.Core.Models;

namespace NetHunter.Core.Intel;

/// <summary>Shared HTTP plumbing: TLS only, default certificate validation, timeouts, status mapping.</summary>
public abstract class HttpReputationProvider : IRemoteReputationProvider
{
    protected readonly HttpClient Http;
    private readonly Func<string?> _apiKey;
    private readonly Func<bool> _enabled;

    protected HttpReputationProvider(HttpClient http, Func<string?> apiKey, Func<bool> enabled, RateLimiter limiter)
    {
        Http = http;
        _apiKey = apiKey;
        _enabled = enabled;
        Limiter = limiter;
    }

    public abstract string Name { get; }
    public bool IsLocal => false;
    public bool IsEnabled => _enabled() && !string.IsNullOrWhiteSpace(_apiKey());
    public RateLimiter Limiter { get; }
    public abstract bool Supports(IocType type);

    protected abstract HttpRequestMessage BuildRequest(IocType type, string value, string apiKey);
    protected abstract ReputationResult Parse(IocType type, string value, string json);

    public async Task<ReputationResult> LookupAsync(IocType type, string value, CancellationToken ct)
    {
        var key = _apiKey();
        if (!_enabled() || string.IsNullOrWhiteSpace(key))
            return new ReputationResult { Provider = Name, Type = type, Value = value, Status = ReputationStatus.Disabled };
        if (!Supports(type))
            return new ReputationResult { Provider = Name, Type = type, Value = value, Status = ReputationStatus.Skipped };

        using var req = BuildRequest(type, value, key);
        if (req.RequestUri is null || req.RequestUri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Reputation providers must use HTTPS.");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        HttpResponseMessage resp;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            resp = await Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            return Fail(type, value, ReputationStatus.Offline, ex.HttpRequestError.ToString());
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            return Fail(type, value, ReputationStatus.Offline, "timeout");
        }

        using (resp)
        {
            if (resp.StatusCode == HttpStatusCode.TooManyRequests)
            {
                var retry = resp.Headers.RetryAfter?.Delta ?? TimeSpan.FromMinutes(1);
                Limiter.BlockUntil(DateTimeOffset.UtcNow + Clamp(retry));
                return Fail(type, value, ReputationStatus.RateLimited, "provider quota exceeded");
            }
            if (resp.StatusCode == HttpStatusCode.NotFound)
                return new ReputationResult { Provider = Name, Type = type, Value = value, Status = ReputationStatus.NotFound };
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                return Fail(type, value, ReputationStatus.Error, "API key rejected");
            if (!resp.IsSuccessStatusCode)
                return Fail(type, value, ReputationStatus.Error, $"HTTP {(int)resp.StatusCode}");

            // Bound the body size: a misbehaving endpoint must not exhaust memory.
            var len = resp.Content.Headers.ContentLength;
            if (len is > 4 * 1024 * 1024) return Fail(type, value, ReputationStatus.Error, "response too large");
            string body;
            try { body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false); }
            catch (HttpRequestException ex) { return Fail(type, value, ReputationStatus.Offline, ex.Message); }
            if (body.Length > 4 * 1024 * 1024) return Fail(type, value, ReputationStatus.Error, "response too large");
            return Parse(type, value, body);
        }
    }

    private static TimeSpan Clamp(TimeSpan t) => t < TimeSpan.FromSeconds(5) ? TimeSpan.FromSeconds(5) : t > TimeSpan.FromHours(24) ? TimeSpan.FromHours(24) : t;

    protected ReputationResult Fail(IocType type, string value, ReputationStatus status, string detail) =>
        new() { Provider = Name, Type = type, Value = value, Status = status, Detail = detail };
}
