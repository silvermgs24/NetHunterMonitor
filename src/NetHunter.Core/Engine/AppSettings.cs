using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetHunter.Core.Engine;

/// <summary>Encrypts secrets at rest (DPAPI on Windows). Keys are never written to disk in plain text.</summary>
public interface ISecretProtector
{
    string Protect(string plain);
    string? Unprotect(string protectedValue);
}

/// <summary>For tests only.</summary>
public sealed class PassthroughProtector : ISecretProtector
{
    public string Protect(string plain) => plain;
    public string? Unprotect(string protectedValue) => protectedValue;
}

public sealed class ProviderSettings
{
    public bool Enabled { get; set; }
    /// <summary>DPAPI-protected API key (base64). Use <see cref="AppSettings.GetApiKey"/>.</summary>
    public string? ProtectedApiKey { get; set; }
    public int RequestsPerMinute { get; set; }
    public int RequestsPerDay { get; set; }
}

public sealed class AppSettings
{
    public const int CurrentVersion = 1;
    public int Version { get; set; } = CurrentVersion;

    // Monitoring
    public int PollIntervalMs { get; set; } = 1000;
    public int DnsCachePollSeconds { get; set; } = 5;
    /// <summary>Use ETW kernel/DNS tracing when running elevated (captures short-lived connections, UDP peers, DNS with PID).</summary>
    public bool UseEtwWhenElevated { get; set; } = true;
    public bool IncludeLoopback { get; set; }
    public bool IncludeLanTraffic { get; set; } = true;
    public bool ResolvePtr { get; set; } = true;
    public bool HashExecutables { get; set; } = true;
    public bool VerifySignatures { get; set; } = true;

    // Retention: 0 = unlimited
    public int RetentionHours { get; set; } = 24 * 7;

    // Notifications
    public bool NotificationsEnabled { get; set; } = true;
    public string MinimumNotificationLevel { get; set; } = "High";
    /// <summary>Lowest severity that creates an alert record. "Low" also alerts on first-seen/unknown destinations.</summary>
    public string MinimumAlertLevel { get; set; } = "Medium";

    // Threat intelligence / privacy
    public bool ThreatIntelEnabled { get; set; } = true;
    public int ReputationCacheHours { get; set; } = 24;
    public bool LookupFileHashes { get; set; } = true;
    public bool LookupDomains { get; set; } = true;
    public ProviderSettings AbuseIpDb { get; set; } = new() { Enabled = false, RequestsPerMinute = 30, RequestsPerDay = 1000 };
    public ProviderSettings VirusTotal { get; set; } = new() { Enabled = false, RequestsPerMinute = 4, RequestsPerDay = 500 };

    // Detection tuning
    public int BaselineLearningHours { get; set; } = 24;
    public List<string> SuspiciousTlds { get; set; } = new()
    {
        "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "rest", "cam", "monster",
        "su", "icu", "buzz", "cyou", "quest", "sbs", "lol", "bond", "beauty", "hair", "uno", "pw", "cc", "ru.com",
    };
    /// <summary>Suffixes of large CDNs/clouds whose hostnames routinely look random. Lowers domain-randomness weight; never whitelists.</summary>
    public List<string> CdnSuffixes { get; set; } = new()
    {
        "akamaiedge.net", "akamai.net", "akamaitechnologies.com", "akadns.net", "edgekey.net", "edgesuite.net",
        "cloudfront.net", "amazonaws.com", "awsglobalaccelerator.com", "fastly.net", "fastlylb.net",
        "cloudflare.com", "cloudflare.net", "googleusercontent.com", "googlevideo.com", "gvt1.com", "gvt2.com", "1e100.net",
        "azureedge.net", "azurefd.net", "trafficmanager.net", "msedge.net", "windows.net", "msn.com", "live.com",
        "office.net", "office.com", "microsoft.com", "windowsupdate.com", "footprintdns.com", "aria.microsoft.com",
        "facebook.com", "fbcdn.net", "edgecastcdn.net", "llnwd.net", "cdn77.org", "b-cdn.net",
    };

    [JsonIgnore] public ISecretProtector? Protector { get; set; }

    public string? GetApiKey(ProviderSettings p) =>
        string.IsNullOrEmpty(p.ProtectedApiKey) ? null : Protector?.Unprotect(p.ProtectedApiKey);

    public void SetApiKey(ProviderSettings p, string? key) =>
        p.ProtectedApiKey = string.IsNullOrWhiteSpace(key) ? null : (Protector ?? throw new InvalidOperationException("No secret protector")).Protect(key.Trim());

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static AppSettings Load(string path, ISecretProtector protector)
    {
        AppSettings s;
        try
        {
            s = File.Exists(path) ? JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path), Json) ?? new() : new();
        }
        catch (JsonException)
        {
            // Corrupt config: keep a copy for inspection and start from defaults rather than refusing to run.
            File.Copy(path, path + ".corrupt", overwrite: true);
            s = new();
        }
        s.Protector = protector;
        s.Sanitize();
        return s;
    }

    public void Save(string path)
    {
        Sanitize();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
        File.Move(tmp, path, overwrite: true);
    }

    public void Sanitize()
    {
        SuspiciousTlds ??= new();
        CdnSuffixes ??= new();
        AbuseIpDb ??= new() { RequestsPerMinute = 30, RequestsPerDay = 1000 };
        VirusTotal ??= new() { RequestsPerMinute = 4, RequestsPerDay = 500 };
        PollIntervalMs = Math.Clamp(PollIntervalMs, 250, 10_000);
        DnsCachePollSeconds = Math.Clamp(DnsCachePollSeconds, 2, 300);
        RetentionHours = Math.Max(0, RetentionHours);
        ReputationCacheHours = Math.Clamp(ReputationCacheHours, 1, 24 * 30);
        BaselineLearningHours = Math.Clamp(BaselineLearningHours, 0, 24 * 30);
        AbuseIpDb.RequestsPerMinute = Math.Clamp(AbuseIpDb.RequestsPerMinute, 1, 1000);
        AbuseIpDb.RequestsPerDay = Math.Clamp(AbuseIpDb.RequestsPerDay, 1, 1_000_000);
        VirusTotal.RequestsPerMinute = Math.Clamp(VirusTotal.RequestsPerMinute, 1, 1000);
        VirusTotal.RequestsPerDay = Math.Clamp(VirusTotal.RequestsPerDay, 1, 1_000_000);
        if (!Enum.TryParse<Models.RiskLevel>(MinimumNotificationLevel, out _)) MinimumNotificationLevel = "High";
        if (!Enum.TryParse<Models.RiskLevel>(MinimumAlertLevel, out _)) MinimumAlertLevel = "Medium";
    }

    public static readonly (string Label, int Hours)[] RetentionChoices =
    {
        ("1 hour", 1), ("6 hours", 6), ("24 hours", 24), ("7 days", 24 * 7), ("30 days", 24 * 30), ("Unlimited", 0),
    };
}
