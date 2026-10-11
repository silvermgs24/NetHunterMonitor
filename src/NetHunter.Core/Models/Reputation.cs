namespace NetHunter.Core.Models;

public enum ReputationStatus { Ok = 0, NotFound = 1, Error = 2, RateLimited = 3, Disabled = 4, Offline = 5, Skipped = 6 }

/// <summary>Normalised result from any reputation provider. Fields a provider does not supply stay null.</summary>
public sealed record ReputationResult
{
    public required string Provider { get; init; }
    public required IocType Type { get; init; }
    public required string Value { get; init; }
    public ReputationStatus Status { get; init; }
    public DateTimeOffset RetrievedAt { get; init; } = DateTimeOffset.UtcNow;

    // VirusTotal-style engine verdicts
    public int? Malicious { get; init; }
    public int? Suspicious { get; init; }
    public int? Harmless { get; init; }
    public int? Undetected { get; init; }
    public int? TotalEngines { get; init; }
    public int? CommunityReputation { get; init; }

    // AbuseIPDB-style
    public int? AbuseConfidence { get; init; }
    public int? TotalReports { get; init; }
    public int? DistinctReporters { get; init; }
    public string? CountryCode { get; init; }
    public string? Isp { get; init; }
    public string? UsageType { get; init; }
    public string? Domain { get; init; }
    public DateTimeOffset? LastReported { get; init; }
    public bool? IsWhitelisted { get; init; }

    // Local list match
    public string? ListName { get; init; }

    public string? Detail { get; init; }

    public bool HasData => Status == ReputationStatus.Ok;

    public string Summary()
    {
        if (Status == ReputationStatus.NotFound) return $"{Provider}: not found / no data";
        if (Status != ReputationStatus.Ok)
            return $"{Provider}: {Status}{(Detail is null ? "" : " (" + Detail + ")")}";
        if (ListName is not null) return $"{Provider}: listed in {ListName}";
        if (AbuseConfidence is not null) return $"{Provider}: confidence {AbuseConfidence}%, {TotalReports ?? 0} reports";
        if (Malicious is not null) return $"{Provider}: {Malicious}/{TotalEngines ?? 0} malicious";
        return $"{Provider}: no data";
    }
}
