namespace NetHunter.Core.Models;

public sealed record SignatureInfo(SignatureStatus Status, string? Signer)
{
    public static readonly SignatureInfo Unknown = new(SignatureStatus.Unknown, null);
    public static readonly SignatureInfo NotChecked = new(SignatureStatus.NotChecked, null);

    public bool IsTrusted => Status is SignatureStatus.Signed or SignatureStatus.CatalogSigned;
    public bool IsMicrosoft => IsTrusted && Signer is not null && Signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);

    public override string ToString() => Status switch
    {
        SignatureStatus.Signed => $"Signed: {Signer ?? "unknown signer"}",
        SignatureStatus.CatalogSigned => $"Catalog-signed: {Signer ?? "Windows catalog"}",
        SignatureStatus.Unsigned => "Unsigned",
        SignatureStatus.Invalid => "INVALID signature",
        SignatureStatus.NotChecked => "Not checked",
        _ => "Unknown",
    };
}

/// <summary>Everything we know about the process behind a connection. Unknown fields stay null and are never guessed.</summary>
public sealed record ProcessInfo
{
    public static readonly ProcessInfo Unknown = new() { Pid = null, Name = "Unknown" };

    public int? Pid { get; init; }
    public string Name { get; init; } = "Unknown";
    public string? Path { get; init; }
    public string? Sha256 { get; init; }
    public int? ParentPid { get; init; }
    public string? ParentName { get; init; }
    public DateTimeOffset? StartTime { get; init; }
    public SignatureInfo Signature { get; init; } = SignatureInfo.NotChecked;
    /// <summary>Why a field is missing (e.g. "Access denied: run as administrator for full detail").</summary>
    public string? AttributionNote { get; init; }
    public bool IsSynthetic { get; init; }

    public bool IsKnown => Pid is not null && Name != "Unknown";

    /// <summary>Stable identity across PIDs: full path when known, else name.</summary>
    public string Key => (Path ?? Name).ToLowerInvariant();
}
