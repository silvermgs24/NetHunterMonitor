namespace NetHunter.Core.Models;

public enum Direction { Unknown = 0, Outbound = 1, Inbound = 2 }

public enum TransportProtocol { Tcp = 0, Udp = 1 }

/// <summary>Severity buckets. Unknown means "not yet evaluated / no data", not "safe".</summary>
public enum RiskLevel { Unknown = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

/// <summary>
/// What kind of conclusion the engine reached. These are deliberately distinct:
/// an IOC match is not the same as behaviour, and neither is "confirmed malware".
/// </summary>
public enum DetectionClass
{
    None = 0,
    /// <summary>Behavioural anomalies only (rare destination, odd port, risky path...).</summary>
    SuspiciousBehavior = 1,
    /// <summary>A threat-intel source reports the indicator (one signal among several).</summary>
    IocMatch = 2,
    /// <summary>Behaviour consistent with command-and-control (e.g. regular beaconing) plus supporting signals.</summary>
    PossibleC2 = 3,
    /// <summary>Indicator is on the analyst's own local IOC list, or strong multi-engine consensus on a file hash.</summary>
    KnownMalicious = 4,
}

public enum ObservationKind { Opened = 0, StateChanged = 1, Closed = 2 }

public enum EvidenceCategory { Reputation, LocalIoc, Beacon, Network, Process, Domain, Dns, Baseline, UserMark }

public enum IocType { Ip = 0, Domain = 1, Sha256 = 2, Url = 3 }

public enum UserMarkKind { None = 0, Trusted = 1, Ignored = 2, Suspicious = 3 }

public enum SignatureStatus { Unknown = 0, Signed = 1, CatalogSigned = 2, Unsigned = 3, Invalid = 4, NotChecked = 5 }

public static class RiskLevelExtensions
{
    public static RiskLevel FromScore(int score) => score switch
    {
        >= 85 => RiskLevel.Critical,
        >= 60 => RiskLevel.High,
        >= 35 => RiskLevel.Medium,
        _ => RiskLevel.Low,
    };

    public static string Label(this RiskLevel level) => level switch
    {
        RiskLevel.Low => "LOW",
        RiskLevel.Medium => "SUSPICIOUS",
        RiskLevel.High => "HIGH",
        RiskLevel.Critical => "CRITICAL",
        _ => "UNKNOWN",
    };

    /// <summary>Text glyph so risk is never conveyed by colour alone.</summary>
    public static string Glyph(this RiskLevel level) => level switch
    {
        RiskLevel.Low => "✓",
        RiskLevel.Medium => "⚠",
        RiskLevel.High => "▲",
        RiskLevel.Critical => "✖",
        _ => "?",
    };

    public static string Describe(this DetectionClass c) => c switch
    {
        DetectionClass.SuspiciousBehavior => "Suspicious behavior",
        DetectionClass.IocMatch => "IOC reputation match",
        DetectionClass.PossibleC2 => "Possible C2 communication",
        DetectionClass.KnownMalicious => "Known malicious indicator",
        _ => "No detection",
    };
}
