namespace NetHunter.Core.Models;

/// <summary>A single attributed and enriched connection event (one row in Live Traffic).</summary>
public sealed class ConnectionEvent
{
    public long Id { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public Direction Direction { get; set; }
    public TransportProtocol Protocol { get; set; }
    public string LocalIp { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemoteIp { get; set; } = "";
    public int RemotePort { get; set; }
    public string State { get; set; } = "";
    public int? Pid { get; set; }
    public string ProcessName { get; set; } = "Unknown";
    public string? ProcessPath { get; set; }
    public string? Sha256 { get; set; }
    public string? Hostname { get; set; }
    public string? Ptr { get; set; }
    public string FlowKey { get; set; } = "";
    public int Score { get; set; }
    public RiskLevel Level { get; set; }
    public string Source { get; set; } = "";
    public bool IsSynthetic { get; set; }

    public ConnectionEvent Clone() => (ConnectionEvent)MemberwiseClone();
}

/// <summary>Aggregated destination per process ("conversation"). This is what gets scored.</summary>
public sealed class FlowRecord
{
    public string Key { get; set; } = "";
    public string ProcessKey { get; set; } = "";
    public string ProcessName { get; set; } = "Unknown";
    public string? ProcessPath { get; set; }
    public int? LastPid { get; set; }
    public string? Sha256 { get; set; }
    public string RemoteIp { get; set; } = "";
    public int RemotePort { get; set; }
    public TransportProtocol Protocol { get; set; }
    public Direction Direction { get; set; }
    public string? Hostname { get; set; }
    public string? Ptr { get; set; }
    public string? Sni { get; set; }
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public long Count { get; set; }
    public int FailedCount { get; set; }
    public string LastState { get; set; } = "";
    public RiskAssessment Assessment { get; set; } = RiskAssessment.Pending;
    public bool IsSynthetic { get; set; }

    public static string MakeKey(string processKey, string remoteIp, int remotePort, TransportProtocol proto, Direction dir) =>
        $"{processKey}|{remoteIp}|{remotePort}|{(int)proto}|{(int)dir}";
}

public sealed class DnsEventRecord
{
    public long Id { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public int? Pid { get; set; }
    public string? ProcessName { get; set; }
    public string Query { get; set; } = "";
    public string RecordType { get; set; } = "";
    public int Status { get; set; }
    public string Answers { get; set; } = "";
    public string Source { get; set; } = "";
    public RiskLevel Level { get; set; }
    public string Notes { get; set; } = "";
    public bool IsSynthetic { get; set; }
}

public sealed class AlertRecord
{
    public long Id { get; set; }
    public DateTimeOffset Created { get; set; }
    public DateTimeOffset Updated { get; set; }
    public RiskLevel Severity { get; set; }
    public DetectionClass Classification { get; set; }
    public string Title { get; set; } = "";
    /// <summary>Flow key or "dns:domain" etc.; used to de-duplicate alerts.</summary>
    public string SubjectKey { get; set; } = "";
    public string ProcessName { get; set; } = "Unknown";
    public int? Pid { get; set; }
    public string? ProcessPath { get; set; }
    public string? Sha256 { get; set; }
    public string? RemoteIp { get; set; }
    public int? RemotePort { get; set; }
    public string? Hostname { get; set; }
    public int Score { get; set; }
    public int Confidence { get; set; }
    public IReadOnlyList<Evidence> Evidence { get; set; } = Array.Empty<Evidence>();
    public DateTimeOffset? FirstSeen { get; set; }
    public DateTimeOffset? LastSeen { get; set; }
    public bool Acknowledged { get; set; }
    public bool IsSynthetic { get; set; }
}

public sealed class ListeningPortRecord
{
    public TransportProtocol Protocol { get; set; }
    public string Address { get; set; } = "";
    public int Port { get; set; }
    public int? Pid { get; set; }
    public string ProcessName { get; set; } = "Unknown";
    public string? ProcessPath { get; set; }
    public RiskAssessment Assessment { get; set; } = RiskAssessment.Pending;
}

public sealed record UserMark(string Kind, string Value, UserMarkKind Mark, string? Note, DateTimeOffset Created);

/// <summary>Aggregated IOC (destination IP / domain / hash) for the IOC view.</summary>
public sealed class IocSummary
{
    public IocType Type { get; set; }
    public string Value { get; set; } = "";
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public string Processes { get; set; } = "";
    public string Reputation { get; set; } = "";
    public RiskLevel Level { get; set; }
    public int Score { get; set; }
    public long Connections { get; set; }
}
