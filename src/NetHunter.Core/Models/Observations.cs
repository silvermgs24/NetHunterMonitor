using System.Net;

namespace NetHunter.Core.Models;

/// <summary>Raw fact reported by a collector. Never fabricated: Pid is null when the source cannot attribute it.</summary>
public sealed record ConnectionObservation
{
    public required DateTimeOffset Timestamp { get; init; }
    public required TransportProtocol Protocol { get; init; }
    public Direction Direction { get; init; }
    public required IPAddress LocalAddress { get; init; }
    public required int LocalPort { get; init; }
    public required IPAddress RemoteAddress { get; init; }
    public required int RemotePort { get; init; }
    public int? Pid { get; init; }
    public string State { get; init; } = "";
    public ObservationKind Kind { get; init; } = ObservationKind.Opened;
    /// <summary>Collector name: "IPHelper", "ETW", "PCAP", "SYNTHETIC".</summary>
    public string Source { get; init; } = "";
    public bool IsSynthetic { get; init; }
    /// <summary>TLS SNI or HTTP Host seen in the payload (PCAP only; live monitoring does not inspect packets).</summary>
    public string? Sni { get; init; }

    public string TupleKey => $"{(int)Protocol}|{LocalAddress}|{LocalPort}|{RemoteAddress}|{RemotePort}";
}

public sealed record DnsObservation
{
    public required DateTimeOffset Timestamp { get; init; }
    public required string Query { get; init; }
    public string RecordType { get; init; } = "A";
    public int? Pid { get; init; }
    public string? ProcessName { get; init; }
    /// <summary>0 = success; otherwise a DNS/Win32 status (e.g. 9003 = name does not exist).</summary>
    public int Status { get; init; }
    public IReadOnlyList<string> Answers { get; init; } = Array.Empty<string>();
    public IReadOnlyList<IPAddress> ResolvedAddresses { get; init; } = Array.Empty<IPAddress>();
    public int? Ttl { get; init; }
    /// <summary>"ETW-DNS", "DNS-CACHE", "PCAP", "SYNTHETIC".</summary>
    public string Source { get; init; } = "";
    public bool IsSynthetic { get; init; }

    public bool IsFailure => Status != 0;
}

public sealed record ListeningEndpoint
{
    public required TransportProtocol Protocol { get; init; }
    public required IPAddress LocalAddress { get; init; }
    public required int Port { get; init; }
    public int? Pid { get; init; }
}
