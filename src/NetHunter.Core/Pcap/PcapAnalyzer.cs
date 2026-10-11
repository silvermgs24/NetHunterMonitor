using System.Net;
using NetHunter.Core.Intel;
using NetHunter.Core.Models;
using NetHunter.Core.Util;

namespace NetHunter.Core.Pcap;

public sealed class PcapSummary
{
    public string File { get; set; } = "";
    public long Packets { get; set; }
    public long Decoded { get; set; }
    public DateTimeOffset? Start { get; set; }
    public DateTimeOffset? End { get; set; }
    public int Connections { get; set; }
    public int DnsMessages { get; set; }
    public int TlsSni { get; set; }
    public int HttpRequests { get; set; }
    public List<string> UrlIocMatches { get; } = new();
    public List<string> Warnings { get; } = new();
}

/// <summary>
/// Turns a capture into the same observations the live collectors produce (connections, DNS, SNI), so the
/// identical detection pipeline runs on it. Process attribution is impossible from packets: Process = Unknown.
/// </summary>
public static class PcapAnalyzer
{
    private sealed class FlowState
    {
        public bool SynAckSeen;
        public bool Reported;
        public DateTimeOffset Start;
        public required ConnectionObservation Obs;
    }

    public static PcapSummary Analyze(string path, Action<object> sink, LocalIocDatabase? urlIocs = null, CancellationToken ct = default)
    {
        using var fs = File.OpenRead(path);
        return Analyze(fs, Path.GetFileName(path), sink, urlIocs, ct);
    }

    public static PcapSummary Analyze(Stream stream, string name, Action<object> sink, LocalIocDatabase? urlIocs = null, CancellationToken ct = default)
    {
        var summary = new PcapSummary { File = name };
        var tcp = new Dictionary<string, FlowState>();
        var udp = new HashSet<string>();
        var sniDone = new HashSet<string>();
        var dnsQueries = new Dictionary<int, (DateTimeOffset T, string Q, int Type)>();

        try
        {
            foreach (var raw in PcapReader.Read(stream))
            {
                ct.ThrowIfCancellationRequested();
                summary.Packets++;
                var p = PacketDecoder.Decode(raw);
                if (p is null) continue;
                summary.Decoded++;
                summary.Start ??= p.Timestamp;
                summary.End = p.Timestamp;

                // DNS (UDP/53, and TCP/53 with length prefix)
                if (p.SrcPort == 53 || p.DstPort == 53)
                {
                    var payload = p.Payload.Span;
                    if (p.Protocol == TransportProtocol.Tcp && payload.Length > 2) payload = payload[2..];
                    var msg = DnsMessageParser.Parse(payload);
                    if (msg is not null)
                    {
                        summary.DnsMessages++;
                        if (!msg.IsResponse && msg.QuestionName is not null) dnsQueries[msg.Id] = (p.Timestamp, msg.QuestionName, msg.QuestionType);
                        else if (msg.IsResponse && msg.QuestionName is not null)
                        {
                            var addrs = msg.Answers.Where(a => a.Address is not null).Select(a => a.Address!).ToList();
                            sink(new DnsObservation
                            {
                                Timestamp = p.Timestamp, Query = msg.QuestionName, RecordType = DnsMessageParser.TypeName(msg.QuestionType),
                                Status = msg.RCode, Answers = msg.Answers.Select(a => $"{DnsMessageParser.TypeName(a.Type)} {a.Data}").ToList(),
                                ResolvedAddresses = addrs, Ttl = msg.Answers.Count > 0 ? msg.Answers.Min(a => a.Ttl) : null, Source = "PCAP",
                            });
                            dnsQueries.Remove(msg.Id);
                        }
                    }
                    if (p.Protocol == TransportProtocol.Udp) continue;
                }

                if (p.Protocol == TransportProtocol.Tcp)
                {
                    if (p.Syn && !p.Ack)
                    {
                        var key = Key(p.Src, p.SrcPort, p.Dst, p.DstPort);
                        if (!tcp.ContainsKey(key))
                        {
                            tcp[key] = new FlowState { Start = p.Timestamp, Obs = MakeObs(p.Timestamp, TransportProtocol.Tcp, p.Src, p.SrcPort, p.Dst, p.DstPort, "SYN_SENT") };
                            summary.Connections++;
                        }
                        continue;
                    }
                    var fwd = Key(p.Src, p.SrcPort, p.Dst, p.DstPort);
                    var rev = Key(p.Dst, p.DstPort, p.Src, p.SrcPort);
                    if (p.Syn && p.Ack && tcp.TryGetValue(rev, out var st))
                    {
                        st.SynAckSeen = true;
                        if (!st.Reported) { sink(st.Obs with { State = "ESTABLISHED" }); st.Reported = true; }
                        continue;
                    }
                    if (tcp.TryGetValue(fwd, out var cs) && p.Payload.Length > 0)
                    {
                        var payload = p.Payload.Span;
                        if (!sniDone.Contains(fwd))
                        {
                            if (TlsSniParser.TryGetSni(payload) is { } sni)
                            {
                                summary.TlsSni++;
                                sniDone.Add(fwd);
                                sink(cs.Obs with { State = "ESTABLISHED", Sni = sni, Kind = ObservationKind.StateChanged });
                            }
                            else if (HttpRequestParser.TryParse(payload) is { } http)
                            {
                                summary.HttpRequests++;
                                sniDone.Add(fwd);
                                var url = $"http://{http.Host}{http.Path}";
                                if (urlIocs?.MatchUrl(url) is { } m) summary.UrlIocMatches.Add($"{url} matched {m.ListName}");
                                sink(cs.Obs with { State = "ESTABLISHED", Sni = http.Host, Kind = ObservationKind.StateChanged });
                            }
                        }
                    }
                }
                else if (p.Protocol == TransportProtocol.Udp)
                {
                    var fwd = Key(p.Src, p.SrcPort, p.Dst, p.DstPort);
                    var rev = Key(p.Dst, p.DstPort, p.Src, p.SrcPort);
                    if (udp.Contains(fwd) || udp.Contains(rev)) continue;
                    if (IpUtil.Classify(p.Dst) == IpScope.Multicast) continue;
                    udp.Add(fwd);
                    summary.Connections++;
                    sink(MakeObs(p.Timestamp, TransportProtocol.Udp, p.Src, p.SrcPort, p.Dst, p.DstPort, ""));
                }
            }
        }
        catch (InvalidDataException ex)
        {
            summary.Warnings.Add("Capture parsing stopped: " + ex.Message);
        }

        // TCP attempts that never got a SYN-ACK are reported as failed connection attempts.
        foreach (var st in tcp.Values.Where(s => !s.Reported))
        {
            sink(st.Obs);
            sink(st.Obs with { Kind = ObservationKind.Closed, State = "SYN_SENT", Timestamp = st.Start.AddSeconds(1) });
        }
        if (summary.Decoded == 0) summary.Warnings.Add("No IPv4/IPv6 TCP/UDP packets could be decoded (unsupported link type?)");
        return summary;
    }

    private static string Key(IPAddress a, int ap, IPAddress b, int bp) => $"{a}|{ap}|{b}|{bp}";

    /// <summary>Orients the observation: the "remote" side is the external party where that can be determined.</summary>
    private static ConnectionObservation MakeObs(DateTimeOffset t, TransportProtocol proto, IPAddress initiator, int iport, IPAddress responder, int rport, string state)
    {
        bool inbound = IpUtil.IsExternal(initiator) && !IpUtil.IsExternal(responder);
        return new ConnectionObservation
        {
            Timestamp = t, Protocol = proto, Direction = inbound ? Direction.Inbound : Direction.Outbound,
            LocalAddress = inbound ? responder : initiator, LocalPort = inbound ? rport : iport,
            RemoteAddress = inbound ? initiator : responder, RemotePort = inbound ? iport : rport,
            Pid = null, State = state, Source = "PCAP",
        };
    }
}
