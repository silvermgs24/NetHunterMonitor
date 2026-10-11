using NetHunter.Core.Pcap;

namespace NetHunter.Core.Synthetic;

/// <summary>
/// Writes a SYNTHETIC sample capture for trying the PCAP investigation feature without real malware traffic.
/// Uses RFC 5737 documentation addresses and the reserved .example TLD only.
/// Contents: an HTTPS beacon every ~30 s (with TLS SNI and preceding DNS), a TXT-based DNS tunnelling pattern,
/// failed connection attempts to port 4444, and irregular "normal" browsing.
/// </summary>
public static class SyntheticCapture
{
    private const string Client = "192.0.2.10";
    private const string Resolver = "192.0.2.1";

    public static byte[] Build(DateTimeOffset start, TimeSpan duration, int seed = 11)
    {
        var rnd = new Random(seed);
        var frames = new List<(DateTimeOffset T, byte[] Frame)>();
        int port = 49200;
        ushort dnsId = 1;

        void Dns(DateTimeOffset t, string name, string ip, int type = 1)
        {
            var id = dnsId++;
            frames.Add((t, PcapWriter.Ethernet(PcapWriter.IPv4(Client, Resolver, 17, PcapWriter.Udp(53000 + id % 1000, 53, PcapWriter.DnsQuery(id, name, type))))));
            frames.Add((t.AddMilliseconds(15), PcapWriter.Ethernet(PcapWriter.IPv4(Resolver, Client, 17, PcapWriter.Udp(53, 53000 + id % 1000,
                ip.Length > 0 ? PcapWriter.DnsResponse(id, name, ip) : PcapWriter.DnsResponse(id, name, "", rcode: 3))))));
        }

        void Https(DateTimeOffset t, string ip, string sni, int dport = 443, bool answer = true)
        {
            int sp = port++;
            frames.Add((t, PcapWriter.Ethernet(PcapWriter.IPv4(Client, ip, 6, PcapWriter.Tcp(sp, dport, 0x02)))));
            if (!answer) return;
            frames.Add((t.AddMilliseconds(30), PcapWriter.Ethernet(PcapWriter.IPv4(ip, Client, 6, PcapWriter.Tcp(dport, sp, 0x12)))));
            frames.Add((t.AddMilliseconds(31), PcapWriter.Ethernet(PcapWriter.IPv4(Client, ip, 6, PcapWriter.Tcp(sp, dport, 0x10)))));
            frames.Add((t.AddMilliseconds(32), PcapWriter.Ethernet(PcapWriter.IPv4(Client, ip, 6, PcapWriter.Tcp(sp, dport, 0x18, PcapWriter.ClientHello(sni))))));
            frames.Add((t.AddMilliseconds(400), PcapWriter.Ethernet(PcapWriter.IPv4(Client, ip, 6, PcapWriter.Tcp(sp, dport, 0x11)))));
        }

        // Beacon: every ~30 s ±10 %, resolving its C2 name each time (short TTL).
        for (var t = start; t < start + duration; t = t.AddSeconds(30 * (1 + (rnd.NextDouble() - 0.5) * 0.2)))
        {
            Dns(t, "cdn-sync-update.example", "203.0.113.50");
            Https(t.AddMilliseconds(40), "203.0.113.50", "cdn-sync-update.example");
        }

        // Normal browsing: irregular, several destinations.
        for (var t = start.AddSeconds(5); t < start + duration; t = t.AddSeconds(rnd.Next(5, 90)))
        {
            int n = rnd.Next(10, 40);
            Dns(t, $"news{n}.example", $"198.51.100.{n}");
            Https(t.AddMilliseconds(40), $"198.51.100.{n}", $"news{n}.example");
        }

        // DNS tunnelling burst.
        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        for (int i = 0; i < 40; i++)
        {
            var label = new string(Enumerable.Range(0, 48).Select(_ => alphabet[rnd.Next(alphabet.Length)]).ToArray());
            Dns(start.AddSeconds(120 + i * 0.7), $"{label}.x.exfil-data.example", "", 16);
        }

        // Failed attempts to a Metasploit-default port.
        for (int i = 0; i < 6; i++) Https(start.AddSeconds(200 + i * 3), "203.0.113.66", "", 4444, answer: false);

        return PcapWriter.ClassicPcap(frames.OrderBy(f => f.T));
    }
}
