using System.Buffers.Binary;
using System.Net;
using System.Text;
using NetHunter.Core.Intel;
using NetHunter.Core.Models;
using NetHunter.Core.Pcap;
using NetHunter.Core.Util;

using PacketBuilder = NetHunter.Core.Pcap.PcapWriter;

namespace NetHunter.Core.Tests;

public class PcapTests
{
    private static readonly DateTimeOffset T = new(2026, 10, 11, 10, 0, 0, TimeSpan.Zero);

    private static List<(DateTimeOffset, byte[])> Frames() => new()
    {
        (T, PacketBuilder.Ethernet(PacketBuilder.IPv4("192.168.1.10", "8.8.8.8", 17, PacketBuilder.Udp(5353, 53, PacketBuilder.DnsQuery(0x1234, "c2.example.com"))))),
        (T.AddMilliseconds(20), PacketBuilder.Ethernet(PacketBuilder.IPv4("8.8.8.8", "192.168.1.10", 17, PacketBuilder.Udp(53, 5353, PacketBuilder.DnsResponse(0x1234, "c2.example.com", "203.0.113.5"))))),
        (T.AddMilliseconds(40), PacketBuilder.Ethernet(PacketBuilder.IPv4("192.168.1.10", "203.0.113.5", 6, PacketBuilder.Tcp(50000, 443, 0x02)))),
        (T.AddMilliseconds(60), PacketBuilder.Ethernet(PacketBuilder.IPv4("203.0.113.5", "192.168.1.10", 6, PacketBuilder.Tcp(443, 50000, 0x12)))),
        (T.AddMilliseconds(70), PacketBuilder.Ethernet(PacketBuilder.IPv4("192.168.1.10", "203.0.113.5", 6, PacketBuilder.Tcp(50000, 443, 0x18, PacketBuilder.ClientHello("c2.example.com"))))),
        (T.AddSeconds(5), PacketBuilder.Ethernet(PacketBuilder.IPv4("192.168.1.10", "198.51.100.7", 6, PacketBuilder.Tcp(50001, 4444, 0x02)))),
    };

    private static void AssertExpected(List<object> obs, PcapSummary s)
    {
        Assert.Equal(6, s.Packets);
        Assert.Equal(6, s.Decoded);
        Assert.Equal(1, s.TlsSni);
        var dns = Assert.Single(obs.OfType<DnsObservation>());
        Assert.Equal("c2.example.com", dns.Query);
        Assert.Equal(IPAddress.Parse("203.0.113.5"), Assert.Single(dns.ResolvedAddresses));
        var conns = obs.OfType<ConnectionObservation>().ToList();
        Assert.Contains(conns, c => c.RemotePort == 443 && c.State == "ESTABLISHED" && c.Pid is null);
        Assert.Contains(conns, c => c.Sni == "c2.example.com");
        Assert.Contains(conns, c => c.RemotePort == 4444 && c.Kind == ObservationKind.Closed && c.State == "SYN_SENT");
    }

    [Fact]
    public void Classic_pcap_is_analyzed()
    {
        var obs = new List<object>();
        var s = PcapAnalyzer.Analyze(new MemoryStream(PacketBuilder.ClassicPcap(Frames())), "t.pcap", obs.Add);
        AssertExpected(obs, s);
        Assert.Equal(T.AddSeconds(5), s.End);
    }

    [Fact]
    public void Pcapng_is_analyzed()
    {
        var obs = new List<object>();
        var s = PcapAnalyzer.Analyze(new MemoryStream(PacketBuilder.PcapNg(Frames())), "t.pcapng", obs.Add);
        AssertExpected(obs, s);
        Assert.Equal(T, s.Start);
    }

    [Fact]
    public void Garbage_and_truncated_input_fails_safely()
    {
        Assert.Throws<InvalidDataException>(() => PcapReader.Read(new MemoryStream(new byte[] { 1, 2, 3, 4, 5 })).ToList());
        var good = PacketBuilder.ClassicPcap(Frames());
        var truncated = good.AsSpan(0, good.Length - 10).ToArray();
        var obs = new List<object>();
        var s = PcapAnalyzer.Analyze(new MemoryStream(truncated), "t.pcap", obs.Add);
        Assert.Equal(5, s.Packets); // last packet dropped, no exception
    }

    [Fact]
    public void Http_host_is_extracted()
    {
        var req = Encoding.ASCII.GetBytes("GET /gate.php?id=1 HTTP/1.1\r\nHost: Panel.Example\r\nUser-Agent: x\r\n\r\n");
        var r = HttpRequestParser.TryParse(req);
        Assert.Equal(("panel.example", "/gate.php?id=1"), r);
    }
}

public class DnsParsingTests
{
    [Fact]
    public void Parses_response_with_compression()
    {
        var m = DnsMessageParser.Parse(PacketBuilder.DnsResponse(7, "www.example.org", "93.184.216.34"));
        Assert.NotNull(m);
        Assert.True(m!.IsResponse);
        Assert.Equal("www.example.org", m.QuestionName);
        var a = Assert.Single(m.Answers);
        Assert.Equal("www.example.org", a.Name);
        Assert.Equal(60, a.Ttl);
        Assert.Equal(IPAddress.Parse("93.184.216.34"), a.Address);
    }

    [Fact]
    public void Nxdomain_rcode_is_reported()
    {
        var m = DnsMessageParser.Parse(PacketBuilder.DnsResponse(8, "nope.example", "", rcode: 3));
        Assert.Equal(3, m!.RCode);
        Assert.Empty(m.Answers);
    }

    [Fact]
    public void Compression_loops_are_rejected()
    {
        // Header + a name that is a pointer to itself.
        var bytes = new byte[] { 0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1 };
        Assert.Null(DnsMessageParser.Parse(bytes));
    }

    [Fact]
    public void Windows_dns_client_results_are_parsed()
    {
        var (answers, addrs) = DnsClientResultParser.Parse("type:  5 star-mini.c10r.facebook.com;::ffff:157.240.1.35;2a03:2880:f12f:83:face:b00c:0:25de;");
        Assert.Equal(new[] { IPAddress.Parse("157.240.1.35"), IPAddress.Parse("2a03:2880:f12f:83:face:b00c:0:25de") }, addrs);
        Assert.Contains("CNAME star-mini.c10r.facebook.com", answers);
        Assert.Empty(DnsClientResultParser.Parse(null).Addresses);
    }

    [Fact]
    public void Sni_parser_rejects_non_tls()
    {
        Assert.Equal("c2.example.com", TlsSniParser.TryGetSni(PacketBuilder.ClientHello("C2.Example.com")));
        Assert.Null(TlsSniParser.TryGetSni(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n.....................................")));
    }
}

public class UtilTests
{
    [Fact]
    public void Sha256_of_file_matches_known_vector()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "abc");
            var h = new FileHasher().TryHash(path, out var err);
            Assert.Null(err);
            Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", h);
            // Cached and still correct; changes are detected.
            File.WriteAllText(path, "abcd");
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(1));
            Assert.Equal("88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589", new FileHasher().TryHash(path, out _));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Missing_file_hash_reports_reason()
    {
        Assert.Null(new FileHasher().TryHash(@"C:\definitely\not\here.exe", out var err));
        Assert.NotNull(err);
    }

    [Theory]
    [InlineData("8.8.8.8", IpScope.Public)]
    [InlineData("10.1.2.3", IpScope.Private)]
    [InlineData("172.16.0.1", IpScope.Private)]
    [InlineData("192.168.0.1", IpScope.Private)]
    [InlineData("127.0.0.1", IpScope.Loopback)]
    [InlineData("169.254.1.1", IpScope.LinkLocal)]
    [InlineData("100.64.0.1", IpScope.CarrierNat)]
    [InlineData("224.0.0.251", IpScope.Multicast)]
    [InlineData("203.0.113.5", IpScope.Documentation)]
    [InlineData("::1", IpScope.Loopback)]
    [InlineData("fe80::1", IpScope.LinkLocal)]
    [InlineData("fd00::1", IpScope.Private)]
    [InlineData("2606:4700::1", IpScope.Public)]
    [InlineData("::ffff:8.8.8.8", IpScope.Public)]
    public void Ip_scopes(string ip, IpScope scope) => Assert.Equal(scope, IpUtil.Classify(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("a.b.example.co.uk", "example.co.uk")]
    [InlineData("www.google.com", "google.com")]
    [InlineData("x.y.duckdns.org", "y.duckdns.org")]
    [InlineData("example.com", "example.com")]
    public void Registrable_domain(string d, string expected) => Assert.Equal(expected, DomainUtil.RegistrableDomain(d));

    [Fact]
    public void Domain_normalisation_rejects_junk()
    {
        Assert.Equal("example.com", DomainUtil.Normalize("Example.COM."));
        Assert.Null(DomainUtil.Normalize("not a domain"));
        Assert.Null(DomainUtil.Normalize("<script>.com"));
        Assert.Equal("xn--bcher-kva.example", DomainUtil.Normalize("bücher.example"));
    }
}
