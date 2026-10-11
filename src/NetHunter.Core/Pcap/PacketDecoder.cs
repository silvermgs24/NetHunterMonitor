using System.Buffers.Binary;
using System.Net;
using NetHunter.Core.Models;

namespace NetHunter.Core.Pcap;

public sealed record DecodedPacket(
    DateTimeOffset Timestamp, IPAddress Src, IPAddress Dst, TransportProtocol Protocol,
    int SrcPort, int DstPort, byte TcpFlags, ReadOnlyMemory<byte> Payload)
{
    public bool Syn => (TcpFlags & 0x02) != 0;
    public bool Ack => (TcpFlags & 0x10) != 0;
    public bool Rst => (TcpFlags & 0x04) != 0;
    public bool Fin => (TcpFlags & 0x01) != 0;
}

/// <summary>Link → IP → TCP/UDP decoding. Returns null for anything it cannot or should not parse.</summary>
public static class PacketDecoder
{
    public static DecodedPacket? Decode(RawPacket p)
    {
        var d = p.Data.AsMemory();
        int ethType;
        switch (p.LinkType)
        {
            case 1: // Ethernet
                if (d.Length < 14) return null;
                ethType = BinaryPrimitives.ReadUInt16BigEndian(d.Span[12..]);
                d = d[14..];
                for (int i = 0; i < 2 && ethType is 0x8100 or 0x88A8; i++) // VLAN / QinQ
                {
                    if (d.Length < 4) return null;
                    ethType = BinaryPrimitives.ReadUInt16BigEndian(d.Span[2..]);
                    d = d[4..];
                }
                break;
            case 0: // BSD loopback / NULL: 4-byte address family in host order
                if (d.Length < 4) return null;
                uint fam = BinaryPrimitives.ReadUInt32LittleEndian(d.Span);
                if (fam > 0xFFFF) fam = BinaryPrimitives.ReadUInt32BigEndian(d.Span);
                ethType = fam == 2 ? 0x0800 : fam is 24 or 28 or 30 ? 0x86DD : 0;
                d = d[4..];
                break;
            case 101: case 12: case 14: // raw IP
                if (d.Length < 1) return null;
                ethType = (d.Span[0] >> 4) == 6 ? 0x86DD : 0x0800;
                break;
            case 228: ethType = 0x0800; break;
            case 229: ethType = 0x86DD; break;
            case 113: // Linux cooked v1
                if (d.Length < 16) return null;
                ethType = BinaryPrimitives.ReadUInt16BigEndian(d.Span[14..]);
                d = d[16..];
                break;
            case 276: // Linux cooked v2
                if (d.Length < 20) return null;
                ethType = BinaryPrimitives.ReadUInt16BigEndian(d.Span);
                d = d[20..];
                break;
            default:
                return null;
        }

        return ethType switch
        {
            0x0800 => DecodeIPv4(p.Timestamp, d),
            0x86DD => DecodeIPv6(p.Timestamp, d),
            _ => null,
        };
    }

    private static DecodedPacket? DecodeIPv4(DateTimeOffset ts, ReadOnlyMemory<byte> d)
    {
        var s = d.Span;
        if (s.Length < 20 || (s[0] >> 4) != 4) return null;
        int ihl = (s[0] & 0x0F) * 4;
        if (ihl < 20 || s.Length < ihl) return null;
        int total = BinaryPrimitives.ReadUInt16BigEndian(s[2..]);
        int fragOffset = BinaryPrimitives.ReadUInt16BigEndian(s[6..]) & 0x1FFF;
        if (fragOffset != 0) return null; // only the first fragment carries the L4 header
        int proto = s[9];
        var src = new IPAddress(s.Slice(12, 4));
        var dst = new IPAddress(s.Slice(16, 4));
        int end = total >= ihl && total <= s.Length ? total : s.Length; // tolerate TSO/truncated captures
        return DecodeL4(ts, src, dst, proto, d[ihl..end]);
    }

    private static DecodedPacket? DecodeIPv6(DateTimeOffset ts, ReadOnlyMemory<byte> d)
    {
        var s = d.Span;
        if (s.Length < 40 || (s[0] >> 4) != 6) return null;
        int next = s[6];
        var src = new IPAddress(s.Slice(8, 16));
        var dst = new IPAddress(s.Slice(24, 16));
        int payloadLen = BinaryPrimitives.ReadUInt16BigEndian(s[4..]);
        var rest = d[40..];
        if (payloadLen > 0 && payloadLen <= rest.Length) rest = rest[..payloadLen];
        for (int hops = 0; hops < 8 && next is 0 or 43 or 60 or 44; hops++)
        {
            var r = rest.Span;
            if (r.Length < 8) return null;
            if (next == 44)
            {
                if ((BinaryPrimitives.ReadUInt16BigEndian(r[2..]) & 0xFFF8) != 0) return null; // non-first fragment
                next = r[0];
                rest = rest[8..];
                continue;
            }
            int len = (r[1] + 1) * 8;
            if (r.Length < len) return null;
            next = r[0];
            rest = rest[len..];
        }
        return DecodeL4(ts, src, dst, next, rest);
    }

    private static DecodedPacket? DecodeL4(DateTimeOffset ts, IPAddress src, IPAddress dst, int proto, ReadOnlyMemory<byte> d)
    {
        var s = d.Span;
        if (proto == 6)
        {
            if (s.Length < 20) return null;
            int off = (s[12] >> 4) * 4;
            if (off < 20 || off > s.Length) return null;
            return new DecodedPacket(ts, src, dst, TransportProtocol.Tcp, BinaryPrimitives.ReadUInt16BigEndian(s), BinaryPrimitives.ReadUInt16BigEndian(s[2..]), s[13], d[off..]);
        }
        if (proto == 17)
        {
            if (s.Length < 8) return null;
            return new DecodedPacket(ts, src, dst, TransportProtocol.Udp, BinaryPrimitives.ReadUInt16BigEndian(s), BinaryPrimitives.ReadUInt16BigEndian(s[2..]), 0, d[8..]);
        }
        return null;
    }
}
