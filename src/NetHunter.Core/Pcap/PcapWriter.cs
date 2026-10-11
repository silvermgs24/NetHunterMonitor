using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace NetHunter.Core.Pcap;

/// <summary>Builds valid wire-format packets and capture files (used by tests and the synthetic sample-capture generator).</summary>
public static class PcapWriter
{
    public static byte[] Ethernet(byte[] ipPacket, bool v6 = false)
    {
        var f = new byte[14 + ipPacket.Length];
        f[12] = v6 ? (byte)0x86 : (byte)0x08;
        f[13] = v6 ? (byte)0xDD : (byte)0x00;
        ipPacket.CopyTo(f, 14);
        return f;
    }

    public static byte[] IPv4(string src, string dst, int proto, byte[] l4)
    {
        var p = new byte[20 + l4.Length];
        p[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
        p[8] = 64;
        p[9] = (byte)proto;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(p, 12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(p, 16);
        l4.CopyTo(p, 20);
        return p;
    }

    public static byte[] Tcp(int sport, int dport, byte flags, byte[]? payload = null)
    {
        payload ??= Array.Empty<byte>();
        var t = new byte[20 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(t, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(t.AsSpan(2), (ushort)dport);
        t[12] = 5 << 4;
        t[13] = flags;
        payload.CopyTo(t, 20);
        return t;
    }

    public static byte[] Udp(int sport, int dport, byte[] payload)
    {
        var u = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(u, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(2), (ushort)dport);
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(4), (ushort)u.Length);
        payload.CopyTo(u, 8);
        return u;
    }

    public static byte[] Name(string name)
    {
        var ms = new MemoryStream();
        foreach (var label in name.Split('.')) { ms.WriteByte((byte)label.Length); ms.Write(Encoding.ASCII.GetBytes(label)); }
        ms.WriteByte(0);
        return ms.ToArray();
    }

    public static byte[] DnsResponse(ushort id, string qname, string ip, int rcode = 0)
    {
        var ms = new MemoryStream();
        void U16(int v) { ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)v); }
        U16(id); U16(0x8180 | rcode); U16(1); U16(rcode == 0 ? 1 : 0); U16(0); U16(0);
        ms.Write(Name(qname)); U16(1); U16(1);
        if (rcode == 0)
        {
            U16(0xC00C); U16(1); U16(1); U16(0); U16(60); U16(4);
            ms.Write(IPAddress.Parse(ip).GetAddressBytes());
        }
        return ms.ToArray();
    }

    public static byte[] DnsQuery(ushort id, string qname, int type = 1)
    {
        var ms = new MemoryStream();
        void U16(int v) { ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)v); }
        U16(id); U16(0x0100); U16(1); U16(0); U16(0); U16(0);
        ms.Write(Name(qname)); U16(type); U16(1);
        return ms.ToArray();
    }

    public static byte[] ClientHello(string sni)
    {
        var name = Encoding.ASCII.GetBytes(sni);
        var ext = new MemoryStream();
        void W16(MemoryStream s, int v) { s.WriteByte((byte)(v >> 8)); s.WriteByte((byte)v); }
        W16(ext, 0); W16(ext, name.Length + 5); W16(ext, name.Length + 3); ext.WriteByte(0); W16(ext, name.Length); ext.Write(name);
        var body = new MemoryStream();
        W16(body, 0x0303); body.Write(new byte[32]); body.WriteByte(0); W16(body, 2); W16(body, 0x1301); body.WriteByte(1); body.WriteByte(0);
        W16(body, (int)ext.Length); body.Write(ext.ToArray());
        var hs = new MemoryStream();
        hs.WriteByte(1); hs.WriteByte(0); W16(hs, (int)body.Length); hs.Write(body.ToArray());
        var rec = new MemoryStream();
        rec.WriteByte(0x16); W16(rec, 0x0301); W16(rec, (int)hs.Length); rec.Write(hs.ToArray());
        return rec.ToArray();
    }

    public static byte[] ClassicPcap(IEnumerable<(DateTimeOffset T, byte[] Frame)> frames)
    {
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(0xA1B2C3D4); w.Write((ushort)2); w.Write((ushort)4); w.Write(0); w.Write(0); w.Write(65535); w.Write(1);
        foreach (var (t, f) in frames)
        {
            w.Write((uint)t.ToUnixTimeSeconds()); w.Write((uint)(t.Millisecond * 1000)); w.Write(f.Length); w.Write(f.Length); w.Write(f);
        }
        return ms.ToArray();
    }

    public static byte[] PcapNg(IEnumerable<(DateTimeOffset T, byte[] Frame)> frames)
    {
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        // SHB
        w.Write(0x0A0D0D0A); w.Write(28); w.Write(0x1A2B3C4D); w.Write((ushort)1); w.Write((ushort)0); w.Write(-1L); w.Write(28);
        // IDB: linktype 1, snaplen
        w.Write(1); w.Write(20); w.Write((ushort)1); w.Write((ushort)0); w.Write(65535); w.Write(20);
        foreach (var (t, f) in frames)
        {
            int pad = (4 - f.Length % 4) % 4;
            int len = 32 + f.Length + pad;
            ulong us = (ulong)(t.ToUnixTimeMilliseconds() * 1000);
            w.Write(6); w.Write(len); w.Write(0); w.Write((uint)(us >> 32)); w.Write((uint)us); w.Write(f.Length); w.Write(f.Length); w.Write(f); w.Write(new byte[pad]); w.Write(len);
        }
        return ms.ToArray();
    }
}

