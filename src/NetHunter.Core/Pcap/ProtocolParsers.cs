using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace NetHunter.Core.Pcap;

public sealed record DnsAnswer(string Name, int Type, int Ttl, string Data, IPAddress? Address);

public sealed record DnsMessage(int Id, bool IsResponse, int RCode, string? QuestionName, int QuestionType, IReadOnlyList<DnsAnswer> Answers);

/// <summary>RFC 1035 wire-format parser with compression-loop protection.</summary>
public static class DnsMessageParser
{
    public static string TypeName(int t) => t switch
    {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR", 15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV",
        64 => "SVCB", 65 => "HTTPS", 255 => "ANY", _ => "TYPE" + t,
    };

    public static DnsMessage? Parse(ReadOnlySpan<byte> m)
    {
        if (m.Length < 12) return null;
        int id = BinaryPrimitives.ReadUInt16BigEndian(m);
        int flags = BinaryPrimitives.ReadUInt16BigEndian(m[2..]);
        int qd = BinaryPrimitives.ReadUInt16BigEndian(m[4..]);
        int an = BinaryPrimitives.ReadUInt16BigEndian(m[6..]);
        if (qd > 16 || an > 256) return null;
        int off = 12;
        string? qname = null;
        int qtype = 0;
        for (int i = 0; i < qd; i++)
        {
            var name = ReadName(m, ref off);
            if (name is null || off + 4 > m.Length) return null;
            if (i == 0) { qname = name; qtype = BinaryPrimitives.ReadUInt16BigEndian(m[off..]); }
            off += 4;
        }
        var answers = new List<DnsAnswer>();
        for (int i = 0; i < an; i++)
        {
            var name = ReadName(m, ref off);
            if (name is null || off + 10 > m.Length) break;
            int type = BinaryPrimitives.ReadUInt16BigEndian(m[off..]);
            int ttl = (int)Math.Min(BinaryPrimitives.ReadUInt32BigEndian(m[(off + 4)..]), int.MaxValue);
            int rdlen = BinaryPrimitives.ReadUInt16BigEndian(m[(off + 8)..]);
            off += 10;
            if (off + rdlen > m.Length) break;
            var rdata = m.Slice(off, rdlen);
            string data;
            IPAddress? addr = null;
            switch (type)
            {
                case 1 when rdlen == 4: addr = new IPAddress(rdata); data = addr.ToString(); break;
                case 28 when rdlen == 16: addr = new IPAddress(rdata); data = addr.ToString(); break;
                case 5 or 2 or 12:
                    int p = off;
                    data = ReadName(m, ref p) ?? "";
                    break;
                case 16:
                    data = ReadTxt(rdata);
                    break;
                default: data = $"({rdlen} bytes)"; break;
            }
            answers.Add(new DnsAnswer(name, type, ttl, data, addr));
            off += rdlen;
        }
        return new DnsMessage(id, (flags & 0x8000) != 0, flags & 0x000F, qname, qtype, answers);
    }

    private static string ReadTxt(ReadOnlySpan<byte> r)
    {
        var sb = new StringBuilder();
        int i = 0;
        while (i < r.Length && sb.Length < 512)
        {
            int len = r[i++];
            if (i + len > r.Length) break;
            foreach (var b in r.Slice(i, len)) sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            i += len;
        }
        return sb.ToString();
    }

    internal static string? ReadName(ReadOnlySpan<byte> m, ref int off)
    {
        var sb = new StringBuilder();
        int pos = off, jumps = 0;
        bool jumped = false;
        while (true)
        {
            if (pos >= m.Length) return null;
            int len = m[pos];
            if (len == 0) { pos++; break; }
            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= m.Length || ++jumps > 16) return null;
                int ptr = ((len & 0x3F) << 8) | m[pos + 1];
                if (ptr >= m.Length) return null;
                if (!jumped) off = pos + 2;
                jumped = true;
                pos = ptr;
                continue;
            }
            if ((len & 0xC0) != 0 || pos + 1 + len > m.Length) return null;
            if (sb.Length > 0) sb.Append('.');
            foreach (var b in m.Slice(pos + 1, len)) sb.Append(b is >= 0x21 and < 0x7F ? char.ToLowerInvariant((char)b) : '?');
            if (sb.Length > 255) return null;
            pos += 1 + len;
        }
        if (!jumped) off = pos;
        return sb.ToString();
    }
}

/// <summary>Extracts the Server Name Indication from a TLS ClientHello (first segment only).</summary>
public static class TlsSniParser
{
    public static string? TryGetSni(ReadOnlySpan<byte> p)
    {
        // TLS record: type 22 (handshake), version 3.x
        if (p.Length < 43 || p[0] != 22 || p[1] != 3) return null;
        int recLen = BinaryPrimitives.ReadUInt16BigEndian(p[3..]);
        var h = p[5..];
        if (h.Length > recLen) h = h[..recLen];
        if (h.Length < 38 || h[0] != 1) return null; // ClientHello
        int i = 4 + 2 + 32; // handshake header, client version, random
        if (i >= h.Length) return null;
        i += 1 + h[i]; // session id
        if (i + 2 > h.Length) return null;
        i += 2 + BinaryPrimitives.ReadUInt16BigEndian(h[i..]); // cipher suites
        if (i >= h.Length) return null;
        i += 1 + h[i]; // compression methods
        if (i + 2 > h.Length) return null;
        int extEnd = Math.Min(h.Length, i + 2 + BinaryPrimitives.ReadUInt16BigEndian(h[i..]));
        i += 2;
        while (i + 4 <= extEnd)
        {
            int type = BinaryPrimitives.ReadUInt16BigEndian(h[i..]);
            int len = BinaryPrimitives.ReadUInt16BigEndian(h[(i + 2)..]);
            i += 4;
            if (i + len > extEnd) return null;
            if (type == 0 && len >= 5)
            {
                var e = h.Slice(i, len);
                int nameType = e[2], nameLen = BinaryPrimitives.ReadUInt16BigEndian(e[3..]);
                if (nameType != 0 || 5 + nameLen > e.Length || nameLen == 0 || nameLen > 255) return null;
                var name = Encoding.ASCII.GetString(e.Slice(5, nameLen));
                return name.All(c => c is >= '!' and <= '~') ? name.ToLowerInvariant() : null;
            }
            i += len;
        }
        return null;
    }
}

public static class HttpRequestParser
{
    private static readonly string[] Methods = { "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT " };

    /// <summary>Returns (host, path) from a plaintext HTTP/1.x request, or null.</summary>
    public static (string Host, string Path)? TryParse(ReadOnlySpan<byte> p)
    {
        if (p.Length < 16) return null;
        var text = Encoding.ASCII.GetString(p[..Math.Min(p.Length, 4096)]);
        if (!Methods.Any(m => text.StartsWith(m, StringComparison.Ordinal))) return null;
        var firstLineEnd = text.IndexOf("\r\n", StringComparison.Ordinal);
        if (firstLineEnd < 0) return null;
        var parts = text[..firstLineEnd].Split(' ');
        if (parts.Length < 3) return null;
        var hostIdx = text.IndexOf("\r\nHost:", StringComparison.OrdinalIgnoreCase);
        if (hostIdx < 0) return null;
        var hostEnd = text.IndexOf("\r\n", hostIdx + 7, StringComparison.Ordinal);
        if (hostEnd < 0) return null;
        var host = text[(hostIdx + 7)..hostEnd].Trim().ToLowerInvariant();
        if (host.Length == 0 || host.Length > 255 || host.Any(c => c is < '!' or > '~')) return null;
        var path = parts[1].Length > 2048 ? parts[1][..2048] : parts[1];
        return (host, path);
    }
}
