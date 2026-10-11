using System.Buffers.Binary;

namespace NetHunter.Core.Pcap;

public readonly record struct RawPacket(DateTimeOffset Timestamp, int LinkType, byte[] Data);

/// <summary>
/// Minimal, defensive reader for classic libpcap (.pcap, both byte orders, µs/ns) and pcapng (SHB/IDB/EPB/SPB/OPB).
/// Captures are untrusted input: every length is bounds-checked and oversized blocks are rejected.
/// </summary>
public static class PcapReader
{
    private const int MaxPacket = 256 * 1024;
    private const int MaxBlock = 16 * 1024 * 1024;

    public static IEnumerable<RawPacket> Read(Stream s)
    {
        var magicBuf = new byte[4];
        if (ReadUpTo(s, magicBuf, 0, 4) != 4) throw new InvalidDataException("File too short to be a capture");
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(magicBuf);
        return magic switch
        {
            0xA1B2C3D4 or 0xD4C3B2A1 or 0xA1B23C4D or 0x4D3CB2A1 => ReadClassic(s, magic),
            0x0A0D0D0A => ReadNg(s),
            _ => throw new InvalidDataException("Not a pcap/pcapng file (unknown magic number)"),
        };
    }

    private static IEnumerable<RawPacket> ReadClassic(Stream s, uint magic)
    {
        bool le = magic is 0xA1B2C3D4 or 0xA1B23C4D;
        bool nano = magic is 0xA1B23C4D or 0x4D3CB2A1;
        var hdr = new byte[20];
        ReadExact(s, hdr, 0, 20);
        int linkType = (int)(U32(hdr, 16, le) & 0x0FFFFFFF);
        var rec = new byte[16];
        while (true)
        {
            int n = ReadUpTo(s, rec, 0, 16);
            if (n == 0) yield break;
            if (n < 16) throw new InvalidDataException("Truncated packet header");
            uint sec = U32(rec, 0, le), frac = U32(rec, 4, le), incl = U32(rec, 8, le);
            if (incl > MaxPacket) throw new InvalidDataException($"Packet length {incl} exceeds limit");
            var data = new byte[incl];
            if (ReadUpTo(s, data, 0, (int)incl) < incl) yield break; // truncated final packet: stop quietly
            var ts = DateTimeOffset.FromUnixTimeSeconds(sec).AddTicks(nano ? frac / 100 : frac * 10L);
            yield return new RawPacket(ts, linkType, data);
        }
    }

    private sealed class NgState
    {
        public bool LittleEndian = true;
        public readonly List<(int LinkType, double TicksPerUnit)> Interfaces = new();
    }

    private static IEnumerable<RawPacket> ReadNg(Stream s)
    {
        var st = new NgState();
        var head = new byte[8];
        // The first block's type (SHB) was consumed while sniffing the magic.
        BinaryPrimitives.WriteUInt32LittleEndian(head, 0x0A0D0D0A);
        bool haveType = true;
        while (true)
        {
            if (!haveType)
            {
                int got = ReadUpTo(s, head, 0, 4);
                if (got == 0) yield break;
                if (got < 4) throw new InvalidDataException("Truncated pcapng block header");
            }
            haveType = false;
            if (ReadUpTo(s, head, 4, 4) < 4) throw new InvalidDataException("Truncated pcapng block header");

            if (BinaryPrimitives.ReadUInt32LittleEndian(head) == 0x0A0D0D0A)
            {
                ReadSectionHeader(s, head, st);
                continue;
            }
            uint type = U32(head, 0, st.LittleEndian);
            uint len = U32(head, 4, st.LittleEndian);
            if (len < 12 || len > MaxBlock || len % 4 != 0) throw new InvalidDataException($"Bad pcapng block length {len}");
            var body = new byte[len - 8];
            ReadExact(s, body, 0, body.Length);
            if (ParseBlock(type, body, body.Length - 4, st) is { } pkt) yield return pkt;
        }
    }

    private static void ReadSectionHeader(Stream s, byte[] head, NgState st)
    {
        var bom = new byte[4];
        ReadExact(s, bom, 0, 4);
        st.LittleEndian = BinaryPrimitives.ReadUInt32LittleEndian(bom) == 0x1A2B3C4D;
        uint total = U32(head, 4, st.LittleEndian);
        if (total < 28 || total > MaxBlock) throw new InvalidDataException("Bad section header length");
        Skip(s, total - 12);
        st.Interfaces.Clear();
    }

    private static RawPacket? ParseBlock(uint type, byte[] b, int len, NgState st)
    {
        bool le = st.LittleEndian;
        switch (type)
        {
            case 1: // Interface Description Block
            {
                if (len < 8) return null;
                int lt = U16(b, 0, le);
                double ticksPerUnit = 10; // default resolution: microseconds
                int off = 8;
                while (off + 4 <= len)
                {
                    int code = U16(b, off, le), olen = U16(b, off + 2, le);
                    if (code == 0) break;
                    if (code == 9 && olen >= 1 && off + 4 < len)
                    {
                        byte r = b[off + 4];
                        double unitsPerSecond = (r & 0x80) != 0 ? Math.Pow(2, r & 0x7F) : Math.Pow(10, r);
                        ticksPerUnit = TimeSpan.TicksPerSecond / unitsPerSecond;
                    }
                    off += 4 + ((olen + 3) & ~3);
                }
                st.Interfaces.Add((lt, ticksPerUnit));
                return null;
            }
            case 6: // Enhanced Packet Block
            case 2: // Obsolete Packet Block
            {
                if (len < 20) return null;
                int ifId = type == 6 ? (int)U32(b, 0, le) : U16(b, 0, le);
                uint tsHigh = U32(b, 4, le), tsLow = U32(b, 8, le), cap = U32(b, 12, le);
                if (cap > MaxPacket || 20 + cap > len) return null;
                if (ifId < 0 || ifId >= st.Interfaces.Count) return null;
                var (lt, tpu) = st.Interfaces[ifId];
                ulong units = ((ulong)tsHigh << 32) | tsLow;
                var ts = DateTimeOffset.UnixEpoch.AddTicks((long)(units * tpu));
                return new RawPacket(ts, lt, b.AsSpan(20, (int)cap).ToArray());
            }
            case 3: // Simple Packet Block (no timestamp)
            {
                if (len < 4 || st.Interfaces.Count == 0) return null;
                int cap = Math.Min(len - 4, MaxPacket);
                return new RawPacket(DateTimeOffset.UnixEpoch, st.Interfaces[0].LinkType, b.AsSpan(4, cap).ToArray());
            }
            default:
                return null;
        }
    }

    private static uint U32(byte[] b, int off, bool le) => le ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(off)) : BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(off));
    private static int U16(byte[] b, int off, bool le) => le ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(off)) : BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(off));

    private static void ReadExact(Stream s, byte[] buf, int off, int count)
    {
        if (ReadUpTo(s, buf, off, count) != count) throw new InvalidDataException("Unexpected end of capture file");
    }

    private static int ReadUpTo(Stream s, byte[] buf, int off, int count)
    {
        int total = 0;
        while (total < count)
        {
            int n = s.Read(buf, off + total, count - total);
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    private static void Skip(Stream s, long count)
    {
        if (s.CanSeek) { s.Seek(count, SeekOrigin.Current); return; }
        var buf = new byte[Math.Min(count, 65536)];
        while (count > 0)
        {
            int n = s.Read(buf, 0, (int)Math.Min(buf.Length, count));
            if (n == 0) throw new InvalidDataException("Unexpected end of capture file");
            count -= n;
        }
    }
}
