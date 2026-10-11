using System.Net;
using System.Net.Sockets;

namespace NetHunter.Core.Util;

public enum IpScope { Public, Private, Loopback, LinkLocal, Multicast, Unspecified, Reserved, Documentation, CarrierNat }

public static class IpUtil
{
    public static IPAddress Normalize(IPAddress ip) => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;

    public static IpScope Classify(IPAddress ip)
    {
        ip = Normalize(ip);
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return IpScope.Unspecified;
        if (IPAddress.IsLoopback(ip)) return IpScope.Loopback;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 10) return IpScope.Private;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return IpScope.Private;
            if (b[0] == 192 && b[1] == 168) return IpScope.Private;
            if (b[0] == 169 && b[1] == 254) return IpScope.LinkLocal;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return IpScope.CarrierNat;
            if (b[0] >= 224 && b[0] <= 239) return IpScope.Multicast;
            if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return IpScope.Multicast; // broadcast
            if ((b[0] == 192 && b[1] == 0 && b[2] == 2) || (b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113))
                return IpScope.Documentation;
            if (b[0] == 0 || b[0] >= 240 || (b[0] == 198 && (b[1] == 18 || b[1] == 19)) || (b[0] == 192 && b[1] == 0 && b[2] == 0))
                return IpScope.Reserved;
            return IpScope.Public;
        }

        if (ip.IsIPv6LinkLocal) return IpScope.LinkLocal;
        if (ip.IsIPv6Multicast) return IpScope.Multicast;
        if (ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal) return IpScope.Private;
        var v6 = ip.GetAddressBytes();
        if (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8) return IpScope.Documentation;
        return IpScope.Public;
    }

    /// <summary>True if the address is routable on the Internet (or a documentation address in synthetic mode).</summary>
    public static bool IsExternal(IPAddress ip, bool allowDocumentationRanges = false)
    {
        var s = Classify(ip);
        return s == IpScope.Public || (allowDocumentationRanges && s == IpScope.Documentation);
    }

    public static bool TryParse(string? text, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (string.IsNullOrWhiteSpace(text)) return false;
        if (!IPAddress.TryParse(text.Trim(), out var parsed)) return false;
        ip = Normalize(parsed);
        return true;
    }

    /// <summary>/24 for IPv4, /48 for IPv6: used as a coarse "same infrastructure" key.</summary>
    public static string NetworkKey(IPAddress ip)
    {
        ip = Normalize(ip);
        var b = ip.GetAddressBytes();
        return ip.AddressFamily == AddressFamily.InterNetwork
            ? $"{b[0]}.{b[1]}.{b[2]}.0/24"
            : $"{b[0]:x2}{b[1]:x2}:{b[2]:x2}{b[3]:x2}:{b[4]:x2}{b[5]:x2}::/48";
    }
}

/// <summary>An IPv4/IPv6 CIDR block for IOC list matching.</summary>
public sealed class CidrBlock
{
    private readonly byte[] _network;
    private readonly int _prefix;

    private CidrBlock(byte[] network, int prefix) { _network = network; _prefix = prefix; }

    public string Text { get; private init; } = "";

    public static bool TryParse(string text, out CidrBlock? block)
    {
        block = null;
        var parts = text.Trim().Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || !int.TryParse(parts[1], out var prefix)) return false;
        ip = IpUtil.Normalize(ip);
        var bytes = ip.GetAddressBytes();
        if (prefix < 0 || prefix > bytes.Length * 8) return false;
        block = new CidrBlock(Mask(bytes, prefix), prefix) { Text = text.Trim() };
        return true;
    }

    public bool Contains(IPAddress ip)
    {
        var bytes = IpUtil.Normalize(ip).GetAddressBytes();
        if (bytes.Length != _network.Length) return false;
        var masked = Mask(bytes, _prefix);
        return masked.AsSpan().SequenceEqual(_network);
    }

    private static byte[] Mask(byte[] bytes, int prefix)
    {
        var r = new byte[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
        {
            int bits = Math.Clamp(prefix - i * 8, 0, 8);
            r[i] = (byte)(bytes[i] & (0xFF << (8 - bits)));
        }
        return r;
    }
}
