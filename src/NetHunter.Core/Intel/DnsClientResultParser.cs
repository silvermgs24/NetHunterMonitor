using System.Net;
using NetHunter.Core.Util;

namespace NetHunter.Core.Intel;

/// <summary>
/// Parses the "QueryResults" string of Microsoft-Windows-DNS-Client event 3008, e.g.
/// "type:  5 star-mini.c10r.facebook.com;::ffff:157.240.1.35;". IPv4 answers are reported as IPv4-mapped IPv6.
/// </summary>
public static class DnsClientResultParser
{
    public static (List<string> Answers, List<IPAddress> Addresses) Parse(string? results)
    {
        var answers = new List<string>();
        var addrs = new List<IPAddress>();
        if (string.IsNullOrWhiteSpace(results)) return (answers, addrs);
        foreach (var raw in results.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (raw.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
            {
                // "type:  5 alias.example.com" → record type number then data
                var rest = raw[5..].Trim();
                var sp = rest.IndexOf(' ');
                if (sp > 0 && int.TryParse(rest[..sp], out var t))
                    answers.Add($"{Pcap.DnsMessageParser.TypeName(t)} {rest[(sp + 1)..].Trim()}");
                else answers.Add(rest);
                continue;
            }
            if (IpUtil.TryParse(raw, out var ip))
            {
                addrs.Add(ip);
                answers.Add((ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "A " : "AAAA ") + ip);
            }
        }
        return (answers, addrs);
    }
}
