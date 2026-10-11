using System.Globalization;
using System.Text.RegularExpressions;

namespace NetHunter.Core.Util;

public static partial class DomainUtil
{
    // Common multi-label public suffixes. A full Public Suffix List is not bundled to keep the app small;
    // this covers the suffixes that matter most for grouping subdomains under a registrable domain.
    private static readonly HashSet<string> MultiLabelSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "co.kr", "or.kr", "co.nz", "org.nz", "co.za", "org.za",
        "com.br", "net.br", "org.br", "com.cn", "net.cn", "org.cn", "com.tw", "com.hk", "com.sg", "com.my",
        "com.mx", "com.ar", "com.tr", "com.sa", "com.eg", "co.in", "net.in", "org.in", "co.il", "co.id",
        "com.pk", "com.ng", "com.ua", "com.pl", "com.ru", "co.th", "com.vn", "com.ph",
        "amazonaws.com", "cloudfront.net", "azurewebsites.net", "blob.core.windows.net", "trafficmanager.net",
        "appspot.com", "herokuapp.com", "github.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
        "duckdns.org", "no-ip.org", "ddns.net", "ngrok.io", "ngrok-free.app",
    };

    [GeneratedRegex(@"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{1,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex HostnameRegex();

    private static readonly IdnMapping Idn = new();

    /// <summary>Lower-cases, trims the trailing dot, converts IDN to punycode. Returns null when not a valid hostname.</summary>
    public static string? Normalize(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        var n = name.Trim().TrimEnd('.').ToLowerInvariant();
        if (n.StartsWith("*.")) n = n[2..];
        try { n = Idn.GetAscii(n); } catch (ArgumentException) { return null; }
        return HostnameRegex().IsMatch(n) ? n : null;
    }

    public static bool IsValid(string? name) => Normalize(name) is not null;

    /// <summary>Approximate registrable domain ("eTLD+1"): a.b.example.co.uk becomes example.co.uk.</summary>
    public static string RegistrableDomain(string domain)
    {
        var labels = domain.TrimEnd('.').ToLowerInvariant().Split('.');
        if (labels.Length <= 2) return string.Join('.', labels);
        for (int take = Math.Min(4, labels.Length - 1); take >= 2; take--)
        {
            var suffix = string.Join('.', labels[^take..]);
            if (MultiLabelSuffixes.Contains(suffix)) return string.Join('.', labels[^(take + 1)..]);
        }
        return string.Join('.', labels[^2..]);
    }

    public static string Tld(string domain)
    {
        var i = domain.LastIndexOf('.');
        return i < 0 ? domain : domain[(i + 1)..];
    }

    /// <summary>Everything left of the registrable domain ("" when none).</summary>
    public static string SubdomainPart(string domain)
    {
        var reg = RegistrableDomain(domain);
        return domain.Length > reg.Length ? domain[..(domain.Length - reg.Length - 1)] : "";
    }

    /// <summary>Yields the domain and each parent: a.b.c.com, b.c.com, c.com.</summary>
    public static IEnumerable<string> SelfAndParents(string domain)
    {
        var d = domain;
        while (true)
        {
            yield return d;
            var i = d.IndexOf('.');
            if (i < 0) yield break;
            d = d[(i + 1)..];
            if (!d.Contains('.')) yield break; // never yield a bare TLD
        }
    }

    /// <summary>Shannon entropy in bits per character.</summary>
    public static double Entropy(string s)
    {
        if (s.Length == 0) return 0;
        Span<int> counts = stackalloc int[128];
        int other = 0;
        foreach (var ch in s)
        {
            if (ch < 128) counts[ch]++; else other++;
        }
        double h = 0;
        foreach (var c in counts)
        {
            if (c == 0) continue;
            double p = (double)c / s.Length;
            h -= p * Math.Log2(p);
        }
        if (other > 0) { double p = (double)other / s.Length; h -= p * Math.Log2(p); }
        return h;
    }
}
