using NetHunter.Core.Models;
using NetHunter.Core.Util;

namespace NetHunter.Core.Detection;

/// <summary>Static, single-name heuristics: randomness, length, depth, TLD, dynamic DNS. CDNs are discounted, never whitelisted.</summary>
public sealed class DomainAnalyzer
{
    private static readonly string[] DynamicDnsSuffixes =
    {
        "duckdns.org", "no-ip.org", "no-ip.com", "noip.me", "ddns.net", "hopto.org", "zapto.org", "sytes.net", "myftp.org",
        "dynu.net", "freedns.afraid.org", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "serveo.net", "portmap.io",
        "dyndns.org", "3utilities.com", "servehttp.com", "webhook.site", "requestbin.net", "interact.sh", "oast.fun",
    };

    private readonly Func<IReadOnlyCollection<string>> _suspiciousTlds;
    private readonly Func<IReadOnlyCollection<string>> _cdnSuffixes;

    public DomainAnalyzer(Func<IReadOnlyCollection<string>> suspiciousTlds, Func<IReadOnlyCollection<string>> cdnSuffixes)
    {
        _suspiciousTlds = suspiciousTlds;
        _cdnSuffixes = cdnSuffixes;
    }

    public bool IsCdn(string domain) => _cdnSuffixes().Any(s => domain.Equals(s, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + s, StringComparison.OrdinalIgnoreCase));

    public static bool IsDynamicDns(string domain) => DynamicDnsSuffixes.Any(s => domain.EndsWith("." + s, StringComparison.OrdinalIgnoreCase) || domain.Equals(s, StringComparison.OrdinalIgnoreCase));

    /// <summary>Randomness score 0..1 for a label: high entropy, digits mixed with letters, long consonant runs.</summary>
    public static double LabelRandomness(string label)
    {
        if (label.Length < 10) return 0;
        var letters = label.Count(char.IsLetter);
        var digits = label.Count(char.IsDigit);
        double entropy = DomainUtil.Entropy(label);
        double vowelRatio = letters == 0 ? 0 : (double)label.Count(c => "aeiou".Contains(c)) / letters;
        int maxConsonantRun = 0, run = 0;
        foreach (var c in label)
        {
            if (char.IsLetter(c) && !"aeiouy".Contains(c)) { run++; maxConsonantRun = Math.Max(maxConsonantRun, run); }
            else run = 0;
        }

        double score = 0;
        if (entropy > 3.5) score += Math.Min(0.4, (entropy - 3.5) * 0.4 + 0.15);
        if (letters > 0 && digits > 0 && digits >= 3 && (double)digits / label.Length is > 0.2 and < 0.8) score += 0.2;
        if (vowelRatio < 0.22 && letters >= 8) score += 0.2;
        if (maxConsonantRun >= 5) score += 0.15;
        if (label.Length >= 20) score += 0.1;
        // Hex-looking identifiers (hashes, GUIDs) are common in legit CDNs too: keep them moderate.
        if (label.All(c => Uri.IsHexDigit(c) || c == '-')) score = Math.Min(score, 0.45);
        return Math.Clamp(score, 0, 1);
    }

    public IReadOnlyList<Evidence> Analyze(string? hostname)
    {
        var ev = new List<Evidence>();
        var d = DomainUtil.Normalize(hostname);
        if (d is null) return ev;
        bool cdn = IsCdn(d);
        var labels = d.Split('.');
        var registrable = DomainUtil.RegistrableDomain(d);
        var sub = DomainUtil.SubdomainPart(d);
        var tld = DomainUtil.Tld(d);

        if (_suspiciousTlds().Contains(tld, StringComparer.OrdinalIgnoreCase))
            ev.Add(new Evidence(EvidenceCategory.Domain, $"Uses a top-level domain frequently abused for malicious infrastructure (.{tld})", 0.12));

        if (IsDynamicDns(d))
            ev.Add(new Evidence(EvidenceCategory.Domain, $"Dynamic DNS / tunnelling service ({registrable}) often used for C2", 0.22));

        // Randomness of the registrable label (DGA-style) and of the longest subdomain label.
        var regLabel = registrable.Split('.')[0];
        double regRandom = LabelRandomness(regLabel);
        double subRandom = sub.Length == 0 ? 0 : sub.Split('.').Max(LabelRandomness);
        double random = Math.Max(regRandom, subRandom);
        if (random >= 0.45)
        {
            double strength = cdn ? 0.03 : regRandom >= 0.45 ? 0.25 : 0.12;
            ev.Add(new Evidence(EvidenceCategory.Domain,
                cdn ? $"Random-looking hostname, but under a known CDN/cloud suffix (weak signal)"
                    : $"Random-looking domain name ({(regRandom >= 0.45 ? regLabel : "subdomain")}): possible DGA", strength));
        }

        if (d.Length > 60 && !cdn)
            ev.Add(new Evidence(EvidenceCategory.Domain, $"Very long hostname ({d.Length} characters)", 0.1));
        if (labels.Length >= 7 && !cdn)
            ev.Add(new Evidence(EvidenceCategory.Domain, $"Unusually deep subdomain nesting ({labels.Length} labels)", 0.08));
        if (labels.Any(l => l.StartsWith("xn--")))
            ev.Add(new Evidence(EvidenceCategory.Domain, "Internationalised (punycode) name: check for look-alike/homograph domain", 0.06));
        return ev;
    }
}
