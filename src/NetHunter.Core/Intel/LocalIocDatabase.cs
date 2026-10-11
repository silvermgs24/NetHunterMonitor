using System.Net;
using NetHunter.Core.Models;
using NetHunter.Core.Util;

namespace NetHunter.Core.Intel;

public sealed record IocEntry(IocType Type, string Value, string ListName, string? Comment);

public sealed record IocImportResult(string ListName, int Ips, int Cidrs, int Domains, int Hashes, int Urls, int Rejected)
{
    public int Total => Ips + Cidrs + Domains + Hashes + Urls;
}

/// <summary>
/// The analyst's own indicator lists (plain text, one indicator per line, '#' comments).
/// Checked locally, offline, before any external service. Type is auto-detected per line:
/// IPv4/IPv6, CIDR, SHA-256, URL (http/https), or domain.
/// </summary>
public sealed class LocalIocDatabase
{
    private readonly object _lock = new();
    private Dictionary<string, IocEntry> _ips = new();
    private List<(CidrBlock Block, IocEntry Entry)> _cidrs = new();
    private Dictionary<string, IocEntry> _domains = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, IocEntry> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, IocEntry> _urls = new(StringComparer.OrdinalIgnoreCase);

    public string? Directory { get; private set; }
    public int Count { get { lock (_lock) return _ips.Count + _cidrs.Count + _domains.Count + _hashes.Count + _urls.Count; } }

    public IReadOnlyList<IocImportResult> LoadDirectory(string dir)
    {
        System.IO.Directory.CreateDirectory(dir);
        Directory = dir;
        var fresh = new LocalIocDatabase();
        var results = new List<IocImportResult>();
        foreach (var file in System.IO.Directory.EnumerateFiles(dir, "*.txt").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            results.Add(fresh.AddLines(File.ReadLines(file), Path.GetFileName(file)));
        lock (_lock)
        {
            _ips = fresh._ips; _cidrs = fresh._cidrs; _domains = fresh._domains; _hashes = fresh._hashes; _urls = fresh._urls;
        }
        return results;
    }

    /// <summary>Copies a user-selected list into the IOC directory (so the app stays portable) and reloads.</summary>
    public IocImportResult Import(string sourceFile)
    {
        if (Directory is null) throw new InvalidOperationException("IOC directory not loaded");
        var probe = new LocalIocDatabase().AddLines(File.ReadLines(sourceFile), Path.GetFileName(sourceFile));
        var name = Path.GetFileNameWithoutExtension(sourceFile);
        var safe = string.Concat(name.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_'));
        if (safe.Length == 0) safe = "imported";
        var dest = Path.Combine(Directory, safe + ".txt");
        File.Copy(sourceFile, dest, overwrite: true);
        LoadDirectory(Directory);
        return probe with { ListName = Path.GetFileName(dest) };
    }

    public IocImportResult AddLines(IEnumerable<string> lines, string listName)
    {
        int ips = 0, cidrs = 0, domains = 0, hashes = 0, urls = 0, rejected = 0;
        lock (_lock)
        {
            foreach (var raw in lines)
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#') || line.StartsWith("//")) continue;
                string? comment = null;
                var hashPos = line.IndexOf(" #", StringComparison.Ordinal);
                if (hashPos > 0) { comment = line[(hashPos + 2)..].Trim(); line = line[..hashPos].Trim(); }
                // Accept "value,comment" and "value<TAB>comment" formats.
                var sep = line.IndexOfAny(new[] { ',', '\t', ' ', ';' });
                if (sep > 0 && !line.StartsWith("http", StringComparison.OrdinalIgnoreCase)) { comment ??= line[(sep + 1)..].Trim(); line = line[..sep]; }
                line = Defang(line);

                switch (Classify(line, out var normalized))
                {
                    case IocType.Ip when normalized.Contains('/'):
                        if (CidrBlock.TryParse(normalized, out var block)) { _cidrs.Add((block!, new IocEntry(IocType.Ip, normalized, listName, comment))); cidrs++; }
                        else rejected++;
                        break;
                    case IocType.Ip: _ips[normalized] = new IocEntry(IocType.Ip, normalized, listName, comment); ips++; break;
                    case IocType.Sha256: _hashes[normalized] = new IocEntry(IocType.Sha256, normalized, listName, comment); hashes++; break;
                    case IocType.Url: _urls[normalized] = new IocEntry(IocType.Url, normalized, listName, comment); urls++; break;
                    case IocType.Domain: _domains[normalized] = new IocEntry(IocType.Domain, normalized, listName, comment); domains++; break;
                    default: rejected++; break;
                }
            }
        }
        return new IocImportResult(listName, ips, cidrs, domains, hashes, urls, rejected);
    }

    /// <summary>Undo common defanging: hxxp, [.], (.), [:]</summary>
    public static string Defang(string s) =>
        s.Replace("[.]", ".").Replace("(.)", ".").Replace("{.}", ".").Replace("[:]", ":")
         .Replace("hxxps://", "https://", StringComparison.OrdinalIgnoreCase)
         .Replace("hxxp://", "http://", StringComparison.OrdinalIgnoreCase);

    public static IocType? Classify(string value, out string normalized)
    {
        normalized = value.Trim();
        if (normalized.Length == 0) return null;
        if (normalized.Contains('/') && !normalized.Contains("://") && CidrBlock.TryParse(normalized, out _)) return IocType.Ip;
        if (IpUtil.TryParse(normalized, out var ip)) { normalized = ip.ToString(); return IocType.Ip; }
        if (VirusTotalProvider.Sha256Regex().IsMatch(normalized)) { normalized = normalized.ToLowerInvariant(); return IocType.Sha256; }
        if (normalized.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || normalized.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(normalized, UriKind.Absolute, out var u)) return null;
            normalized = NormalizeUrl(u);
            return IocType.Url;
        }
        if (DomainUtil.Normalize(normalized) is { } d && d.Contains('.')) { normalized = d; return IocType.Domain; }
        return null;
    }

    public static string NormalizeUrl(Uri u) => $"{u.Scheme}://{u.Host.ToLowerInvariant()}{(u.IsDefaultPort ? "" : ":" + u.Port)}{u.PathAndQuery}";

    public IocEntry? MatchIp(IPAddress ip)
    {
        ip = IpUtil.Normalize(ip);
        lock (_lock)
        {
            if (_ips.TryGetValue(ip.ToString(), out var e)) return e;
            foreach (var (block, entry) in _cidrs) if (block.Contains(ip)) return entry;
        }
        return null;
    }

    /// <summary>Matches the domain itself or any parent (listing evil.com flags a.b.evil.com).</summary>
    public IocEntry? MatchDomain(string domain)
    {
        var d = DomainUtil.Normalize(domain);
        if (d is null) return null;
        lock (_lock)
            foreach (var candidate in DomainUtil.SelfAndParents(d))
                if (_domains.TryGetValue(candidate, out var e)) return e;
        return null;
    }

    public IocEntry? MatchHash(string sha256)
    {
        lock (_lock) return _hashes.TryGetValue(sha256.Trim(), out var e) ? e : null;
    }

    public IocEntry? MatchUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return null;
        lock (_lock) return _urls.TryGetValue(NormalizeUrl(u), out var e) ? e : null;
    }

    public IocEntry? Match(IocType type, string value) => type switch
    {
        IocType.Ip => IpUtil.TryParse(value, out var ip) ? MatchIp(ip) : null,
        IocType.Domain => MatchDomain(value),
        IocType.Sha256 => MatchHash(value),
        IocType.Url => MatchUrl(value),
        _ => null,
    };
}

/// <summary>Adapter exposing the local lists through the same pluggable provider interface.</summary>
public sealed class LocalIocProvider : IReputationProvider
{
    public const string ProviderName = "Local IOC";
    private readonly LocalIocDatabase _db;
    public LocalIocProvider(LocalIocDatabase db) { _db = db; }

    public string Name => ProviderName;
    public bool IsLocal => true;
    public bool IsEnabled => true;
    public bool Supports(IocType type) => true;

    public Task<ReputationResult> LookupAsync(IocType type, string value, CancellationToken ct) => Task.FromResult(Lookup(type, value));

    public ReputationResult Lookup(IocType type, string value)
    {
        var m = _db.Match(type, value);
        return m is null
            ? new ReputationResult { Provider = Name, Type = type, Value = value, Status = ReputationStatus.NotFound }
            : new ReputationResult { Provider = Name, Type = type, Value = value, Status = ReputationStatus.Ok, ListName = m.ListName, Detail = $"matched {m.Value}{(m.Comment is null ? "" : " (" + m.Comment + ")")}" };
    }
}
