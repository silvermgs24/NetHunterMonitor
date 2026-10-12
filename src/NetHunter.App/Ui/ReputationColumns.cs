using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using NetHunter.App.Pages;
using NetHunter.Core.Intel;
using NetHunter.Core.Models;
using NetHunter.Core.Util;
using NetHunter.Windows;

namespace NetHunter.App.Ui;

public enum RepColumn { VirusTotalDestination, VirusTotalFile, AbuseIpDb }

/// <summary>
/// At-a-glance VirusTotal / AbuseIPDB cells for grids. Reads only cached results (never triggers a lookup),
/// so it is cheap enough to evaluate per visible row.
/// </summary>
public static class ReputationColumns
{
    /// <summary>The live host whose cache the cells read. Set once by the main window.</summary>
    public static AppHost? Host { get; set; }

    public static DataGrid Rep(this DataGrid g, string header, RepColumn kind, string path = ".", double width = 92)
    {
        var conv = new RepCellConverter(kind);
        var tb = new FrameworkElementFactory(typeof(TextBlock));
        tb.SetBinding(TextBlock.TextProperty, new Binding(path) { Converter = conv, ConverterParameter = "text", Mode = BindingMode.OneWay });
        tb.SetBinding(TextBlock.ForegroundProperty, new Binding(path) { Converter = conv, ConverterParameter = "brush", Mode = BindingMode.OneWay });
        tb.SetBinding(FrameworkElement.ToolTipProperty, new Binding(path) { Converter = conv, ConverterParameter = "tip", Mode = BindingMode.OneWay });
        tb.SetValue(TextBlock.FontWeightProperty, FontWeights.SemiBold);
        tb.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
        g.Columns.Add(new DataGridTemplateColumn
        {
            Header = header, Width = new DataGridLength(width), CanUserSort = false,
            CellTemplate = new DataTemplate { VisualTree = tb },
        });
        return g;
    }

    internal static (string? Ip, string? Domain, string? Sha) Keys(object? o) => o switch
    {
        ConnectionEvent e => (e.RemoteIp, e.Hostname, e.Sha256),
        FlowRecord f => (f.RemoteIp, f.Hostname, f.Sha256),
        FlowRow r => (r.RemoteIp, r.Hostname, r.Flow.Sha256),
        TimelineRow t => (t.E.RemoteIp, t.E.Hostname, t.E.Sha256),
        ProcessRow p => (null, null, p.Sha256),
        AlertRow a => (a.Alert.RemoteIp, a.Alert.Hostname, a.Alert.Sha256),
        IocRow i => i.Ioc.Type switch
        {
            IocType.Ip => (i.Value, null, null),
            IocType.Domain => (null, i.Value, null),
            IocType.Sha256 => (null, null, i.Value),
            _ => (null, null, null),
        },
        _ => (null, null, null),
    };
}

public sealed record RepCell(string Text, Brush Brush, string Tip);

public sealed class RepCellConverter : IValueConverter
{
    private readonly RepColumn _kind;
    public RepCellConverter(RepColumn kind) { _kind = kind; }

    public object Convert(object value, Type t, object p, CultureInfo c)
    {
        var cell = Cell(value);
        return (p as string) switch
        {
            "brush" => cell.Brush,
            "tip" => cell.Tip,
            _ => cell.Text,
        };
    }

    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;

    private static readonly Brush Muted = Freeze(new SolidColorBrush(Color.FromRgb(0x8B, 0x98, 0xA9)));
    private static Brush Freeze(SolidColorBrush b) { b.Freeze(); return b; }

    private RepCell Cell(object? row)
    {
        var host = ReputationColumns.Host;
        if (host is null) return new("", Muted, "");
        var (ip, domain, sha) = ReputationColumns.Keys(row);
        string providerName = _kind == RepColumn.AbuseIpDb ? AbuseIpDbProvider.ProviderName : VirusTotalProvider.ProviderName;

        // Which indicators this column covers.
        var targets = new List<(IocType Type, string Value)>();
        switch (_kind)
        {
            case RepColumn.VirusTotalDestination:
                if (ip is not null && IpUtil.TryParse(ip, out var vip) && IpUtil.IsExternal(vip)) targets.Add((IocType.Ip, ip));
                if (domain is not null && host.Settings.LookupDomains) targets.Add((IocType.Domain, domain));
                if (row is IocRow && sha is not null) targets.Add((IocType.Sha256, sha)); // IOC view: one VirusTotal column for every type
                break;
            case RepColumn.VirusTotalFile:
                if (sha is not null && host.Settings.LookupFileHashes) targets.Add((IocType.Sha256, sha));
                break;
            case RepColumn.AbuseIpDb:
                if (ip is not null && IpUtil.TryParse(ip, out var aip) && IpUtil.IsExternal(aip)) targets.Add((IocType.Ip, ip));
                break;
        }
        if (targets.Count == 0) return new("n/a", Muted, _kind == RepColumn.VirusTotalFile ? "No file hash available for this process" : "Private/local address or nothing to look up");

        var provider = host.Reputation.RemoteProviders.FirstOrDefault(x => x.Name == providerName);
        var results = targets
            .Select(x => host.Reputation.Cache.GetAll(x.Type, x.Value).FirstOrDefault(r => r.Provider == providerName))
            .Where(r => r is not null).Cast<ReputationResult>().ToList();

        if (results.Count == 0)
        {
            if (provider is null || !provider.IsEnabled || !host.Settings.ThreatIntelEnabled)
                return new("—", Muted, $"{providerName} not configured (Settings → Threat intelligence providers)");
            if (host.Reputation.Status == IntelStatus.Offline) return new("offline", Muted, "Threat intelligence unavailable (offline); will retry");
            return new("pending", Muted, "Lookup queued (subject to the provider's rate limit)");
        }

        if (_kind == RepColumn.AbuseIpDb)
        {
            var r = results[0];
            if (r.Status == ReputationStatus.NotFound) return new("no data", Muted, "AbuseIPDB has no data for this IP");
            if (r.Status != ReputationStatus.Ok || r.AbuseConfidence is null) return new("error", Muted, r.Summary());
            int conf = r.AbuseConfidence.Value;
            var brush = r.IsWhitelisted == true ? RiskColors.LowFg : conf >= 75 ? RiskColors.CriticalFg : conf >= 25 ? RiskColors.HighFg : conf > 0 ? RiskColors.MediumFg : RiskColors.LowFg;
            return new($"{conf}% · {r.TotalReports ?? 0}", brush,
                $"Abuse confidence {conf}%, {r.TotalReports ?? 0} reports from {r.DistinctReporters ?? 0} users\nCountry {r.CountryCode ?? "?"} · {r.Isp ?? "?"} · {r.UsageType ?? "?"}" +
                (r.LastReported is { } lr ? $"\nLast reported {lr.ToLocalTime():yyyy-MM-dd}" : "") + (r.IsWhitelisted == true ? "\nWhitelisted by AbuseIPDB" : ""));
        }

        // VirusTotal: show the worst of the covered indicators (IP and domain for destinations).
        var ok = results.Where(r => r.Status == ReputationStatus.Ok && r.Malicious is not null).ToList();
        var tip = string.Join("\n", results.Select(r => $"{r.Type} {r.Value}: " + (r.Status == ReputationStatus.Ok
            ? $"{r.Malicious}/{r.TotalEngines} malicious, {r.Suspicious ?? 0} suspicious"
            : r.Status == ReputationStatus.NotFound ? "not found on VirusTotal" : r.Summary())));
        if (ok.Count == 0)
            return results.All(r => r.Status == ReputationStatus.NotFound) ? new("not found", Muted, tip) : new("error", Muted, tip);
        var worst = ok.OrderByDescending(r => r.Malicious).ThenByDescending(r => r.Suspicious ?? 0).First();
        int mal = worst.Malicious!.Value, sus = worst.Suspicious ?? 0;
        var vtBrush = mal >= 5 ? RiskColors.CriticalFg : mal >= 1 ? RiskColors.HighFg : sus > 0 ? RiskColors.MediumFg : RiskColors.LowFg;
        return new($"{mal}/{worst.TotalEngines ?? 0}", vtBrush, tip);
    }
}
