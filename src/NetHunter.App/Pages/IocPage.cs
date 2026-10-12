using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using NetHunter.App.Ui;
using NetHunter.Core.Export;
using NetHunter.Core.Models;

namespace NetHunter.App.Pages;

public sealed class IocRow
{
    public required IocSummary Ioc { get; init; }
    public string Value => Ioc.Value;
    public string Type => Ioc.Type switch { IocType.Ip => "IP", IocType.Domain => "Domain", IocType.Sha256 => "SHA-256", _ => "URL" };
    public DateTimeOffset FirstSeen => Ioc.FirstSeen;
    public DateTimeOffset LastSeen => Ioc.LastSeen;
    public string Processes => Ioc.Processes;
    public string Reputation => Ioc.Reputation;
    public RiskLevel Level => Ioc.Level;
    public int Score => Ioc.Score;
    public long Connections => Ioc.Connections;
    public string Category { get; init; } = "Unknown";
}

/// <summary>Destination IPs, domains and executable hashes seen on this machine, with reputation from every source.</summary>
public sealed class IocPage : PageBase
{
    private readonly ObservableCollection<IocRow> _rows = new();
    private readonly DataGrid _grid;
    private readonly StackPanel _detail = new();
    private readonly TextBlock _iocInfo = new() { Style = Ux.S("Muted"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0, 0, 0) };
    private List<IocRow> _all = new();
    private string _category = "All";
    private string _text = "";

    public IocPage(UiContext ctx) : base(ctx)
    {
        _grid = Grids.Create(_rows)
            .Text("IOC", "Value", 260, mono: true)
            .Text("Type", "Type", 70)
            .Text("Category", "Category", 90)
            .Text("First seen", "FirstSeen", 130, Grids.Conv("DateTime"))
            .Text("Last seen", "LastSeen", 130, Grids.Conv("DateTime"))
            .Text("Processes", "Processes", 170)
            .Rep("VirusTotal", RepColumn.VirusTotalDestination)
            .Rep("AbuseIPDB", RepColumn.AbuseIpDb)
            .Text("All reputation", "Reputation", 260)
            .Risk();
        _grid.SelectionChanged += (_, _) => ShowDetail();

        var cats = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) };
        foreach (var c in new[] { "All", "Malicious", "Suspicious", "Unknown", "Clean" })
        {
            var rb = new RadioButton { Content = c, GroupName = "ioccat", IsChecked = c == "All", VerticalAlignment = VerticalAlignment.Center };
            rb.Checked += (_, _) => { _category = c; Apply(); };
            cats.Children.Add(rb);
        }
        var toolbar = Toolbar(cats, SearchBox("Filter IOCs", t => { _text = t.Trim(); Apply(); }, 200),
            Ux.Button("Refresh", Reload),
            Ux.Button("Import IOC list…", Import, tooltip: "Add a text file of IPs, CIDRs, domains, SHA-256 hashes or URLs (one per line)"),
            Ux.Button("Open IOC folder", () => Ux.OpenFolder(Host.IocDirectory)),
            Ux.Button("Export…", Export), _iocInfo);
        var scroll = new ScrollViewer { Content = _detail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        _detail.Children.Add(Ux.Muted("Select an indicator to see its reputation from every source."));
        Layout(toolbar, TwoPane(_grid, scroll, 440));
    }

    public override string Title => "IOC";

    public override void OnShown(object? argument)
    {
        Reload();
        if (argument is string v)
        {
            var row = _rows.FirstOrDefault(r => r.Value.Equals(v, StringComparison.OrdinalIgnoreCase));
            if (row is not null) { _grid.SelectedItem = row; _grid.ScrollIntoView(row); }
        }
    }

    private async void Reload()
    {
        var host = Host;
        var list = await Task.Run(() => host.Database.QueryIocs());
        _all = list.Select(i =>
        {
            var reps = host.Engine.GetReputation(i.Type, i.Value);
            i.Reputation = reps.Count == 0 ? "" : string.Join(" · ", reps.Select(r => r.Summary()));
            return new IocRow { Ioc = i, Category = Categorize(i, reps) };
        }).OrderByDescending(r => r.Score).ThenByDescending(r => r.LastSeen).ToList();
        _iocInfo.Text = $"{host.Reputation.LocalDb.Count} indicators loaded from local IOC lists · {host.Reputation.StatusText}";
        Apply();
    }

    private static string Categorize(IocSummary i, IReadOnlyList<ReputationResult> reps)
    {
        bool bad = reps.Any(r => r.ListName is not null || (r.Malicious ?? 0) >= 3 || (r.AbuseConfidence ?? 0) >= 75);
        if (bad || i.Level == RiskLevel.Critical) return "Malicious";
        bool sus = reps.Any(r => (r.Malicious ?? 0) >= 1 || (r.AbuseConfidence ?? 0) >= 25) || i.Level is RiskLevel.High or RiskLevel.Medium;
        if (sus) return "Suspicious";
        return reps.Any(r => r.Status == ReputationStatus.Ok) ? "Clean" : "Unknown";
    }

    private void Apply()
    {
        _rows.Clear();
        foreach (var r in _all.Where(r => (_category == "All" || r.Category == _category) && (_text.Length == 0 || r.Value.Contains(_text, StringComparison.OrdinalIgnoreCase) || r.Processes.Contains(_text, StringComparison.OrdinalIgnoreCase))))
            _rows.Add(r);
    }

    private void ShowDetail()
    {
        if (_grid.SelectedItem is not IocRow r) return;
        _detail.Children.Clear();
        var head = new DockPanel();
        var b = Ux.Badge(r.Level);
        DockPanel.SetDock(b, Dock.Right);
        head.Children.Add(b);
        head.Children.Add(Ux.Heading($"{r.Type} indicator"));
        _detail.Children.Add(head);
        _detail.Children.Add(Ux.Field("Value", r.Value));
        _detail.Children.Add(Ux.Field("Category", r.Category));
        _detail.Children.Add(Ux.Field("First / last seen", $"{r.FirstSeen.ToLocalTime():yyyy-MM-dd HH:mm:ss} / {r.LastSeen.ToLocalTime():yyyy-MM-dd HH:mm:ss}"));
        _detail.Children.Add(Ux.Field("Processes", r.Processes));
        _detail.Children.Add(Ux.Field("Connections", r.Connections.ToString()));
        if (r.Ioc.Type == IocType.Ip)
        {
            var h = Host.Engine.GetHostInfo(r.Value);
            _detail.Children.Add(Ux.Field("DNS hostname", h?.DnsNames.Count > 0 ? string.Join(", ", h.DnsNames) : null));
            _detail.Children.Add(Ux.Field("PTR (informational)", h?.Ptr, "None / not looked up"));
        }
        _detail.Children.Add(Ux.Heading("Reputation"));
        var reps = Host.Engine.GetReputation(r.Ioc.Type, r.Value);
        if (reps.Count == 0) _detail.Children.Add(Ux.Muted("No local IOC match and no provider data. " + Host.Reputation.StatusText));
        foreach (var rep in reps) _detail.Children.Add(FlowDetailView.ReputationBlock(rep));

        string kind = r.Ioc.Type switch { IocType.Ip => "ip", IocType.Domain => "domain", _ => "hash" };
        _detail.Children.Add(Ux.Heading("Analyst actions"));
        _detail.Children.Add(Ux.Buttons(
            Ux.Button("Look up now", () => { Host.Engine.RequestLookup(r.Ioc.Type, r.Value); Ux.Info("Queued", Host.Reputation.StatusText); }),
            Ux.Button("Search events", () => Ctx.Navigate("Search", r.Value))));
        _detail.Children.Add(Ux.Buttons(
            Ux.Button("Trusted", () => Host.Engine.SetMark(kind, r.Value, UserMarkKind.Trusted)),
            Ux.Button("Ignored", () => Host.Engine.SetMark(kind, r.Value, UserMarkKind.Ignored)),
            Ux.Button("Suspicious", () => Host.Engine.SetMark(kind, r.Value, UserMarkKind.Suspicious)),
            Ux.Button("Clear mark", () => Host.Engine.SetMark(kind, r.Value, UserMarkKind.None))));
        _detail.Children.Add(Ux.Muted($"Current mark: {Host.Engine.GetMark(kind, r.Value)}. Nothing is ever whitelisted automatically."));
    }

    private void Import()
    {
        var file = Ux.OpenFile("Import IOC list", "Text files (*.txt;*.csv;*.ioc)|*.txt;*.csv;*.ioc|All files (*.*)|*.*");
        if (file is null) return;
        var res = Host.Reputation.LocalDb.Import(file);
        Host.LogFile.Write($"Imported IOC list {file}: {res.Total} indicators, {res.Rejected} rejected");
        Host.Engine.ReassessAll();
        Ux.Info("IOC list imported", $"{res.ListName}\n\nIPs: {res.Ips}\nCIDR ranges: {res.Cidrs}\nDomains: {res.Domains}\nSHA-256: {res.Hashes}\nURLs: {res.Urls}\nRejected lines: {res.Rejected}\n\nAll current traffic has been re-checked against the lists.");
        Reload();
    }

    private void Export()
    {
        var rows = _rows.Select(r => { r.Ioc.Reputation = r.Reputation; return r.Ioc; }).ToList();
        Reports.SaveText("Export IOCs", $"iocs-{DateTime.Now:yyyyMMdd-HHmmss}", "CSV (*.csv)|*.csv|Indicator list (*.txt)|*.txt|JSON (*.json)|*.json",
            ext => ext switch { ".txt" => Exporter.IocList(rows), ".json" => Exporter.ToJson(rows), _ => Exporter.IocsCsv(rows) });
    }
}
