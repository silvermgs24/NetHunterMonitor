using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using NetHunter.App.Ui;
using NetHunter.Core.Models;

namespace NetHunter.App.Pages;

public sealed class ProcessRow
{
    public string Key { get; init; } = "";
    public string Name { get; init; } = "";
    public int? Pid { get; init; }
    public string? Path { get; init; }
    public long Connections { get; init; }
    public int Destinations { get; init; }
    public int External { get; init; }
    public RiskLevel Level { get; init; }
    public int Score { get; init; }
    public string Signature { get; init; } = "";
    public string? Sha256 { get; init; }
    public DateTimeOffset LastSeen { get; init; }
}

/// <summary>Process-centric view: which programs talk to the network, how much, and how risky.</summary>
public sealed class ProcessesPage : PageBase
{
    private readonly ObservableCollection<ProcessRow> _rows = new();
    private readonly DataGrid _grid;
    private readonly StackPanel _detail = new();
    private readonly DispatcherTimer _refresh = new() { Interval = TimeSpan.FromSeconds(3) };
    private string _text = "";

    public ProcessesPage(UiContext ctx) : base(ctx)
    {
        _grid = Grids.Create(_rows)
            .Text("Process", "Name", 170)
            .Text("PID", "Pid", 60, fallback: "-")
            .Text("Connections", "Connections", 90)
            .Text("Destinations", "Destinations", 95)
            .Risk()
            .Text("Score", "Score", 50)
            .Rep("VT (file)", RepColumn.VirusTotalFile)
            .Text("Signature", "Signature", 200)
            .Text("Path", "Path", 0, fallback: "Unknown");
        _grid.SelectionChanged += (_, _) => ShowDetail();
        var scroll = new ScrollViewer { Content = _detail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        _detail.Children.Add(Ux.Muted("Select a process."));
        Layout(Toolbar(SearchBox("Filter processes", t => { _text = t.Trim(); Rebuild(); })), TwoPane(_grid, scroll, 470));
        _refresh.Tick += (_, _) => { if (IsVisible) Rebuild(); };
        _refresh.Start();
    }

    public override string Title => "Processes";

    public override void OnShown(object? argument)
    {
        Rebuild();
        if (argument is string key && _rows.FirstOrDefault(r => r.Key.Equals(key, StringComparison.OrdinalIgnoreCase)) is { } row)
        {
            _grid.SelectedItem = row;
            _grid.ScrollIntoView(row);
        }
    }

    private void Rebuild()
    {
        var selected = (_grid.SelectedItem as ProcessRow)?.Key;
        var groups = Store.Flows.GroupBy(f => f.Flow.ProcessKey).Select(g =>
        {
            var latest = g.OrderByDescending(f => f.LastSeen).First();
            var info = Host.Engine.GetProcess(g.Key);
            return new ProcessRow
            {
                Key = g.Key, Name = latest.ProcessName, Pid = latest.Pid, Path = latest.ProcessPath, Connections = g.Sum(f => f.Count),
                Destinations = g.Select(f => f.RemoteIp).Distinct().Count(), Level = g.Max(f => f.Level), Score = g.Max(f => f.Score),
                Signature = info?.Signature.ToString() ?? "", Sha256 = latest.Flow.Sha256 ?? info?.Sha256, LastSeen = latest.LastSeen,
            };
        })
        .Where(r => _text.Length == 0 || r.Name.Contains(_text, StringComparison.OrdinalIgnoreCase) || (r.Path?.Contains(_text, StringComparison.OrdinalIgnoreCase) ?? false))
        .OrderByDescending(r => r.Score).ThenByDescending(r => r.Connections).ToList();

        _rows.Clear();
        foreach (var r in groups) _rows.Add(r);
        if (selected is not null && _rows.FirstOrDefault(r => r.Key == selected) is { } again) _grid.SelectedItem = again;
    }

    private ProcessRow? _shown;

    private void ShowDetail()
    {
        if (_grid.SelectedItem is not ProcessRow r) return;
        if (_shown?.Key == r.Key && _shown.Score == r.Score && _shown.Connections == r.Connections) return;
        _shown = r;
        var info = Host.Engine.GetProcess(r.Key) ?? (r.Pid is { } pid ? Host.Engine.GetProcessByPid(pid) : null);
        _detail.Children.Clear();
        var head = new DockPanel();
        var b = Ux.Badge(r.Level);
        DockPanel.SetDock(b, Dock.Right);
        head.Children.Add(b);
        head.Children.Add(Ux.Heading("Process information"));
        _detail.Children.Add(head);
        _detail.Children.Add(Ux.Field("Name", r.Name));
        _detail.Children.Add(Ux.Field("PID", r.Pid?.ToString()));
        _detail.Children.Add(Ux.Field("Path", r.Path, info?.AttributionNote is { } n ? "Unknown: " + n : "Unknown"));
        _detail.Children.Add(Ux.Field("SHA-256", r.Sha256, "Not available"));
        _detail.Children.Add(Ux.Field("Signature", info?.Signature.ToString()));
        _detail.Children.Add(Ux.Field("Parent", info?.ParentName is null ? null : $"{info.ParentName} (PID {info.ParentPid})"));
        _detail.Children.Add(Ux.Field("Started", info?.StartTime?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")));
        var baseline = Host.Engine.Baseline.DestinationsFor(r.Key);
        _detail.Children.Add(Ux.Field("Baseline", baseline.Count == 0
            ? "No external destinations learned for this process yet"
            : $"Normally communicates with {baseline.Count} destination group(s): " + string.Join(", ", baseline.OrderByDescending(kv => kv.Value).Take(8).Select(kv => kv.Key[2..]))));
        _detail.Children.Add(Ux.Field("Analyst mark", Host.Engine.GetMark("process", r.Key).ToString()));

        _detail.Children.Add(Ux.Heading("Network connections"));
        var flows = Store.Flows.Where(f => f.Flow.ProcessKey == r.Key).OrderByDescending(f => f.Score).ThenByDescending(f => f.LastSeen).ToList();
        var mini = Grids.Create(flows)
            .Text("Remote", "RemoteIp", 140, mono: true)
            .Text("Host", "Hostname", 0, fallback: "Unknown")
            .Text("Port", "RemotePort", 50)
            .Text("Count", "Count", 50)
            .Risk();
        mini.MaxHeight = 260;
        mini.MouseDoubleClick += (_, _) => { if (mini.SelectedItem is FlowRow f) Ctx.Navigate("Connections", f.Key); };
        _detail.Children.Add(mini);
        _detail.Children.Add(Ux.Muted("Double-click a connection to open its full explanation."));

        var worst = flows.FirstOrDefault();
        if (worst is not null && worst.Flow.Assessment.Evidence.Any(e => e.Category == EvidenceCategory.Process))
        {
            _detail.Children.Add(Ux.Heading("Process-level signals"));
            _detail.Children.Add(Ux.EvidenceList(worst.Flow.Assessment.Evidence.Where(e => e.Category == EvidenceCategory.Process)));
        }

        _detail.Children.Add(Ux.Heading("Analyst actions"));
        _detail.Children.Add(Ux.Buttons(
            Ux.Button("Trusted", () => Host.Engine.SetMark("process", r.Key, UserMarkKind.Trusted)),
            Ux.Button("Ignored", () => Host.Engine.SetMark("process", r.Key, UserMarkKind.Ignored)),
            Ux.Button("Suspicious", () => Host.Engine.SetMark("process", r.Key, UserMarkKind.Suspicious)),
            Ux.Button("Clear mark", () => Host.Engine.SetMark("process", r.Key, UserMarkKind.None))));
        var actions = new List<Button>();
        if (r.Sha256 is not null) actions.Add(Ux.Button("Look up hash", () => { Host.Engine.RequestLookup(IocType.Sha256, r.Sha256); Ux.Info("Queued", Host.Reputation.StatusText); }));
        if (r.Path is not null) actions.Add(Ux.Button("Show file", () => Ux.RevealFile(r.Path)));
        if (actions.Count > 0) _detail.Children.Add(Ux.Buttons(actions.ToArray()));
        if (r.Sha256 is not null)
            foreach (var rep in Host.Engine.GetReputation(IocType.Sha256, r.Sha256)) _detail.Children.Add(FlowDetailView.ReputationBlock(rep));
    }
}
