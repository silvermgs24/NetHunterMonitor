using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using NetHunter.App.Ui;
using NetHunter.Core.Models;

namespace NetHunter.App.Pages;

/// <summary>Security alerts. Every alert carries its score, confidence and the reasons behind it.</summary>
public sealed class AlertsPage : PageBase
{
    private readonly ICollectionView _view;
    private readonly DataGrid _grid;
    private readonly StackPanel _detail = new();
    private bool _showAck = true;
    private RiskLevel? _min;

    public AlertsPage(UiContext ctx) : base(ctx)
    {
        _view = new CollectionViewSource { Source = Store.Alerts }.View;
        _view.SortDescriptions.Add(new SortDescription(nameof(AlertRow.Updated), ListSortDirection.Descending));
        _view.Filter = o => o is AlertRow a && (_showAck || !a.Acknowledged) && (_min is null || a.Severity >= _min);
        _grid = Grids.Create(_view)
            .Text("Updated", "Updated", 130, Grids.Conv("DateTime"))
            .Risk("Severity", "Severity")
            .Text("Detection", "Title", 240)
            .Text("Process", "ProcessName", 140)
            .Text("Destination", "Destination", 170, mono: true)
            .Text("Score", "Score", 50)
            .Text("Confidence", "Confidence", 80)
            .Text("Status", "Status", 100);
        _grid.SelectionChanged += (_, _) => ShowDetail();

        var showAck = new CheckBox { Content = "Show acknowledged", IsChecked = true, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0) };
        showAck.Click += (_, _) => { _showAck = showAck.IsChecked == true; _view.Refresh(); };
        var toolbar = Toolbar(
            Label("Severity"), Combo(new[] { "All", "Suspicious+", "High+", "Critical" }, 0, s => { _min = ParseRisk(s); _view.Refresh(); }),
            showAck,
            Ux.Button("Acknowledge all visible", () => { foreach (var a in _view.Cast<AlertRow>().ToList()) Store.Acknowledge(a, true); _view.Refresh(); }),
            Ux.Button("Export visible…", () => Reports.SaveInvestigation(Host, _view.Cast<AlertRow>().Select(a => a.Alert).ToList(),
                _view.Cast<AlertRow>().Select(a => Store.FindFlow(a.Alert.SubjectKey)?.Flow).Where(f => f is not null).Cast<FlowRecord>().ToList())));
        var scroll = new ScrollViewer { Content = _detail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        _detail.Children.Add(Ux.Muted("Select an alert to see why it was raised."));
        Layout(toolbar, TwoPane(_grid, scroll, 470));
        Store.Applied += _ => _view.Refresh();
    }

    public override string Title => "Alerts";

    public override void OnShown(object? argument)
    {
        if (argument is AlertRow a) { _grid.SelectedItem = a; _grid.ScrollIntoView(a); }
    }

    private void ShowDetail()
    {
        if (_grid.SelectedItem is not AlertRow row) return;
        var a = row.Alert;
        _detail.Children.Clear();
        var head = new DockPanel();
        var b = Ux.Badge(a.Severity);
        DockPanel.SetDock(b, Dock.Right);
        head.Children.Add(b);
        head.Children.Add(Ux.Heading((a.IsSynthetic ? "[SYNTHETIC TEST] " : "") + a.Title));
        _detail.Children.Add(head);
        _detail.Children.Add(Ux.Muted($"{a.Classification.Describe()} · score {a.Score}/100 · confidence {a.Confidence}%"));
        _detail.Children.Add(Ux.Field("Process", $"{a.ProcessName} (PID {a.Pid?.ToString() ?? "unknown"})"));
        _detail.Children.Add(Ux.Field("Executable", a.ProcessPath));
        _detail.Children.Add(Ux.Field("SHA-256", a.Sha256));
        _detail.Children.Add(Ux.Field("Destination", a.RemoteIp is null ? null : $"{a.RemoteIp}{(a.RemotePort is null ? "" : ":" + a.RemotePort)}"));
        _detail.Children.Add(Ux.Field("Hostname", a.Hostname));
        _detail.Children.Add(Ux.Field("First seen / last seen", $"{a.FirstSeen?.ToLocalTime():yyyy-MM-dd HH:mm:ss} / {a.LastSeen?.ToLocalTime():yyyy-MM-dd HH:mm:ss}"));
        _detail.Children.Add(Ux.Field("Alert raised / updated", $"{a.Created.ToLocalTime():yyyy-MM-dd HH:mm:ss} / {a.Updated.ToLocalTime():yyyy-MM-dd HH:mm:ss}"));

        _detail.Children.Add(Ux.Heading("Reasons"));
        _detail.Children.Add(Ux.EvidenceList(a.Evidence));
        var reps = Reports.Reputations(Host, a).ToList();
        if (reps.Count > 0)
        {
            _detail.Children.Add(Ux.Heading("IOC reputation"));
            foreach (var r in reps) _detail.Children.Add(FlowDetailView.ReputationBlock(r));
        }
        _detail.Children.Add(Ux.Muted("\"Possible C2\" means the behaviour is consistent with command-and-control and needs analyst verification; it is not a confirmed malware verdict."));

        var buttons = new List<Button>
        {
            a.Acknowledged ? Ux.Button("Reopen", () => { Store.Acknowledge(row, false); ShowDetail(); }) : Ux.Button("Acknowledge", () => { Store.Acknowledge(row, true); ShowDetail(); }, "Primary"),
            Ux.Button("Export report…", () => Reports.SaveInvestigation(Host, new[] { a }, Store.FindFlow(a.SubjectKey) is { } f ? new[] { f.Flow } : Array.Empty<FlowRecord>())),
        };
        if (Store.FindFlow(a.SubjectKey) is not null) buttons.Add(Ux.Button("Open connection", () => Ctx.Navigate("Connections", a.SubjectKey)));
        if (a.ProcessPath is not null) buttons.Add(Ux.Button("Open process", () => Ctx.Navigate("Processes", a.ProcessPath.ToLowerInvariant())));
        _detail.Children.Add(Ux.Buttons(buttons.ToArray()));
    }
}
