using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using NetHunter.App.Ui;
using NetHunter.Core.Models;

namespace NetHunter.App.Pages;

/// <summary>Live traffic + current alerts + status at a glance.</summary>
public sealed class DashboardPage : PageBase
{
    private readonly FlowDetailView _detail;
    private readonly TextBlock _rate = new() { FontSize = 22, FontWeight = FontWeights.SemiBold };
    private readonly TextBlock _flows = new() { FontSize = 22, FontWeight = FontWeights.SemiBold };
    private readonly TextBlock _alertCount = new() { FontSize = 22, FontWeight = FontWeights.SemiBold };
    private readonly TextBlock _alertBreakdown = new() { Style = Ux.S("Muted") };
    private readonly TextBlock _intel = new() { FontSize = 14, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _collectors = new() { Style = Ux.S("Muted"), TextWrapping = TextWrapping.Wrap, TextTrimming = TextTrimming.None };
    private readonly ICollectionView _liveView;
    private RiskLevel? _min;

    public DashboardPage(UiContext ctx) : base(ctx)
    {
        _detail = new FlowDetailView(Host);
        _liveView = new CollectionViewSource { Source = Store.Live }.View;
        _liveView.Filter = o => _min is null || o is ConnectionEvent e && e.Level >= _min;

        var cards = new UniformGrid { Columns = 4, Margin = new Thickness(0, 0, 0, 12) };
        cards.Children.Add(Card("Connections / minute", _rate, Ux.Muted("new connections observed")));
        cards.Children.Add(Card("Tracked destinations", _flows, Ux.Muted("process → destination flows")));
        cards.Children.Add(Card("Open alerts", _alertCount, _alertBreakdown));
        cards.Children.Add(Card("Threat intelligence", _intel, _collectors));

        var live = Grids.Create(_liveView)
            .Text("Time", "Timestamp", 72, Grids.Conv("Time"))
            .Text("Dir", "Direction", 62, Grids.Conv("Dir"))
            .Text("Process", "ProcessName", 150)
            .Text("PID", "Pid", 58, fallback: "-")
            .Text("Remote IP", "RemoteIp", 150, mono: true)
            .Text("Hostname", "Hostname", 0, fallback: "Unknown")
            .Text("Port", "RemotePort", 56)
            .Text("Proto", "Protocol", 52, Grids.Conv("Upper"))
            .Rep("VirusTotal", RepColumn.VirusTotalDestination)
            .Rep("AbuseIPDB", RepColumn.AbuseIpDb)
            .Risk();
        live.SelectionChanged += (_, _) =>
        {
            if (live.SelectedItem is ConnectionEvent e && Store.FindFlow(e.FlowKey) is { } row) _detail.Show(row.Flow);
        };

        var filter = Combo(new[] { "All traffic", "Suspicious+", "High+", "Critical" }, 0, s => { _min = ParseRisk(s); _liveView.Refresh(); });
        var leftHeader = Toolbar(Ux.Heading("Live traffic"), new TextBlock { Width = 16 }, Label("Show"), filter);

        var alerts = Grids.Create(Store.Alerts)
            .Text("Time", "Updated", 72, Grids.Conv("Time"))
            .Risk("Severity", "Severity")
            .Text("Detection", "Title", 0)
            .Text("Process", "ProcessName", 120)
            .Text("Destination", "Destination", 160, mono: true);
        alerts.MaxHeight = 230;
        alerts.Margin = new Thickness(0, 0, 0, 10);
        alerts.MouseDoubleClick += (_, _) => { if (alerts.SelectedItem is AlertRow a) Ctx.Navigate("Alerts", a); };
        alerts.SelectionChanged += (_, _) =>
        {
            if (alerts.SelectedItem is AlertRow a && Store.FindFlow(a.Alert.SubjectKey) is { } row) _detail.Show(row.Flow);
        };

        var stack = new Grid();
        stack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        stack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        stack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        stack.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        var ah = Ux.Heading("Current alerts (double-click to open)");
        Grid.SetRow(ah, 0); stack.Children.Add(ah);
        Grid.SetRow(alerts, 1); stack.Children.Add(alerts);
        Grid.SetRow(leftHeader, 2); stack.Children.Add(leftHeader);
        Grid.SetRow(live, 3); stack.Children.Add(live);

        Layout(cards, TwoPane(stack, _detail));
        Store.Applied += _ => Refresh();
        Refresh();
    }

    public override string Title => "Dashboard";

    private static Border Card(string title, UIElement value, UIElement sub)
    {
        var sp = new StackPanel();
        sp.Children.Add(new TextBlock { Text = title, Style = Ux.S("Muted") });
        sp.Children.Add(value);
        sp.Children.Add(sub);
        return new Border { Style = Ux.S("Card"), Child = sp, Margin = new Thickness(0, 0, 10, 0), Padding = new Thickness(14, 10, 14, 10) };
    }

    public override void OnShown(object? argument) => Refresh();

    private void Refresh()
    {
        _rate.Text = Store.EventsPerMinute.ToString("0");
        _flows.Text = Store.Flows.Count.ToString("N0");
        var open = Store.Alerts.Where(a => !a.Acknowledged).ToList();
        _alertCount.Text = open.Count.ToString();
        _alertCount.Foreground = open.Any(a => a.Severity == RiskLevel.Critical) ? RiskColors.CriticalFg : open.Any(a => a.Severity == RiskLevel.High) ? RiskColors.HighFg : Ux.B("Text");
        _alertBreakdown.Text = $"✖ {open.Count(a => a.Severity == RiskLevel.Critical)} critical · ▲ {open.Count(a => a.Severity == RiskLevel.High)} high · ⚠ {open.Count(a => a.Severity == RiskLevel.Medium)} suspicious";
        _intel.Text = Host.Reputation.StatusText;
        _intel.Foreground = Host.Reputation.Status == Core.Intel.IntelStatus.Offline ? RiskColors.MediumFg : Ux.B("Text");
        var running = Host.Engine.Sources.Where(s => s.Running).Select(s => s.Name).ToList();
        _collectors.Text = Host.Engine.IsMonitoring
            ? $"Collectors: {(running.Count == 0 ? "none" : string.Join(", ", running))}. Pending lookups: {Host.Reputation.PendingLookups}"
            : "Monitoring is stopped.";
    }
}
