using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using NetHunter.App.Ui;
using NetHunter.Core.Export;
using NetHunter.Core.Models;
using NetHunter.Core.Storage;

namespace NetHunter.App.Pages;

public sealed class TimelineRow
{
    public required ConnectionEvent E { get; init; }
    public string Minute { get; init; } = "";
    public DateTimeOffset Timestamp => E.Timestamp;
    public string Flow => $"{E.ProcessName} {(E.Direction == Direction.Inbound ? "←" : "→")} {E.Hostname ?? E.RemoteIp}";
    public string Endpoint => $"{E.RemoteIp}:{E.RemotePort}/{E.Protocol.ToString().ToUpperInvariant()}";
    public RiskLevel Level => E.Level;
    public string Marker => E.Level >= RiskLevel.Medium ? "⚠" : "";
}

/// <summary>Historical network activity from the local database with the full set of filters.</summary>
public sealed class TimelinePage : PageBase
{
    private readonly ObservableCollection<TimelineRow> _rows = new();
    private readonly FlowDetailView _detail;
    private readonly TextBox _process = new() { Width = 120 }, _ip = new() { Width = 120 }, _domain = new() { Width = 130 }, _port = new() { Width = 60 };
    private readonly ComboBox _proto, _risk, _dir, _range;
    private readonly TextBlock _status = new() { Style = Ux.S("Muted"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };

    public TimelinePage(UiContext ctx) : base(ctx)
    {
        _detail = new FlowDetailView(Host);
        _proto = Combo(new[] { "Any protocol", "TCP", "UDP" }, 0, _ => { });
        _risk = Combo(new[] { "All", "Suspicious+", "High+", "Critical" }, 0, _ => { });
        _dir = Combo(new[] { "Both directions", "Outbound", "Inbound" }, 0, _ => { });
        _range = Combo(new[] { "Last 15 min", "Last hour", "Last 6 hours", "Last 24 hours", "Last 7 days", "All time" }, 1, _ => { });
        var grid = Grids.Create(_rows)
            .Text("Minute", "Minute", 120)
            .Text("Time", "Timestamp", 72, Grids.Conv("Time"))
            .Text("", "Marker", 24)
            .Text("Activity", "Flow", 0)
            .Text("Endpoint", "Endpoint", 230, mono: true)
            .Risk();
        grid.SelectionChanged += (_, _) =>
        {
            if (grid.SelectedItem is TimelineRow r)
            {
                if (Store.FindFlow(r.E.FlowKey) is { } f) _detail.Show(f.Flow);
                else _detail.ShowEmpty("This event's flow is no longer in memory (older than the live window). Event: " + r.Flow + " " + r.Endpoint);
            }
        };
        foreach (var tb in new[] { _process, _ip, _domain, _port }) { tb.Margin = new Thickness(0, 0, 8, 0); tb.KeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Enter) Query(); }; }
        var filters = new WrapPanel { Margin = new Thickness(0, 0, 0, 10) };
        foreach (var el in new UIElement[] { Label("Process"), _process, Label("IP"), _ip, Label("Domain"), _domain, Label("Port"), _port, _proto, _risk, _dir, _range,
                     Ux.Button("Apply", Query, "Primary"), Ux.Button("Export CSV…", Export), _status })
        {
            if (el is FrameworkElement fe) fe.Margin = new Thickness(0, 4, 8, 0);
            filters.Children.Add(el);
        }
        Layout(filters, TwoPane(grid, _detail));
    }

    public override string Title => "Timeline";

    public override void OnShown(object? argument)
    {
        if (argument is string ip) _ip.Text = ip;
        Query();
    }

    private EventFilter BuildFilter()
    {
        var hours = (_range.SelectedItem as string) switch
        {
            "Last 15 min" => 0.25, "Last hour" => 1, "Last 6 hours" => 6, "Last 24 hours" => 24, "Last 7 days" => 168, _ => (double?)null,
        };
        return new EventFilter
        {
            Process = _process.Text, Ip = _ip.Text, Domain = _domain.Text, Port = int.TryParse(_port.Text, out var p) ? p : null,
            Protocol = (_proto.SelectedItem as string) switch { "TCP" => TransportProtocol.Tcp, "UDP" => TransportProtocol.Udp, _ => null },
            MinLevel = ParseRisk(_risk.SelectedItem as string ?? ""),
            Direction = (_dir.SelectedItem as string) switch { "Outbound" => Direction.Outbound, "Inbound" => Direction.Inbound, _ => null },
            From = hours is { } h ? DateTimeOffset.Now.AddHours(-h) : null,
            Limit = 5000,
        };
    }

    private async void Query()
    {
        _status.Text = "Querying…";
        var f = BuildFilter();
        var list = await Task.Run(() => Host.Database.QueryEvents(f));
        _rows.Clear();
        foreach (var e in list) _rows.Add(new TimelineRow { E = e, Minute = e.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm") });
        _status.Text = $"{list.Count} events{(list.Count >= f.Limit ? " (limit reached; narrow the filter)" : "")}";
    }

    private void Export()
    {
        var events = _rows.Select(r => r.E).ToList();
        Reports.SaveText("Export timeline", $"timeline-{DateTime.Now:yyyyMMdd-HHmmss}", "CSV (*.csv)|*.csv|JSON (*.json)|*.json",
            ext => ext == ".json" ? Exporter.ToJson(events) : Exporter.ConnectionsCsv(events));
    }
}
