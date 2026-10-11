using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using NetHunter.App.Ui;
using NetHunter.Core.Models;
using NetHunter.Core.Storage;

namespace NetHunter.App.Pages;

/// <summary>Global search: IP, process, domain, SHA-256 or port across connections, flows, DNS and alerts.</summary>
public sealed class SearchPage : PageBase
{
    private readonly ObservableCollection<ConnectionEvent> _events = new();
    private readonly ObservableCollection<FlowRow> _flows = new();
    private readonly ObservableCollection<DnsEventRecord> _dns = new();
    private readonly ObservableCollection<AlertRow> _alerts = new();
    private readonly TextBlock _title = new() { Style = Ux.S("H1") };
    private readonly TabControl _tabs = new() { Background = Ux.B("Panel"), BorderBrush = Ux.B("Border") };

    public SearchPage(UiContext ctx) : base(ctx)
    {
        var flows = Grids.Create(_flows)
            .Text("Process", "ProcessName", 150).Text("Remote IP", "RemoteIp", 160, mono: true).Text("Hostname", "Hostname", 200, fallback: "Unknown")
            .Text("Port", "RemotePort", 55).Text("Count", "Count", 60).Risk().Text("Last seen", "LastSeen", 130, Grids.Conv("DateTime"));
        flows.MouseDoubleClick += (_, _) => { if (flows.SelectedItem is FlowRow r) Ctx.Navigate("Connections", r.Key); };
        var events = Grids.Create(_events)
            .Text("Time", "Timestamp", 130, Grids.Conv("DateTime")).Text("Dir", "Direction", 62, Grids.Conv("Dir")).Text("Process", "ProcessName", 140)
            .Text("Remote IP", "RemoteIp", 160, mono: true).Text("Hostname", "Hostname", 180, fallback: "Unknown").Text("Port", "RemotePort", 55).Risk();
        events.MouseDoubleClick += (_, _) => { if (events.SelectedItem is ConnectionEvent e) Ctx.Navigate("Connections", e.FlowKey); };
        var dns = Grids.Create(_dns)
            .Text("Time", "Timestamp", 130, Grids.Conv("DateTime")).Text("Process", "ProcessName", 130, fallback: "Unknown").Text("Query", "Query", 260, mono: true)
            .Text("Response", "Answers", 0).Risk();
        var alerts = Grids.Create(_alerts)
            .Text("Updated", "Updated", 130, Grids.Conv("DateTime")).Risk("Severity", "Severity").Text("Detection", "Title", 0).Text("Process", "ProcessName", 140)
            .Text("Destination", "Destination", 170, mono: true);
        alerts.MouseDoubleClick += (_, _) => { if (alerts.SelectedItem is AlertRow a) Ctx.Navigate("Alerts", a); };
        foreach (var (h, c) in new (string, UIElement)[] { ("Flows", flows), ("Connection events", events), ("DNS", dns), ("Alerts", alerts) })
            _tabs.Items.Add(new TabItem { Header = h, Content = c });
        Layout(_title, _tabs);
    }

    public override string Title => "Search";

    public override async void OnShown(object? argument)
    {
        var q = (argument as string ?? "").Trim();
        _title.Text = q.Length == 0 ? "Search" : $"Results for \"{q}\"";
        _events.Clear(); _flows.Clear(); _dns.Clear(); _alerts.Clear();
        if (q.Length == 0) return;

        foreach (var f in Store.Flows.Where(f => Matches(f, q)).OrderByDescending(f => f.LastSeen)) _flows.Add(f);
        foreach (var a in Store.Alerts.Where(a => Contains(a.ProcessName, q) || Contains(a.Destination, q) || Contains(a.Hostname, q) || Contains(a.Alert.Sha256, q) || Contains(a.Alert.ProcessPath, q) || Contains(a.Title, q)))
            _alerts.Add(a);
        var host = Host;
        var (events, dnsRows) = await Task.Run(() => (host.Database.QueryEvents(new EventFilter { Text = q, Limit = 3000 }), host.Database.QueryDns(q, 3000)));
        foreach (var e in events) _events.Add(e);
        foreach (var d in dnsRows) _dns.Add(d);
        ((TabItem)_tabs.Items[0]).Header = $"Flows ({_flows.Count})";
        ((TabItem)_tabs.Items[1]).Header = $"Connection events ({_events.Count})";
        ((TabItem)_tabs.Items[2]).Header = $"DNS ({_dns.Count})";
        ((TabItem)_tabs.Items[3]).Header = $"Alerts ({_alerts.Count})";
    }

    private static bool Contains(string? s, string q) => s?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false;

    private static bool Matches(FlowRow f, string q) =>
        Contains(f.ProcessName, q) || Contains(f.RemoteIp, q) || Contains(f.Hostname, q) || Contains(f.Ptr, q) || Contains(f.ProcessPath, q) ||
        Contains(f.Flow.Sha256, q) || f.RemotePort.ToString() == q;
}
