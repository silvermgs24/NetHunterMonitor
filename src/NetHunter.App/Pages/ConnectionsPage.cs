using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using NetHunter.App.Ui;
using NetHunter.Core.Export;
using NetHunter.Core.Models;

namespace NetHunter.App.Pages;

/// <summary>All inbound/outbound flows (process → destination) with filtering and the explain panel.</summary>
public sealed class ConnectionsPage : PageBase
{
    private readonly FlowDetailView _detail;
    private readonly ICollectionView _view;
    private readonly DataGrid _grid;
    private string _text = "";
    private RiskLevel? _min;
    private Direction? _dir;
    private string? _proto;

    public ConnectionsPage(UiContext ctx) : base(ctx)
    {
        _detail = new FlowDetailView(Host);
        _view = new CollectionViewSource { Source = Store.Flows }.View;
        _view.SortDescriptions.Add(new SortDescription(nameof(FlowRow.LastSeen), ListSortDirection.Descending));
        _view.Filter = Filter;

        _grid = Grids.Create(_view)
            .Text("Last seen", "LastSeen", 72, Grids.Conv("Time"))
            .Text("Dir", "Direction", 62, Grids.Conv("Dir"))
            .Text("Process", "ProcessName", 140)
            .Text("PID", "Pid", 56, fallback: "-")
            .Text("Remote IP", "RemoteIp", 160, mono: true)
            .Text("Hostname", "Hostname", 180, fallback: "Unknown")
            .Text("Port", "RemotePort", 54)
            .Text("Proto", "Protocol", 50)
            .Text("Count", "Count", 56)
            .Text("State", "State", 92)
            .Risk()
            .Text("Score", "Score", 48)
            .Text("Detection", "Classification", 150, Grids.Conv("Detection"))
            .Text("First seen", "FirstSeen", 130, Grids.Conv("DateTime"));
        _grid.SelectionChanged += (_, _) => { if (_grid.SelectedItem is FlowRow r) _detail.Show(r.Flow); };

        var toolbar = Toolbar(
            SearchBox("Filter by process, IP, hostname, port, hash", t => { _text = t.Trim(); _view.Refresh(); }),
            Label("Risk"), Combo(new[] { "All", "Suspicious+", "High+", "Critical" }, 0, s => { _min = ParseRisk(s); _view.Refresh(); }),
            Label("Direction"), Combo(new[] { "Both", "Outbound", "Inbound" }, 0, s => { _dir = s == "Both" ? null : Enum.Parse<Direction>(s); _view.Refresh(); }),
            Label("Protocol"), Combo(new[] { "All", "TCP", "UDP" }, 0, s => { _proto = s == "All" ? null : s; _view.Refresh(); }),
            Ux.Button("Export…", Export));
        Layout(toolbar, TwoPane(_grid, _detail));
        Store.Applied += _ => { if (_grid.SelectedItem is FlowRow r && IsVisible) _detail.Show(r.Flow); };
    }

    public override string Title => "Connections";

    public override void OnShown(object? argument)
    {
        if (argument is string flowKey && Store.FindFlow(flowKey) is { } row)
        {
            _grid.SelectedItem = row;
            _grid.ScrollIntoView(row);
            _detail.Show(row.Flow);
        }
    }

    private bool Filter(object o)
    {
        if (o is not FlowRow r) return false;
        if (_min is { } m && r.Level < m) return false;
        if (_dir is { } d && r.Direction != d) return false;
        if (_proto is not null && r.Protocol != _proto) return false;
        if (_text.Length == 0) return true;
        return r.ProcessName.Contains(_text, StringComparison.OrdinalIgnoreCase)
            || r.RemoteIp.Contains(_text, StringComparison.OrdinalIgnoreCase)
            || (r.Hostname?.Contains(_text, StringComparison.OrdinalIgnoreCase) ?? false)
            || (r.ProcessPath?.Contains(_text, StringComparison.OrdinalIgnoreCase) ?? false)
            || (r.Flow.Sha256?.Equals(_text, StringComparison.OrdinalIgnoreCase) ?? false)
            || r.RemotePort.ToString() == _text;
    }

    private void Export()
    {
        var rows = _view.Cast<FlowRow>().Select(r => r.Flow).ToList();
        Reports.SaveText("Export connections", $"connections-{DateTime.Now:yyyyMMdd-HHmmss}", "CSV (*.csv)|*.csv|JSON (*.json)|*.json",
            ext => ext == ".json" ? Exporter.ToJson(rows) : Exporter.FlowsCsv(rows));
    }
}
