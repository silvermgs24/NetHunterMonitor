using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using NetHunter.App.Ui;
using NetHunter.Core.Models;

namespace NetHunter.App.Pages;

public sealed class ListenRow
{
    public required ListeningPortRecord R { get; init; }
    public int Port => R.Port;
    public string Protocol => R.Protocol.ToString().ToUpperInvariant();
    public string Address => R.Address;
    public string Process => R.ProcessName;
    public int? Pid => R.Pid;
    public RiskLevel Level => R.Assessment.Level;
    public string Reasons => string.Join("; ", R.Assessment.Evidence.Where(e => e.Strength > 0).Select(e => e.Text));
}

/// <summary>Local listening services with owning process and risk.</summary>
public sealed class ListeningPage : PageBase
{
    private readonly ObservableCollection<ListenRow> _rows = new();
    private readonly DataGrid _grid;
    private readonly StackPanel _detail = new();
    private readonly TextBlock _status = new() { Style = Ux.S("Muted"), VerticalAlignment = VerticalAlignment.Center };

    public ListeningPage(UiContext ctx) : base(ctx)
    {
        _grid = Grids.Create(_rows)
            .Text("Port", "Port", 60)
            .Text("Proto", "Protocol", 55)
            .Text("Process", "Process", 160)
            .Text("PID", "Pid", 60, fallback: "-")
            .Text("Address", "Address", 170, mono: true)
            .Risk()
            .Text("Reasons", "Reasons", 0);
        _grid.SelectionChanged += (_, _) => ShowDetail();
        var scroll = new ScrollViewer { Content = _detail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        _detail.Children.Add(Ux.Muted("Select a listening port."));
        Layout(Toolbar(Ux.Button("Refresh", Refresh, "Primary"), _status), TwoPane(_grid, scroll, 400));
    }

    public override string Title => "Listening Ports";

    public override void OnShown(object? argument) => Refresh();

    private async void Refresh()
    {
        _status.Text = "Reading endpoint tables…";
        try
        {
            var list = await Task.Run(() => Host.Engine.GetListeningPorts());
            _rows.Clear();
            foreach (var r in list.OrderByDescending(r => r.Assessment.Score).ThenBy(r => r.Port)) _rows.Add(new ListenRow { R = r });
            _status.Text = $"{list.Count} listening endpoints · {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex) { _status.Text = "Failed: " + ex.Message; }
    }

    private void ShowDetail()
    {
        if (_grid.SelectedItem is not ListenRow r) return;
        _detail.Children.Clear();
        var head = new DockPanel();
        var b = Ux.Badge(r.Level);
        DockPanel.SetDock(b, Dock.Right);
        head.Children.Add(b);
        head.Children.Add(Ux.Heading($"{r.Protocol} port {r.Port}"));
        _detail.Children.Add(head);
        _detail.Children.Add(Ux.Field("Bound address", r.Address + (r.Address is "0.0.0.0" or "::" ? " (all interfaces)" : "")));
        _detail.Children.Add(Ux.Field("Process", $"{r.Process} (PID {r.Pid?.ToString() ?? "unknown"})"));
        _detail.Children.Add(Ux.Field("Executable", r.R.ProcessPath));
        _detail.Children.Add(Ux.Heading("Why this risk level"));
        _detail.Children.Add(Ux.EvidenceList(r.R.Assessment.Evidence));
        if (r.R.ProcessPath is { } path)
            _detail.Children.Add(Ux.Buttons(Ux.Button("Investigate process", () => Ctx.Navigate("Processes", path.ToLowerInvariant())), Ux.Button("Show file", () => Ux.RevealFile(path))));
    }
}
