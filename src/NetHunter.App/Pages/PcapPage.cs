using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using NetHunter.App.Ui;
using NetHunter.Core.Models;
using NetHunter.Core.Pcap;
using NetHunter.Windows;

namespace NetHunter.App.Pages;

/// <summary>
/// Optional offline investigation: load a .pcap/.pcapng and run the same IOC/reputation/behaviour pipeline on it.
/// Results go to a separate database under database\pcap\ so they never mix with live monitoring data.
/// </summary>
public sealed class PcapPage : PageBase
{
    private readonly ObservableCollection<FlowRow> _flows = new();
    private readonly ObservableCollection<AlertRow> _alerts = new();
    private readonly TextBlock _summary = new() { TextWrapping = TextWrapping.Wrap, TextTrimming = TextTrimming.None, Margin = new Thickness(0, 0, 0, 8) };
    private readonly ContentControl _detailHost = new();
    private AppHost? _pcapHost;

    public PcapPage(UiContext ctx) : base(ctx)
    {
        var flows = Grids.Create(_flows)
            .Text("Initiator → responder", "RemoteIp", 170, mono: true)
            .Text("Hostname / SNI", "Hostname", 220, fallback: "Unknown")
            .Text("Port", "RemotePort", 55)
            .Text("Proto", "Protocol", 50)
            .Text("Dir", "Direction", 62, Grids.Conv("Dir"))
            .Text("Count", "Count", 55)
            .Risk()
            .Text("Detection", "Classification", 0, Grids.Conv("Detection"));
        flows.SelectionChanged += (_, _) =>
        {
            if (flows.SelectedItem is FlowRow r && _pcapHost is not null)
            {
                var v = new FlowDetailView(_pcapHost);
                v.Show(r.Flow);
                _detailHost.Content = v;
            }
        };
        var alerts = Grids.Create(_alerts)
            .Risk("Severity", "Severity")
            .Text("Detection", "Title", 0)
            .Text("Destination", "Destination", 180, mono: true);
        alerts.MaxHeight = 180;
        alerts.Margin = new Thickness(0, 0, 0, 8);

        var left = new Grid();
        left.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        left.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        left.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        Grid.SetRow(_summary, 0); left.Children.Add(_summary);
        Grid.SetRow(alerts, 1); left.Children.Add(alerts);
        Grid.SetRow(flows, 2); left.Children.Add(flows);
        _detailHost.Content = Ux.Muted("Open a capture file. Process attribution is not possible from packets, so every flow shows Process: Unknown. " +
            "TLS SNI and HTTP Host headers are extracted when present and shown as the hostname.");

        var toolbar = Toolbar(
            Ux.Button("Open capture…", Open, "Primary"),
            Ux.Button("Refresh results", Refresh, tooltip: "Reputation lookups finish in the background; refresh to see re-scored flows"),
            Ux.Button("Export report…", () => { if (_pcapHost is not null) Reports.SaveInvestigation(_pcapHost, _alerts.Select(a => a.Alert).ToList(), _flows.Select(f => f.Flow).ToList()); }),
            Ux.Button("Open PCAP results folder", () => Ux.OpenFolder(Path.Combine(Host.Root, "database", "pcap"))));
        Layout(toolbar, TwoPane(left, _detailHost));
    }

    public override string Title => "PCAP Investigation";

    private async void Open()
    {
        var file = Ux.OpenFile("Open packet capture", "Packet captures (*.pcap;*.pcapng;*.cap)|*.pcap;*.pcapng;*.cap|All files (*.*)|*.*");
        if (file is null) return;
        if (_pcapHost is not null) { await _pcapHost.DisposeAsync(); _pcapHost = null; }
        _flows.Clear();
        _alerts.Clear();
        _summary.Text = $"Analyzing {Path.GetFileName(file)}…";
        try
        {
            var name = string.Concat(Path.GetFileNameWithoutExtension(file).Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_'));
            var host = AppHost.Create(HostMode.Pcap, Host.Root, Path.Combine("pcap", $"{name}-{DateTime.Now:yyyyMMdd-HHmmss}.db"));
            _pcapHost = host;
            host.Engine.StartPipeline();
            var summary = await Task.Run(() => PcapAnalyzer.Analyze(file, host.Engine.Post, host.Reputation.LocalDb));
            await host.Engine.DrainAsync(TimeSpan.FromMinutes(2));
            var span = summary.Start is { } s && summary.End is { } e ? $"{s.ToLocalTime():yyyy-MM-dd HH:mm:ss} → {e.ToLocalTime():HH:mm:ss}" : "no timestamps";
            _summary.Text = $"{summary.File}: {summary.Packets:N0} packets ({summary.Decoded:N0} decoded), {span}. {summary.Connections} connections, {summary.DnsMessages} DNS messages, " +
                $"{summary.TlsSni} TLS SNI, {summary.HttpRequests} HTTP requests. {host.Reputation.StatusText}." +
                (summary.UrlIocMatches.Count > 0 ? "\nURL IOC matches: " + string.Join("; ", summary.UrlIocMatches) : "") +
                (summary.Warnings.Count > 0 ? "\nWarnings: " + string.Join("; ", summary.Warnings) : "");
            host.LogFile.Write($"PCAP analyzed: {file}");
            Refresh();
        }
        catch (Exception ex)
        {
            _summary.Text = "Could not analyze the capture: " + ex.Message;
        }
    }

    private void Refresh()
    {
        if (_pcapHost is null) return;
        _flows.Clear();
        foreach (var f in _pcapHost.Engine.SnapshotFlows().OrderByDescending(f => f.Assessment.Score).ThenByDescending(f => f.Count)) _flows.Add(new FlowRow(f));
        _alerts.Clear();
        foreach (var a in _pcapHost.Database.GetAlerts()) _alerts.Add(new AlertRow(a));
    }
}
