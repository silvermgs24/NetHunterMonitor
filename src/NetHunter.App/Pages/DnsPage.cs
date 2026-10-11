using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using NetHunter.App.Ui;
using NetHunter.Core.Export;
using NetHunter.Core.Models;

namespace NetHunter.App.Pages;

/// <summary>DNS activity and suspicious DNS behaviour (tunnelling, DGA-like names, churn).</summary>
public sealed class DnsPage : PageBase
{
    private readonly ICollectionView _view;
    private readonly TextBlock _sources = new() { Style = Ux.S("Muted"), TextWrapping = TextWrapping.Wrap, TextTrimming = TextTrimming.None, Margin = new Thickness(0, 0, 0, 8) };
    private string _text = "";
    private bool _onlySuspicious;

    public DnsPage(UiContext ctx) : base(ctx)
    {
        _view = new CollectionViewSource { Source = Store.Dns }.View;
        _view.Filter = o => o is DnsEventRecord d && (!_onlySuspicious || d.Level >= RiskLevel.Medium || d.Notes.Length > 0) &&
            (_text.Length == 0 || d.Query.Contains(_text, StringComparison.OrdinalIgnoreCase) || d.Answers.Contains(_text, StringComparison.OrdinalIgnoreCase) || (d.ProcessName?.Contains(_text, StringComparison.OrdinalIgnoreCase) ?? false));
        var grid = Grids.Create(_view)
            .Text("Time", "Timestamp", 72, Grids.Conv("Time"))
            .Text("Process", "ProcessName", 130, fallback: "Unknown")
            .Text("Query", "Query", 260, mono: true)
            .Text("Type", "RecordType", 55)
            .Text("Response", "Answers", 260)
            .Text("Status", "Status", 55)
            .Text("Source", "Source", 85)
            .Risk()
            .Text("Notes", "Notes", 0);
        var only = new CheckBox { Content = "Only suspicious", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0) };
        only.Click += (_, _) => { _onlySuspicious = only.IsChecked == true; _view.Refresh(); };
        var header = new StackPanel();
        header.Children.Add(Toolbar(SearchBox("Filter by query, answer or process", t => { _text = t.Trim(); _view.Refresh(); }), only,
            Ux.Button("Export…", () => Reports.SaveText("Export DNS", $"dns-{DateTime.Now:yyyyMMdd-HHmmss}", "CSV (*.csv)|*.csv|JSON (*.json)|*.json",
                ext => ext == ".json" ? Exporter.ToJson(_view.Cast<DnsEventRecord>().ToList()) : Exporter.ToCsv(_view.Cast<DnsEventRecord>(),
                    ("Time", d => d.Timestamp), ("Process", d => d.ProcessName), ("PID", d => d.Pid), ("Query", d => d.Query), ("Type", d => d.RecordType),
                    ("Status", d => d.Status), ("Answers", d => d.Answers), ("Source", d => d.Source), ("Risk", d => d.Level), ("Notes", d => d.Notes))))));
        header.Children.Add(_sources);
        Layout(header, grid);
    }

    public override string Title => "DNS";

    public override void OnShown(object? argument)
    {
        var running = Host.Engine.Sources.Where(s => s.Running && s.Name.Contains("DNS")).Select(s => s.Name).ToList();
        _sources.Text = running.Count == 0
            ? "No DNS source is running. Start monitoring to collect DNS activity."
            : $"DNS sources: {string.Join(", ", running)}. " + (running.Any(r => r.StartsWith("ETW"))
                ? "Real-time queries with requesting process where Windows records it."
                : "Without administrator rights DNS comes from the Windows DNS cache: no per-process attribution, and very short-lived entries can be missed. Run as administrator for real-time ETW DNS.");
    }
}
