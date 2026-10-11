using System.Collections;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Markup;
using NetHunter.Core.Export;
using NetHunter.Core.Models;
using NetHunter.Windows;

namespace NetHunter.App.Ui;

public static class Grids
{
    public static DataGrid Create(IEnumerable? items = null)
    {
        var g = new DataGrid { ItemsSource = items };
        VirtualizingPanel.SetIsVirtualizing(g, true);
        return g;
    }

    public static DataGrid Text(this DataGrid g, string header, string path, double width = 120, IValueConverter? conv = null, bool mono = false, string? fallback = null)
    {
        var b = new Binding(path) { Converter = conv, Mode = BindingMode.OneWay };
        if (fallback is not null) { b.TargetNullValue = fallback; b.FallbackValue = fallback; }
        var col = new DataGridTextColumn { Header = header, Binding = b, Width = width <= 0 ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(width) };
        if (mono)
        {
            var st = new Style(typeof(TextBlock));
            st.Setters.Add(new Setter(TextBlock.FontFamilyProperty, Application.Current.Resources["Mono"]));
            col.ElementStyle = st;
        }
        g.Columns.Add(col);
        return g;
    }

    public static DataGrid Risk(this DataGrid g, string header = "Risk", string path = "Level", double width = 115)
    {
        var xaml = $"""
            <DataTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
              <ContentControl Content="{"{"}Binding {path}{"}"}" ContentTemplate="{"{"}StaticResource RiskBadge{"}"}" Focusable="False"/>
            </DataTemplate>
            """;
        g.Columns.Add(new DataGridTemplateColumn
        {
            Header = header, Width = new DataGridLength(width), SortMemberPath = path,
            CellTemplate = (DataTemplate)XamlReader.Parse(xaml),
        });
        return g;
    }

    public static IValueConverter Conv(string key) => (IValueConverter)Application.Current.Resources[key];
}

public static class Reports
{
    /// <summary>Exports alerts + flows as HTML report, JSON or CSV (chosen via the save dialog).</summary>
    public static void SaveInvestigation(AppHost host, IReadOnlyList<AlertRecord> alerts, IReadOnlyList<FlowRecord> flows)
    {
        var path = Ux.SaveFile("Export investigation", $"investigation-{DateTime.Now:yyyyMMdd-HHmmss}",
            "HTML report (*.html)|*.html|JSON (*.json)|*.json|CSV - alerts (*.csv)|*.csv");
        if (path is null) return;
        var ext = Path.GetExtension(path).ToLowerInvariant();
        string content = ext switch
        {
            ".json" => Exporter.ToJson(new
            {
                Host = Environment.MachineName, Generated = DateTimeOffset.Now, Alerts = alerts,
                Flows = flows.Select(f => new
                {
                    f.ProcessName, f.LastPid, f.ProcessPath, f.Sha256, f.Direction, f.Protocol, f.RemoteIp, f.RemotePort, f.Hostname, f.Ptr, f.Sni,
                    f.FirstSeen, f.LastSeen, f.Count, f.Assessment.Level, f.Assessment.Score, f.Assessment.Confidence, f.Assessment.Classification, f.Assessment.Evidence, f.IsSynthetic,
                }),
            }),
            ".csv" => alerts.Count > 0 ? Exporter.AlertsCsv(alerts) : Exporter.FlowsCsv(flows),
            _ => Exporter.HtmlReport(Environment.MachineName, alerts, flows, a => Reputations(host, a)),
        };
        File.WriteAllText(path, content);
        host.LogFile.Write($"Exported investigation to {path}");
        Ux.RevealFile(path);
    }

    public static IEnumerable<ReputationResult> Reputations(AppHost host, AlertRecord a)
    {
        var list = new List<ReputationResult>();
        if (a.RemoteIp is not null) list.AddRange(host.Engine.GetReputation(IocType.Ip, a.RemoteIp));
        if (a.Hostname is not null) list.AddRange(host.Engine.GetReputation(IocType.Domain, a.Hostname));
        if (a.Sha256 is not null) list.AddRange(host.Engine.GetReputation(IocType.Sha256, a.Sha256));
        return list;
    }

    public static void SaveText(string title, string defaultName, string filter, Func<string, string> contentForPath)
    {
        var path = Ux.SaveFile(title, defaultName, filter);
        if (path is null) return;
        File.WriteAllText(path, contentForPath(Path.GetExtension(path).ToLowerInvariant()));
        Ux.RevealFile(path);
    }
}

/// <summary>Base for pages hosted in the main window.</summary>
public abstract class PageBase : Grid
{
    protected PageBase(UiContext ctx) { Ctx = ctx; Margin = new Thickness(18, 14, 18, 14); }
    protected UiContext Ctx { get; }
    protected AppHost Host => Ctx.Host;
    protected LiveStore Store => Ctx.Store;
    public abstract string Title { get; }
    public virtual void OnShown(object? argument) { }

    protected static Grid TwoPane(UIElement left, UIElement right, double rightWidth = 430)
    {
        var g = new Grid();
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star), MinWidth = 300 });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(6) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(rightWidth), MinWidth = 280 });
        Grid.SetColumn(left, 0);
        var splitter = new GridSplitter { Width = 6, HorizontalAlignment = HorizontalAlignment.Stretch, Background = System.Windows.Media.Brushes.Transparent };
        Grid.SetColumn(splitter, 1);
        var card = new Border { Style = Ux.S("Card"), Child = right, Padding = new Thickness(12, 10, 4, 10) };
        Grid.SetColumn(card, 2);
        g.Children.Add(left);
        g.Children.Add(splitter);
        g.Children.Add(card);
        return g;
    }

    protected void Layout(UIElement header, UIElement body)
    {
        RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        SetRow(header, 0);
        SetRow(body, 1);
        Children.Add(header);
        Children.Add(body);
    }

    protected static StackPanel Toolbar(params UIElement[] items)
    {
        var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
        foreach (var i in items) sp.Children.Add(i);
        return sp;
    }

    protected static FrameworkElement SearchBox(string placeholder, Action<string> onChanged, double width = 260)
    {
        var tb = new TextBox { Width = width, Height = 30, ToolTip = placeholder };
        var hint = new TextBlock { Text = placeholder, Style = Ux.S("Muted"), IsHitTestVisible = false, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(9, 0, 0, 0) };
        var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        timer.Tick += (_, _) => { timer.Stop(); onChanged(tb.Text); };
        tb.TextChanged += (_, _) =>
        {
            hint.Visibility = tb.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
            timer.Stop(); timer.Start(); // debounce
        };
        var g = new Grid { Margin = new Thickness(0, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center };
        g.Children.Add(tb);
        g.Children.Add(hint);
        return g;
    }

    protected static ComboBox Combo(IEnumerable<string> items, int selected, Action<string> onChanged)
    {
        var cb = new ComboBox { ItemsSource = items.ToList(), SelectedIndex = selected, Margin = new Thickness(0, 0, 8, 0) };
        cb.SelectionChanged += (_, _) => { if (cb.SelectedItem is string s) onChanged(s); };
        return cb;
    }

    protected static TextBlock Label(string text) => new() { Text = text, Style = Ux.S("Muted"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) };

    protected static RiskLevel? ParseRisk(string s) => s switch
    {
        "Suspicious+" => RiskLevel.Medium, "High+" => RiskLevel.High, "Critical" => RiskLevel.Critical, _ => null,
    };
}

public sealed class UiContext
{
    public required AppHost Host { get; init; }
    public required LiveStore Store { get; init; }
    public required Action<string, object?> Navigate { get; init; }
}
