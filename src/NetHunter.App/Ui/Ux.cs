using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using NetHunter.Core.Models;

namespace NetHunter.App.Ui;

/// <summary>Small helpers for building consistent detail panels in code. All text is set as plain text (never markup).</summary>
public static class Ux
{
    public static Style S(string key) => (Style)Application.Current.Resources[key];
    public static Brush B(string key) => (Brush)Application.Current.Resources[key];

    public static TextBlock Heading(string text, string style = "H2") => new() { Text = text, Style = S(style), TextWrapping = TextWrapping.Wrap };

    public static TextBlock Muted(string text) => new() { Text = text, Style = S("Muted"), TextWrapping = TextWrapping.Wrap, TextTrimming = TextTrimming.None };

    public static TextBlock Text(string text, bool wrap = true) => new() { Text = text, TextWrapping = wrap ? TextWrapping.Wrap : TextWrapping.NoWrap, TextTrimming = wrap ? TextTrimming.None : TextTrimming.CharacterEllipsis };

    /// <summary>Label + selectable value (so analysts can copy hashes, paths, IPs).</summary>
    public static StackPanel Field(string label, string? value, string unknown = "Unknown")
    {
        var sp = new StackPanel();
        sp.Children.Add(new TextBlock { Text = label, Style = S("Label") });
        sp.Children.Add(new TextBox { Text = string.IsNullOrWhiteSpace(value) ? unknown : value, Style = S("Value") });
        return sp;
    }

    public static Border Badge(RiskLevel level)
    {
        return new Border
        {
            Background = RiskColors.Background(level), CornerRadius = new CornerRadius(9), Padding = new Thickness(8, 2, 8, 2),
            HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock { Text = $"{level.Glyph()} {level.Label()}", Foreground = RiskColors.Foreground(level), FontWeight = FontWeights.SemiBold, FontSize = 12 },
        };
    }

    public static TextBlock Arrow() => new() { Text = "↓", FontSize = 16, Foreground = B("MutedBrush"), Margin = new Thickness(6, 2, 0, 2) };

    public static Border Section(UIElement content, Thickness? margin = null) => new()
    {
        Background = B("Panel2"), BorderBrush = B("Border"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6),
        Padding = new Thickness(10, 6, 10, 8), Margin = margin ?? new Thickness(0, 0, 0, 2), Child = content,
    };

    public static Button Button(string text, Action onClick, string? style = null, string? tooltip = null)
    {
        var b = new Button { Content = text, Margin = new Thickness(0, 4, 6, 0), ToolTip = tooltip };
        if (style is not null) b.Style = S(style);
        b.Click += (_, _) =>
        {
            try { onClick(); }
            catch (Exception ex) { Error("Action failed", ex.Message); }
        };
        return b;
    }

    public static WrapPanel Buttons(params Button[] buttons)
    {
        var wp = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
        foreach (var b in buttons) wp.Children.Add(b);
        return wp;
    }

    public static UIElement EvidenceList(IEnumerable<Evidence> evidence)
    {
        var sp = new StackPanel();
        var list = evidence.ToList();
        if (list.Count == 0) { sp.Children.Add(Muted("No suspicious signals were found.")); return sp; }
        foreach (var e in list)
        {
            var row = new DockPanel { Margin = new Thickness(0, 2, 0, 2) };
            var mark = new TextBlock
            {
                Text = e.Strength < 0 ? "−" : e.Strength >= 0.1 ? "✓" : "·", Width = 18, FontWeight = FontWeights.Bold,
                Foreground = e.Strength < 0 ? RiskColors.LowFg : e.Strength >= 0.5 ? RiskColors.CriticalFg : e.Strength >= 0.2 ? RiskColors.HighFg : e.Strength >= 0.1 ? RiskColors.MediumFg : B("MutedBrush"),
            };
            DockPanel.SetDock(mark, Dock.Left);
            row.Children.Add(mark);
            var tag = new TextBlock { Text = $"{e.Category} {e.Points:+0;-0;0}", Style = S("Muted"), Margin = new Thickness(8, 0, 0, 0) };
            DockPanel.SetDock(tag, Dock.Right);
            row.Children.Add(tag);
            row.Children.Add(new TextBlock { Text = e.Text, TextWrapping = TextWrapping.Wrap, TextTrimming = TextTrimming.None });
            sp.Children.Add(row);
        }
        return sp;
    }

    public static string? SaveFile(string title, string defaultName, string filter)
    {
        var dlg = new SaveFileDialog { Title = title, FileName = defaultName, Filter = filter, AddExtension = true };
        return dlg.ShowDialog() == true ? dlg.FileName : null;
    }

    public static string? OpenFile(string title, string filter)
    {
        var dlg = new OpenFileDialog { Title = title, Filter = filter, CheckFileExists = true };
        return dlg.ShowDialog() == true ? dlg.FileName : null;
    }

    public static void Info(string title, string message) => MessageBox.Show(Application.Current.MainWindow, message, title, MessageBoxButton.OK, MessageBoxImage.Information);
    public static void Error(string title, string message) => MessageBox.Show(Application.Current.MainWindow, message, title, MessageBoxButton.OK, MessageBoxImage.Error);
    public static bool Confirm(string title, string message, MessageBoxImage icon = MessageBoxImage.Warning) =>
        MessageBox.Show(Application.Current.MainWindow, message, title, MessageBoxButton.YesNo, icon, MessageBoxResult.No) == MessageBoxResult.Yes;

    /// <summary>Opens a folder in Explorer. Paths are passed as a single argument (no shell string building).</summary>
    public static void OpenFolder(string path)
    {
        if (!Directory.Exists(path)) Directory.CreateDirectory(path);
        Process.Start(new ProcessStartInfo { FileName = "explorer.exe", ArgumentList = { path }, UseShellExecute = false });
    }

    /// <summary>Highlights a file in Explorer.</summary>
    public static void RevealFile(string path)
    {
        if (!File.Exists(path)) { Error("File not found", path); return; }
        Process.Start(new ProcessStartInfo { FileName = "explorer.exe", ArgumentList = { "/select," + path }, UseShellExecute = false });
    }
}
