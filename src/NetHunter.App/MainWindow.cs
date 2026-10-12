using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using NetHunter.App.Pages;
using NetHunter.App.Ui;
using NetHunter.Windows;

namespace NetHunter.App;

/// <summary>Shell: navigation, global search, start/stop, privilege and mode banners, status bar.</summary>
public sealed class MainWindow : Window
{
    private readonly AppHost _host;
    private readonly LiveStore _store;
    private readonly UiContext _ctx;
    private readonly Dictionary<string, Func<PageBase>> _factories;
    private readonly Dictionary<string, PageBase> _pages = new();
    private readonly ListBox _nav = new() { Style = Ux.S("Nav") };
    private readonly ContentControl _content = new();
    private readonly Button _startStop = new() { MinWidth = 150 };
    private readonly TextBlock _statusLeft = new() { Style = Ux.S("Muted") };
    private readonly TextBlock _statusRight = new() { Style = Ux.S("Muted"), HorizontalAlignment = HorizontalAlignment.Right };
    private readonly TextBlock _monitorState = new() { FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 14, 0) };
    private readonly Border _intelBanner;
    private readonly TextBlock _intelBannerText = new() { TextWrapping = TextWrapping.Wrap };
    private readonly ListBoxItem _alertsNav;
    private bool _suppressNav;

    public MainWindow(AppHost host)
    {
        _host = host;
        Title = "NetHunter Monitor" + (host.Mode == HostMode.Synthetic ? " — SYNTHETIC TEST MODE" : "") + (host.IsElevated ? " (Administrator)" : "");
        Width = 1500; Height = 900; MinWidth = 1000; MinHeight = 600;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = Ux.B("Bg");
        Foreground = Ux.B("Text");
        FontFamily = new FontFamily("Segoe UI");
        FontSize = 13;
        try { Icon = BitmapFrame.Create(new Uri("pack://application:,,,/Assets/NetHunter.ico")); } catch (Exception) { /* icon is cosmetic */ }

        ReputationColumns.Host = host;
        _store = new LiveStore(host, Dispatcher);
        _ctx = new UiContext { Host = host, Store = _store, Navigate = Navigate };
        _factories = new()
        {
            ["Dashboard"] = () => new DashboardPage(_ctx),
            ["Connections"] = () => new ConnectionsPage(_ctx),
            ["Processes"] = () => new ProcessesPage(_ctx),
            ["IOC"] = () => new IocPage(_ctx),
            ["Alerts"] = () => new AlertsPage(_ctx),
            ["DNS"] = () => new DnsPage(_ctx),
            ["Listening Ports"] = () => new ListeningPage(_ctx),
            ["Timeline"] = () => new TimelinePage(_ctx),
            ["PCAP"] = () => new PcapPage(_ctx),
            ["Settings"] = () => new SettingsPage(_ctx),
            ["Search"] = () => new SearchPage(_ctx),
        };

        var root = new DockPanel();

        // ── Banners
        var banners = new StackPanel();
        if (host.Mode == HostMode.Synthetic)
            banners.Children.Add(Banner("SYNTHETIC TEST MODE: all events are generated test data (RFC 5737 addresses, .example domains), not real traffic. Stored separately; never sent to reputation providers.",
                "SynthBg", Ux.Button("Return to live monitoring", () => App.Restart(false))));
        if (!host.IsElevated && host.Mode == HostMode.Live)
            banners.Children.Add(Banner("Running without administrator rights. Working: TCP connections with process attribution (polling), DNS cache, listening ports, IOC & reputation checks, " +
                "beacon detection. Needs administrator: real-time capture of very short connections and UDP peers (ETW), DNS queries per process, and path/hash of SYSTEM processes.",
                "WarnBg", Ux.Button("Restart as administrator", RestartElevated, "Primary")));
        _intelBanner = Banner("", "WarnBg");
        ((DockPanel)_intelBanner.Child).Children.Add(_intelBannerText);
        _intelBanner.Visibility = Visibility.Collapsed;
        banners.Children.Add(_intelBanner);
        DockPanel.SetDock(banners, Dock.Top);
        root.Children.Add(banners);

        // ── Top bar
        var top = new DockPanel { Background = Ux.B("Panel"), Height = 54 };
        var brand = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(16, 0, 0, 0), Width = 196 };
        brand.Children.Add(new TextBlock { Text = "◉", FontSize = 20, Foreground = Ux.B("Accent"), Margin = new Thickness(0, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center });
        brand.Children.Add(new TextBlock { Text = "NetHunter Monitor", FontSize = 15, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center });
        DockPanel.SetDock(brand, Dock.Left);
        top.Children.Add(brand);
        var right = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) };
        right.Children.Add(_monitorState);
        _startStop.Click += (_, _) => ToggleMonitoring();
        right.Children.Add(_startStop);
        DockPanel.SetDock(right, Dock.Right);
        top.Children.Add(right);
        var search = new TextBox { Width = 460, Height = 32, HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0, 0, 0),
            ToolTip = "Search everything: IP, process name, domain, SHA-256 or port (Enter)" };
        var hint = new TextBlock { Text = "Search IP, process, domain, SHA-256, port…  (Ctrl+F)", Style = Ux.S("Muted"), IsHitTestVisible = false, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(22, 0, 0, 0) };
        search.TextChanged += (_, _) => hint.Visibility = search.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        search.KeyDown += (_, e) => { if (e.Key == Key.Enter && search.Text.Trim().Length > 0) Navigate("Search", search.Text.Trim()); };
        var searchHost = new Grid();
        searchHost.Children.Add(search);
        searchHost.Children.Add(hint);
        top.Children.Add(searchHost);
        DockPanel.SetDock(top, Dock.Top);
        root.Children.Add(top);
        InputBindings.Add(new KeyBinding(new RelayCommand(() => search.Focus()), Key.F, ModifierKeys.Control));

        // ── Status bar
        var status = new DockPanel { Background = Ux.B("Panel"), Height = 26 };
        _statusLeft.Margin = new Thickness(12, 0, 0, 0);
        _statusLeft.VerticalAlignment = VerticalAlignment.Center;
        _statusRight.Margin = new Thickness(0, 0, 12, 0);
        _statusRight.VerticalAlignment = VerticalAlignment.Center;
        DockPanel.SetDock(_statusRight, Dock.Right);
        status.Children.Add(_statusRight);
        status.Children.Add(_statusLeft);
        DockPanel.SetDock(status, Dock.Bottom);
        root.Children.Add(status);

        // ── Navigation
        var navPanel = new DockPanel { Width = 212, Background = Ux.B("Panel") };
        foreach (var name in new[] { "Dashboard", "Connections", "Processes", "IOC", "Alerts", "DNS", "Listening Ports", "Timeline", "PCAP", "Settings" })
        {
            var item = new ListBoxItem { Content = name, Style = Ux.S("NavItem"), Tag = name };
            _nav.Items.Add(item);
        }
        _alertsNav = (ListBoxItem)_nav.Items[4];
        _nav.SelectionChanged += (_, _) => { if (!_suppressNav && _nav.SelectedItem is ListBoxItem li) Navigate((string)li.Tag, null); };
        var navFoot = new TextBlock
        {
            Style = Ux.S("Muted"), Margin = new Thickness(16, 0, 10, 12), TextWrapping = TextWrapping.Wrap, TextTrimming = TextTrimming.None,
            Text = $"{(host.IsElevated ? "Administrator" : "Standard user")} · {host.Mode} mode\nData: {host.Root}",
        };
        DockPanel.SetDock(navFoot, Dock.Bottom);
        navPanel.Children.Add(navFoot);
        _nav.Margin = new Thickness(0, 10, 0, 0);
        navPanel.Children.Add(_nav);
        DockPanel.SetDock(navPanel, Dock.Left);
        root.Children.Add(navPanel);

        root.Children.Add(_content);
        Content = root;

        _store.Applied += _ => UpdateStatus();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        timer.Tick += (_, _) => UpdateStatus();
        timer.Start();
        Navigate("Dashboard", null);
        UpdateStatus();
    }

    public LiveStore Store => _store;

    private static Border Banner(string text, string bgKey, Button? action = null)
    {
        var dp = new DockPanel { Margin = new Thickness(16, 6, 12, 6) };
        if (action is not null)
        {
            action.VerticalAlignment = VerticalAlignment.Center;
            DockPanel.SetDock(action, Dock.Right);
            dp.Children.Add(action);
        }
        if (text.Length > 0) dp.Children.Add(new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, TextTrimming = TextTrimming.None, VerticalAlignment = VerticalAlignment.Center });
        return new Border { Background = Ux.B(bgKey), BorderBrush = Ux.B("Border"), BorderThickness = new Thickness(0, 0, 0, 1), Child = dp };
    }

    public void Navigate(string page, object? argument)
    {
        if (!_factories.ContainsKey(page)) return;
        if (!_pages.TryGetValue(page, out var p)) _pages[page] = p = _factories[page]();
        _content.Content = p;
        _suppressNav = true;
        _nav.SelectedItem = _nav.Items.Cast<ListBoxItem>().FirstOrDefault(i => (string)i.Tag == page);
        _suppressNav = false;
        try { p.OnShown(argument); }
        catch (Exception ex) { _host.LogFile.Write($"Page {page} failed: {ex}"); Ux.Error("Error", ex.Message); }
    }

    private void ToggleMonitoring()
    {
        if (_host.Engine.IsMonitoring) _host.Engine.StopMonitoring();
        else _host.Engine.StartMonitoring();
        UpdateStatus();
    }

    private void UpdateStatus()
    {
        bool on = _host.Engine.IsMonitoring;
        _startStop.Content = on ? "■  Stop monitoring" : "▶  Start monitoring";
        _startStop.Style = on ? Ux.S("Danger") : Ux.S("Primary");
        _monitorState.Text = on ? "● Monitoring" : "○ Stopped";
        _monitorState.Foreground = on ? RiskColors.LowFg : Ux.B("MutedBrush");
        int open = _store.OpenAlerts;
        _alertsNav.Content = open > 0 ? $"Alerts  ({open})" : "Alerts";
        var intel = _host.Reputation.Status;
        _intelBanner.Visibility = intel == Core.Intel.IntelStatus.Offline ? Visibility.Visible : Visibility.Collapsed;
        _intelBannerText.Text = "Threat intelligence unavailable (no Internet or provider unreachable). Monitoring, process attribution, hashing, local IOC checks and behaviour analysis continue normally; lookups resume automatically.";
        var running = _host.Engine.Sources.Count(s => s.Running);
        _statusLeft.Text = $"{(on ? $"{running} collector(s) running" : "Monitoring stopped")} · {_store.EventsPerMinute:0} connections/min · {_store.Flows.Count:N0} flows · {open} open alerts · {_host.Reputation.StatusText}" +
            (_host.Engine.DroppedObservations > 0 ? $" · {_host.Engine.DroppedObservations} observations dropped (overload)" : "");
        _statusRight.Text = $"Started {_host.Engine.StartedAt?.ToLocalTime():HH:mm:ss} · retention {(_host.Settings.RetentionHours == 0 ? "unlimited" : _host.Settings.RetentionHours + " h")}";
    }

    private void RestartElevated()
    {
        if (App.TryStartElevated(_host.Mode == HostMode.Synthetic)) Application.Current.Shutdown();
    }
}

public sealed class RelayCommand : ICommand
{
    private readonly Action _run;
    public RelayCommand(Action run) { _run = run; }
    public event EventHandler? CanExecuteChanged { add { } remove { } }
    public bool CanExecute(object? parameter) => true;
    public void Execute(object? parameter) => _run();
}
