using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using NetHunter.App.Ui;
using NetHunter.Core.Models;
using NetHunter.Windows;

namespace NetHunter.App;

public partial class App : Application
{
    private const string MutexName = @"Local\NetHunterMonitor.SingleInstance";
    private static Mutex? _mutex;
    private AppHost? _host;
    private TrayNotifier? _tray;
    private static bool _restarting;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUiException;
        AppDomain.CurrentDomain.UnhandledException += (_, ex) => _host?.LogFile.Write("Unhandled: " + ex.ExceptionObject);
        TaskScheduler.UnobservedTaskException += (_, ex) => { _host?.LogFile.Write("Unobserved task exception: " + ex.Exception); ex.SetObserved(); };

        bool synthetic = e.Args.Any(a => a.Equals("--synthetic", StringComparison.OrdinalIgnoreCase));
        // A restart passes --wait so the new instance can take over the single-instance lock cleanly.
        _mutex = new Mutex(true, MutexName, out bool first);
        if (!first && e.Args.Contains("--wait"))
        {
            try { first = _mutex.WaitOne(TimeSpan.FromSeconds(15)); }
            catch (AbandonedMutexException) { first = true; } // previous instance exited without releasing
        }
        if (!first)
        {
            MessageBox.Show("NetHunter Monitor is already running (check the notification area).", "NetHunter Monitor", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        try
        {
            _host = AppHost.Create(synthetic ? HostMode.Synthetic : HostMode.Live);
        }
        catch (Exception ex)
        {
            MessageBox.Show("NetHunter Monitor could not start:\n\n" + ex.Message, "NetHunter Monitor", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        var window = new MainWindow(_host);
        MainWindow = window;
        _tray = new TrayNotifier(window, _host);
        window.Store.Notify += a => _tray.Notify(a);
        window.Show();
        _host.Engine.StartPipeline();
        _host.Engine.StartMonitoring();
    }

    private void OnUiException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        _host?.LogFile.Write("UI error: " + e.Exception);
        MessageBox.Show("An unexpected error occurred. Monitoring continues; details were written to the log.\n\n" + e.Exception.Message,
            "NetHunter Monitor", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        if (_host is not null)
        {
            try { _host.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(10)); }
            catch (Exception) { /* exiting anyway */ }
        }
        if (_mutex is not null)
        {
            try { _mutex.ReleaseMutex(); } catch (ApplicationException) { }
            _mutex.Dispose();
        }
        base.OnExit(e);
    }

    /// <summary>Relaunches through UAC ("runas"). The user approves elevation; nothing is bypassed.</summary>
    public static bool TryStartElevated(bool synthetic)
    {
        try
        {
            var psi = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" };
            psi.ArgumentList.Add("--wait");
            if (synthetic) psi.ArgumentList.Add("--synthetic");
            Process.Start(psi);
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false; // user declined the UAC prompt
        }
    }

    public static void Restart(bool synthetic)
    {
        if (_restarting) return;
        _restarting = true;
        var psi = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
        psi.ArgumentList.Add("--wait");
        if (synthetic) psi.ArgumentList.Add("--synthetic");
        Process.Start(psi);
        Current.Shutdown();
    }
}

/// <summary>Notification-area icon with balloon alerts (can be disabled in Settings).</summary>
public sealed class TrayNotifier : IDisposable
{
    private readonly System.Windows.Forms.NotifyIcon _icon;
    private readonly AppHost _host;
    private readonly Window _window;
    private DateTime _lastBalloon = DateTime.MinValue;

    public TrayNotifier(Window window, AppHost host)
    {
        _window = window;
        _host = host;
        System.Drawing.Icon? ico = null;
        try
        {
            var res = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/NetHunter.ico"));
            if (res is not null) ico = new System.Drawing.Icon(res.Stream);
        }
        catch (Exception) { }
        _icon = new System.Windows.Forms.NotifyIcon { Icon = ico ?? System.Drawing.SystemIcons.Shield, Text = "NetHunter Monitor", Visible = true };
        _icon.DoubleClick += (_, _) => Show();
        _icon.BalloonTipClicked += (_, _) => { Show(); ((MainWindow)_window).Navigate("Alerts", null); };
        var menu = new System.Windows.Forms.ContextMenuStrip();
        menu.Items.Add("Open", null, (_, _) => Show());
        menu.Items.Add("Exit", null, (_, _) => Application.Current.Shutdown());
        _icon.ContextMenuStrip = menu;
    }

    private void Show()
    {
        _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    public void Notify(AlertRecord a)
    {
        if (!_host.Settings.NotificationsEnabled) return;
        if (DateTime.UtcNow - _lastBalloon < TimeSpan.FromSeconds(5)) return; // avoid notification storms
        _lastBalloon = DateTime.UtcNow;
        var text = $"{a.Title}\n{a.ProcessName} → {a.Hostname ?? a.RemoteIp}{(a.RemotePort is null ? "" : ":" + a.RemotePort)}\nScore {a.Score}, confidence {a.Confidence}%";
        _icon.ShowBalloonTip(8000, $"{a.Severity.Label()} alert{(a.IsSynthetic ? " (synthetic)" : "")}", text.Length > 250 ? text[..250] : text,
            a.Severity >= RiskLevel.High ? System.Windows.Forms.ToolTipIcon.Warning : System.Windows.Forms.ToolTipIcon.Info);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
