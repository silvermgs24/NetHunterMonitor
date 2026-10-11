using System.Windows;
using System.Windows.Controls;
using NetHunter.App.Ui;
using NetHunter.Core.Engine;
using NetHunter.Core.Models;
using NetHunter.Windows;

namespace NetHunter.App.Pages;

/// <summary>API keys, providers and limits, monitoring, retention, notifications, privacy, data folders.</summary>
public sealed class SettingsPage : PageBase
{
    private readonly AppSettings _s;
    private readonly PasswordBox _abuseKey = new() { Width = 360 }, _vtKey = new() { Width = 360 };
    private readonly CheckBox _abuseOn = new() { Content = "Enable AbuseIPDB (IP reputation)" }, _vtOn = new() { Content = "Enable VirusTotal (IP, domain and file-hash reputation)" };
    private readonly TextBox _abuseMin = Num(), _abuseDay = Num(), _vtMin = Num(), _vtDay = Num(), _cacheHours = Num(), _poll = Num(), _dnsPoll = Num(), _learn = Num();
    private readonly CheckBox _intel = new() { Content = "Allow external threat-intelligence lookups (send IOC values to the enabled providers)" };
    private readonly CheckBox _lookupHashes = new() { Content = "Look up executable SHA-256 hashes (hash only; files are never uploaded automatically)" };
    private readonly CheckBox _lookupDomains = new() { Content = "Look up domain names" };
    private readonly CheckBox _ptr = new() { Content = "Resolve PTR (reverse DNS) for external IPs" };
    private readonly CheckBox _etw = new() { Content = "Use real-time ETW tracing when running as administrator" };
    private readonly CheckBox _lan = new() { Content = "Include LAN (private address) traffic" };
    private readonly CheckBox _loopback = new() { Content = "Include loopback (127.0.0.1 / ::1) traffic" };
    private readonly CheckBox _hash = new() { Content = "Compute SHA-256 of executables" };
    private readonly CheckBox _sign = new() { Content = "Verify Authenticode signatures" };
    private readonly CheckBox _notify = new() { Content = "Desktop notifications" };
    private readonly ComboBox _notifyLevel = new() { ItemsSource = new[] { "Medium", "High", "Critical" } };
    private readonly ComboBox _alertLevel = new() { ItemsSource = new[] { "Low", "Medium", "High", "Critical" } };
    private readonly ComboBox _retention = new() { ItemsSource = AppSettings.RetentionChoices.Select(c => c.Label).ToList() };
    private readonly TextBlock _saved = new() { Style = Ux.S("Muted"), VerticalAlignment = VerticalAlignment.Center };

    public SettingsPage(UiContext ctx) : base(ctx)
    {
        _s = Host.Settings;
        var root = new StackPanel { MaxWidth = 900, HorizontalAlignment = HorizontalAlignment.Left };

        root.Children.Add(Section("Threat intelligence providers",
            Ux.Muted("API keys are stored encrypted with Windows DPAPI for the current user in config\\settings.json. They are never written in plain text, " +
                     "never logged, and are not portable to another user or machine (re-enter them there). Leave a key empty to keep the stored one."),
            _abuseOn, Row("AbuseIPDB API key", _abuseKey, Status(_s.AbuseIpDb)), Row("Requests / minute", _abuseMin, Label("per day"), _abuseDay),
            _vtOn, Row("VirusTotal API key", _vtKey, Status(_s.VirusTotal)), Row("Requests / minute", _vtMin, Label("per day"), _vtDay),
            Ux.Muted("VirusTotal public API: 4 requests/minute and 500/day. AbuseIPDB free plan: 1,000 checks/day. Lookups beyond the limits wait in a queue."),
            Row("Cache reputation for (hours)", _cacheHours),
            Ux.Buttons(Ux.Button("Clear stored keys", ClearKeys, "Danger"))));

        root.Children.Add(Section("Privacy",
            _intel, _lookupHashes, _lookupDomains, _ptr,
            Ux.Muted("Never sent anywhere: packet contents, executable files (unless you click \"Upload file to VirusTotal\" and confirm), private/LAN addresses, " +
                     "process names or paths. Only the indicator value (public IP, domain or SHA-256) is sent to the providers you enable. Every query is listed below.")));

        root.Children.Add(Section("Monitoring",
            Row("TCP table poll interval (ms)", _poll), Row("DNS cache poll interval (s)", _dnsPoll), _etw, _lan, _loopback, _hash, _sign,
            Row("Baseline learning period (hours)", _learn, Ux.Button("Reset baseline", ResetBaseline, tooltip: "Forget learned destinations and start learning again")),
            Ux.Muted($"Running as administrator: {(Host.IsElevated ? "yes" : "no")}. Administrator enables: " + string.Join("; ", Elevation.FeaturesRequiringAdmin) + "."),
            Ux.Muted("Changes to collectors take effect the next time monitoring is started.")));

        root.Children.Add(Section("Alerts & notifications",
            Row("Create alerts at or above", _alertLevel), _notify, Row("Notify at or above", _notifyLevel)));

        root.Children.Add(Section("Data retention",
            Row("Keep connection, DNS and alert history for", _retention),
            Ux.Muted("Old records are removed automatically every 10 minutes. The learned baseline is kept."),
            Ux.Buttons(
                Ux.Button("Open data folder", () => Ux.OpenFolder(Host.Root)),
                Ux.Button("Open logs", () => Ux.OpenFolder(Path.Combine(Host.Root, "logs"))),
                Ux.Button("Open IOC lists", () => Ux.OpenFolder(Host.IocDirectory)))));

        root.Children.Add(Section("Detection test mode",
            Ux.Muted("Restarts the application in SYNTHETIC TEST MODE: a generator feeds clearly-labelled fake events (RFC 5737 addresses, .example domains) " +
                     "through the real detection engine so you can see beaconing, IOC and DNS-tunnelling detections without malware. Synthetic data goes to a " +
                     "separate database and is never sent to reputation providers."),
            Ux.Buttons(Host.Mode == HostMode.Synthetic
                ? Ux.Button("Return to live monitoring", () => App.Restart(synthetic: false), "Primary")
                : Ux.Button("Restart in synthetic test mode", () => App.Restart(synthetic: true)))));

        var apiLog = Grids.Create(Store.ApiLog).Text("Time", "Time", 80, Grids.Conv("Time")).Text("Provider", "Provider", 100).Text("Type", "Type", 70)
            .Text("Value sent", "Value", 0, mono: true).Text("Outcome", "Outcome", 100);
        apiLog.Height = 200;
        root.Children.Add(Section("Threat-intelligence activity (this session)", apiLog));

        var save = Ux.Button("Save settings", Save, "Primary");
        root.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 30), Children = { save, _saved } });
        Children.Add(new ScrollViewer { Content = root, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        Load();
    }

    public override string Title => "Settings";
    public override void OnShown(object? argument) => Load();

    private static TextBox Num() => new() { Width = 80 };

    private static TextBlock Status(ProviderSettings p) => new()
    {
        Text = string.IsNullOrEmpty(p.ProtectedApiKey) ? "no key stored" : "key stored (encrypted)",
        Style = Ux.S("Muted"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0),
    };

    private static Border Section(string title, params UIElement[] children)
    {
        var sp = new StackPanel();
        sp.Children.Add(Ux.Heading(title));
        foreach (var c in children) sp.Children.Add(c);
        return new Border { Style = Ux.S("Card"), Child = sp, Margin = new Thickness(0, 0, 0, 12) };
    }

    private static StackPanel Row(string label, params UIElement[] controls)
    {
        var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        sp.Children.Add(new TextBlock { Text = label, Width = 240, VerticalAlignment = VerticalAlignment.Center });
        foreach (var c in controls)
        {
            if (c is FrameworkElement fe && fe.Margin == default) fe.Margin = new Thickness(0, 0, 8, 0);
            sp.Children.Add(c);
        }
        return sp;
    }

    private void Load()
    {
        _abuseOn.IsChecked = _s.AbuseIpDb.Enabled; _vtOn.IsChecked = _s.VirusTotal.Enabled;
        _abuseMin.Text = _s.AbuseIpDb.RequestsPerMinute.ToString(); _abuseDay.Text = _s.AbuseIpDb.RequestsPerDay.ToString();
        _vtMin.Text = _s.VirusTotal.RequestsPerMinute.ToString(); _vtDay.Text = _s.VirusTotal.RequestsPerDay.ToString();
        _cacheHours.Text = _s.ReputationCacheHours.ToString(); _poll.Text = _s.PollIntervalMs.ToString(); _dnsPoll.Text = _s.DnsCachePollSeconds.ToString();
        _learn.Text = _s.BaselineLearningHours.ToString();
        _intel.IsChecked = _s.ThreatIntelEnabled; _lookupHashes.IsChecked = _s.LookupFileHashes; _lookupDomains.IsChecked = _s.LookupDomains; _ptr.IsChecked = _s.ResolvePtr;
        _etw.IsChecked = _s.UseEtwWhenElevated; _lan.IsChecked = _s.IncludeLanTraffic; _loopback.IsChecked = _s.IncludeLoopback; _hash.IsChecked = _s.HashExecutables; _sign.IsChecked = _s.VerifySignatures;
        _notify.IsChecked = _s.NotificationsEnabled; _notifyLevel.SelectedItem = _s.MinimumNotificationLevel; _alertLevel.SelectedItem = _s.MinimumAlertLevel;
        _retention.SelectedIndex = Math.Max(0, Array.FindIndex(AppSettings.RetentionChoices, c => c.Hours == _s.RetentionHours));
    }

    private static int Int(TextBox t, int fallback) => int.TryParse(t.Text.Trim(), out var v) ? v : fallback;

    private void Save()
    {
        _s.AbuseIpDb.Enabled = _abuseOn.IsChecked == true;
        _s.VirusTotal.Enabled = _vtOn.IsChecked == true;
        if (_abuseKey.Password.Length > 0) _s.SetApiKey(_s.AbuseIpDb, _abuseKey.Password);
        if (_vtKey.Password.Length > 0) _s.SetApiKey(_s.VirusTotal, _vtKey.Password);
        _abuseKey.Clear(); _vtKey.Clear();
        _s.AbuseIpDb.RequestsPerMinute = Int(_abuseMin, 30); _s.AbuseIpDb.RequestsPerDay = Int(_abuseDay, 1000);
        _s.VirusTotal.RequestsPerMinute = Int(_vtMin, 4); _s.VirusTotal.RequestsPerDay = Int(_vtDay, 500);
        _s.ReputationCacheHours = Int(_cacheHours, 24); _s.PollIntervalMs = Int(_poll, 1000); _s.DnsCachePollSeconds = Int(_dnsPoll, 5);
        _s.BaselineLearningHours = Int(_learn, 24);
        _s.ThreatIntelEnabled = _intel.IsChecked == true; _s.LookupFileHashes = _lookupHashes.IsChecked == true; _s.LookupDomains = _lookupDomains.IsChecked == true;
        _s.ResolvePtr = _ptr.IsChecked == true; _s.UseEtwWhenElevated = _etw.IsChecked == true; _s.IncludeLanTraffic = _lan.IsChecked == true;
        _s.IncludeLoopback = _loopback.IsChecked == true; _s.HashExecutables = _hash.IsChecked == true; _s.VerifySignatures = _sign.IsChecked == true;
        _s.NotificationsEnabled = _notify.IsChecked == true;
        _s.MinimumNotificationLevel = _notifyLevel.SelectedItem as string ?? "High";
        _s.MinimumAlertLevel = _alertLevel.SelectedItem as string ?? "Medium";
        _s.RetentionHours = AppSettings.RetentionChoices[Math.Max(0, _retention.SelectedIndex)].Hours;
        _s.Sanitize();
        // Apply new limits to the live limiters.
        foreach (var p in Host.Reputation.RemoteProviders)
        {
            var ps = p.Name == "AbuseIPDB" ? _s.AbuseIpDb : _s.VirusTotal;
            p.Limiter.PerMinute = ps.RequestsPerMinute;
            p.Limiter.PerDay = ps.RequestsPerDay;
        }
        Host.Reputation.Cache.Ttl = TimeSpan.FromHours(_s.ReputationCacheHours);
        Host.Engine.Baseline.LearningPeriod = TimeSpan.FromHours(_s.BaselineLearningHours);
        Host.SaveSettings();
        Host.LogFile.Write("Settings saved");
        Load();
        _saved.Text = $"Saved at {DateTime.Now:HH:mm:ss}. Threat intel: {Host.Reputation.StatusText}";
        Host.Engine.ReassessAll();
        // Rebuild provider status labels.
        Ctx.Navigate("Settings", null);
    }

    private void ClearKeys()
    {
        if (!Ux.Confirm("Clear API keys", "Remove both stored API keys?")) return;
        _s.AbuseIpDb.ProtectedApiKey = null;
        _s.VirusTotal.ProtectedApiKey = null;
        Host.SaveSettings();
        _saved.Text = "API keys removed.";
    }

    private void ResetBaseline()
    {
        if (!Ux.Confirm("Reset baseline", "Forget all learned process → destination history and start learning again?")) return;
        Host.Database.ResetBaseline();
        Ux.Info("Baseline reset", "The stored baseline was cleared. Restart the application to also clear the in-memory copy.");
    }
}
