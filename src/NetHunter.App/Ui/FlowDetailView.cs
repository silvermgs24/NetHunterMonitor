using System.Windows;
using System.Windows.Controls;
using NetHunter.Core.Detection;
using NetHunter.Core.Export;
using NetHunter.Core.Models;
using NetHunter.Windows;

namespace NetHunter.App.Ui;

/// <summary>
/// The explain panel: Process → PID → Executable → SHA-256 → Destination → Port → Hostname → Reputation → Risk,
/// followed by every reason that contributed to the score. Used by Dashboard, Connections and Timeline.
/// </summary>
public sealed class FlowDetailView : ScrollViewer
{
    private readonly AppHost _host;
    private readonly StackPanel _root = new() { Margin = new Thickness(2, 0, 8, 12) };
    private FlowRecord? _flow;

    public FlowDetailView(AppHost host)
    {
        _host = host;
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled;
        Content = _root;
        ShowEmpty();
    }

    public void ShowEmpty(string text = "Select a connection to see where it comes from, where it goes, and why it was scored.")
    {
        _flow = null;
        _root.Children.Clear();
        _root.Children.Add(Ux.Muted(text));
    }

    public void Show(FlowRecord flow)
    {
        _flow = flow;
        var a = flow.Assessment;
        var proc = _host.Engine.GetProcess(flow.ProcessKey) ?? (flow.LastPid is { } pid ? _host.Engine.GetProcessByPid(pid) : null);
        var hostInfo = _host.Engine.GetHostInfo(flow.RemoteIp);
        _root.Children.Clear();

        var head = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
        var badge = Ux.Badge(a.Level);
        DockPanel.SetDock(badge, Dock.Right);
        head.Children.Add(badge);
        head.Children.Add(Ux.Heading((flow.IsSynthetic ? "[SYNTHETIC] " : "") + (string.IsNullOrEmpty(a.Title) ? "Connection" : a.Title), "H2"));
        _root.Children.Add(head);
        _root.Children.Add(Ux.Muted($"Risk score {a.Score}/100 · confidence {a.Confidence}% · {(a.Classification == DetectionClass.None ? "no detection" : a.Classification.Describe())}{(a.Suppressed ? " · suppressed by analyst mark (" + a.Mark + ")" : "")}"));

        // ── Process
        var p = new StackPanel();
        p.Children.Add(Ux.Heading("Process"));
        p.Children.Add(Ux.Field("Name", flow.ProcessName));
        p.Children.Add(Ux.Field("PID", flow.LastPid?.ToString()));
        p.Children.Add(Ux.Field("Executable", flow.ProcessPath, proc?.AttributionNote is { } note ? "Unknown: " + note : "Unknown"));
        p.Children.Add(Ux.Field("SHA-256", flow.Sha256 ?? proc?.Sha256, flow.ProcessPath is null ? "Unknown" : "Not available (pending, access denied, or file too large)"));
        p.Children.Add(Ux.Field("Signature", proc?.Signature.ToString()));
        p.Children.Add(Ux.Field("Parent process", proc?.ParentName is null ? null : $"{proc.ParentName} (PID {proc.ParentPid})"));
        p.Children.Add(Ux.Field("Process started", proc?.StartTime?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")));
        _root.Children.Add(Ux.Section(p, new Thickness(0, 8, 0, 0)));
        _root.Children.Add(Ux.Arrow());

        // ── Destination
        var d = new StackPanel();
        d.Children.Add(Ux.Heading("Destination"));
        d.Children.Add(Ux.Field("Remote endpoint", $"{flow.RemoteIp}:{flow.RemotePort} / {flow.Protocol.ToString().ToUpperInvariant()} ({flow.Direction})"));
        d.Children.Add(Ux.Field("Connections", $"{flow.Count} (first {flow.FirstSeen.ToLocalTime():yyyy-MM-dd HH:mm:ss}, last {flow.LastSeen.ToLocalTime():HH:mm:ss}), state {flow.LastState}{(flow.FailedCount > 0 ? $", {flow.FailedCount} failed" : "")}"));
        var beacon = _host.Engine.GetBeacon(flow);
        if (beacon.Contacts >= BeaconDetector.MinContacts)
            d.Children.Add(Ux.Field("Timing", beacon.IsBeacon ? "Possible periodic beacon: " + beacon.Describe() : $"{beacon.Contacts} distinct contacts, no regular period detected"));
        _root.Children.Add(Ux.Section(d));
        _root.Children.Add(Ux.Arrow());

        // ── Hostname (each source labelled separately; PTR is not proof of ownership)
        var h = new StackPanel();
        h.Children.Add(Ux.Heading("Hostname"));
        h.Children.Add(Ux.Field("DNS hostname (observed resolution)", hostInfo?.DnsNames.Count > 0 ? string.Join(", ", hostInfo.DnsNames) : null,
            _host.Engine.HasDnsVisibility ? "Unknown (no DNS lookup observed for this IP)" : "Unknown (no DNS source running)"));
        h.Children.Add(Ux.Field("PTR record (reverse DNS, informational only)", flow.Ptr ?? hostInfo?.Ptr, hostInfo?.PtrAttempted == true ? "None" : "Not looked up"));
        h.Children.Add(Ux.Field("TLS SNI / HTTP Host", flow.Sni, "Not available in live mode (no packet inspection); see PCAP import"));
        _root.Children.Add(Ux.Section(h));
        _root.Children.Add(Ux.Arrow());

        // ── Reputation
        var r = new StackPanel();
        r.Children.Add(Ux.Heading("IOC reputation"));
        var reps = new List<ReputationResult>();
        reps.AddRange(_host.Engine.GetReputation(IocType.Ip, flow.RemoteIp));
        if (flow.Hostname is not null) reps.AddRange(_host.Engine.GetReputation(IocType.Domain, flow.Hostname));
        if (flow.Sha256 is not null) reps.AddRange(_host.Engine.GetReputation(IocType.Sha256, flow.Sha256));
        if (reps.Count == 0)
            r.Children.Add(Ux.Muted(_host.Reputation.Status switch
            {
                Core.Intel.IntelStatus.Offline => "Threat intelligence unavailable (offline). Local IOC lists were checked: no match.",
                Core.Intel.IntelStatus.NoProviders => "No reputation providers configured (Settings). Local IOC lists were checked: no match.",
                Core.Intel.IntelStatus.Disabled => "External reputation lookups are disabled (Settings → Privacy). Local IOC lists were checked: no match.",
                _ => "No reputation data yet (lookup queued or not applicable to private addresses). Local IOC lists: no match.",
            }));
        foreach (var rep in reps) r.Children.Add(ReputationBlock(rep));
        _root.Children.Add(Ux.Section(r));
        _root.Children.Add(Ux.Arrow());

        // ── Why
        var w = new StackPanel();
        var wh = new DockPanel();
        var wb = Ux.Badge(a.Level);
        DockPanel.SetDock(wb, Dock.Right);
        wh.Children.Add(wb);
        wh.Children.Add(Ux.Heading("Why this risk level"));
        w.Children.Add(wh);
        w.Children.Add(Ux.EvidenceList(a.Evidence));
        _root.Children.Add(Ux.Section(w));

        // ── Actions
        _root.Children.Add(Ux.Heading("Analyst actions"));
        _root.Children.Add(Ux.Buttons(
            Ux.Button("Look up reputation now", LookupNow, tooltip: "Queue IP, domain and hash lookups at top priority (only enabled providers; values are sent to them)"),
            Ux.Button("Export report", ExportReport)));
        _root.Children.Add(Ux.Muted("Destination " + flow.RemoteIp + (flow.Hostname is null ? "" : " / " + flow.Hostname) + ":"));
        _root.Children.Add(Ux.Buttons(
            Ux.Button("Trusted", () => MarkDest(UserMarkKind.Trusted)),
            Ux.Button("Ignored", () => MarkDest(UserMarkKind.Ignored)),
            Ux.Button("Suspicious", () => MarkDest(UserMarkKind.Suspicious)),
            Ux.Button("Clear mark", () => MarkDest(UserMarkKind.None))));
        _root.Children.Add(Ux.Muted("Process " + flow.ProcessName + ":"));
        _root.Children.Add(Ux.Buttons(
            Ux.Button("Trusted", () => MarkProc(UserMarkKind.Trusted)),
            Ux.Button("Ignored", () => MarkProc(UserMarkKind.Ignored)),
            Ux.Button("Suspicious", () => MarkProc(UserMarkKind.Suspicious)),
            Ux.Button("Clear mark", () => MarkProc(UserMarkKind.None)),
            Ux.Button("Upload file to VirusTotal…", UploadToVt, "Danger", "Uploads the executable itself. Separate, explicit action with a privacy warning.")));
    }

    public static UIElement ReputationBlock(ReputationResult rep)
    {
        var sp = new StackPanel { Margin = new Thickness(0, 4, 0, 4) };
        sp.Children.Add(new TextBlock { Text = $"{rep.Provider} · {rep.Type} {rep.Value}", FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
        var lines = new List<string>();
        if (rep.Status != ReputationStatus.Ok) lines.Add(rep.Summary());
        if (rep.ListName is not null) lines.Add($"Listed in local IOC list '{rep.ListName}' ({rep.Detail})");
        if (rep.AbuseConfidence is not null)
        {
            lines.Add($"Abuse confidence: {rep.AbuseConfidence}%   Reports: {rep.TotalReports ?? 0} from {rep.DistinctReporters ?? 0} users");
            lines.Add($"Country: {rep.CountryCode ?? "?"}   ISP: {rep.Isp ?? "?"}   Usage: {rep.UsageType ?? "?"}");
            if (rep.Domain is not null) lines.Add($"Domain: {rep.Domain}");
            if (rep.LastReported is { } lr) lines.Add($"Last reported: {lr.ToLocalTime():yyyy-MM-dd}");
            if (rep.IsWhitelisted == true) lines.Add("Whitelisted by AbuseIPDB");
        }
        if (rep.Malicious is not null)
        {
            lines.Add($"Detections: {rep.Malicious} malicious, {rep.Suspicious ?? 0} suspicious / {rep.TotalEngines ?? 0} engines");
            if (rep.CountryCode is not null || rep.Isp is not null) lines.Add($"Country: {rep.CountryCode ?? "?"}   AS owner: {rep.Isp ?? "?"}");
            if (rep.Detail is not null && rep.Type == IocType.Sha256) lines.Add($"Name on VirusTotal: {rep.Detail}");
        }
        lines.Add($"Retrieved {rep.RetrievedAt.ToLocalTime():yyyy-MM-dd HH:mm}. One signal among several, not a verdict.");
        foreach (var l in lines) sp.Children.Add(Ux.Muted(l));
        return sp;
    }

    private void LookupNow()
    {
        if (_flow is null) return;
        _host.Engine.RequestLookup(IocType.Ip, _flow.RemoteIp);
        if (_flow.Hostname is not null) _host.Engine.RequestLookup(IocType.Domain, _flow.Hostname);
        if (_flow.Sha256 is not null) _host.Engine.RequestLookup(IocType.Sha256, _flow.Sha256);
        Ux.Info("Lookup queued", _host.Reputation.Status == Core.Intel.IntelStatus.Online
            ? "Lookups queued with the enabled providers. Results appear here and re-score the connection automatically."
            : _host.Reputation.StatusText);
    }

    private void MarkDest(UserMarkKind m)
    {
        if (_flow is null) return;
        _host.Engine.SetMark("ip", _flow.RemoteIp, m);
        if (_flow.Hostname is not null) _host.Engine.SetMark("domain", _flow.Hostname, m);
    }

    private void MarkProc(UserMarkKind m)
    {
        if (_flow is null) return;
        _host.Engine.SetMark("process", _flow.ProcessKey, m);
    }

    private void ExportReport()
    {
        if (_flow is null) return;
        var f = _flow;
        var alert = new AlertRecord
        {
            Created = f.FirstSeen, Updated = f.LastSeen, Severity = f.Assessment.Level, Classification = f.Assessment.Classification,
            Title = string.IsNullOrEmpty(f.Assessment.Title) ? "Connection" : f.Assessment.Title, ProcessName = f.ProcessName, Pid = f.LastPid,
            ProcessPath = f.ProcessPath, Sha256 = f.Sha256, RemoteIp = f.RemoteIp, RemotePort = f.RemotePort, Hostname = f.Hostname,
            Score = f.Assessment.Score, Confidence = f.Assessment.Confidence, Evidence = f.Assessment.Evidence, FirstSeen = f.FirstSeen,
            LastSeen = f.LastSeen, IsSynthetic = f.IsSynthetic,
        };
        Reports.SaveInvestigation(_host, new[] { alert }, new[] { f });
    }

    private async void UploadToVt()
    {
        if (_flow?.ProcessPath is not { } path) { Ux.Info("No executable", "The executable path for this process is unknown."); return; }
        if (!Ux.Confirm("Upload executable to VirusTotal?",
            $"This uploads the FILE ITSELF:\n\n{path}\n\nUploaded files become available to VirusTotal and its security partners and may be " +
            "downloadable by premium users. Do not upload files that may contain confidential or personal data.\n\nHash lookups (the default) " +
            "never upload anything. Continue with the upload?")) return;
        var (ok, msg) = await _host.VirusTotal.UploadFileAsync(path, CancellationToken.None);
        _host.LogFile.Write($"VirusTotal upload of {path}: {(ok ? "ok" : "failed")} {msg}");
        if (ok) Ux.Info("Uploaded", msg); else Ux.Error("Upload failed", msg);
    }
}
