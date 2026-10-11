using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetHunter.Core.Models;

namespace NetHunter.Core.Export;

/// <summary>CSV / JSON / HTML exports. All output is escaped for its format (CSV formula injection, HTML encoding).</summary>
public static class Exporter
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string ToJson<T>(T value) => JsonSerializer.Serialize(value, Json);

    public static string Csv(string? v)
    {
        v ??= "";
        // Neutralise spreadsheet formula injection from attacker-controlled strings (hostnames, paths).
        if (v.Length > 0 && "=+-@\t\r".Contains(v[0])) v = "'" + v;
        return v.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v;
    }

    public static string ToCsv<T>(IEnumerable<T> rows, params (string Header, Func<T, object?> Get)[] cols)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(',', cols.Select(c => Csv(c.Header))));
        foreach (var r in rows)
            sb.AppendLine(string.Join(',', cols.Select(c => Csv(Format(c.Get(r))))));
        return sb.ToString();
    }

    private static string Format(object? o) => o switch
    {
        null => "",
        DateTimeOffset d => d.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
        RiskLevel l => l.Label(),
        _ => o.ToString() ?? "",
    };

    public static string ConnectionsCsv(IEnumerable<ConnectionEvent> rows) => ToCsv(rows,
        ("Time", e => e.Timestamp), ("Direction", e => e.Direction), ("Protocol", e => e.Protocol), ("Process", e => e.ProcessName), ("PID", e => e.Pid),
        ("Path", e => e.ProcessPath), ("SHA256", e => e.Sha256), ("LocalIP", e => e.LocalIp), ("LocalPort", e => e.LocalPort), ("RemoteIP", e => e.RemoteIp),
        ("RemotePort", e => e.RemotePort), ("Hostname", e => e.Hostname), ("PTR", e => e.Ptr), ("State", e => e.State), ("Risk", e => e.Level),
        ("Score", e => e.Score), ("Source", e => e.Source), ("Synthetic", e => e.IsSynthetic));

    public static string FlowsCsv(IEnumerable<FlowRecord> rows) => ToCsv(rows,
        ("Process", f => f.ProcessName), ("PID", f => f.LastPid), ("Path", f => f.ProcessPath), ("SHA256", f => f.Sha256), ("Direction", f => f.Direction),
        ("Protocol", f => f.Protocol), ("RemoteIP", f => f.RemoteIp), ("RemotePort", f => f.RemotePort), ("Hostname", f => f.Hostname), ("PTR", f => f.Ptr),
        ("SNI", f => f.Sni), ("FirstSeen", f => f.FirstSeen), ("LastSeen", f => f.LastSeen), ("Connections", f => f.Count), ("Risk", f => f.Assessment.Level),
        ("Score", f => f.Assessment.Score), ("Confidence", f => f.Assessment.Confidence), ("Detection", f => f.Assessment.Classification.Describe()),
        ("Evidence", f => string.Join(" | ", f.Assessment.Evidence.Select(e => e.Text))));

    public static string AlertsCsv(IEnumerable<AlertRecord> rows) => ToCsv(rows,
        ("Created", a => a.Created), ("Updated", a => a.Updated), ("Severity", a => a.Severity), ("Detection", a => a.Classification.Describe()), ("Title", a => a.Title),
        ("Process", a => a.ProcessName), ("PID", a => a.Pid), ("Path", a => a.ProcessPath), ("SHA256", a => a.Sha256), ("RemoteIP", a => a.RemoteIp),
        ("RemotePort", a => a.RemotePort), ("Hostname", a => a.Hostname), ("Score", a => a.Score), ("Confidence", a => a.Confidence),
        ("Evidence", a => string.Join(" | ", a.Evidence.Select(e => e.Text))), ("Synthetic", a => a.IsSynthetic));

    public static string IocsCsv(IEnumerable<IocSummary> rows) => ToCsv(rows,
        ("IOC", i => i.Value), ("Type", i => i.Type), ("FirstSeen", i => i.FirstSeen), ("LastSeen", i => i.LastSeen), ("Processes", i => i.Processes),
        ("Reputation", i => i.Reputation), ("Risk", i => i.Level), ("Score", i => i.Score), ("Connections", i => i.Connections));

    /// <summary>Plain indicator list (one per line) in the same format the IOC importer accepts.</summary>
    public static string IocList(IEnumerable<IocSummary> rows) =>
        string.Join(Environment.NewLine, rows.Select(r => $"{r.Value} # {r.Type} {r.Level.Label()} score {r.Score}")) + Environment.NewLine;

    private static string H(object? v) => WebUtility.HtmlEncode(v switch
    {
        null => "Unknown",
        DateTimeOffset d => d.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
        _ => v.ToString() ?? "",
    });

    /// <summary>Self-contained HTML investigation report (no scripts, no external resources).</summary>
    public static string HtmlReport(string host, IReadOnlyList<AlertRecord> alerts, IReadOnlyList<FlowRecord> flows,
        Func<AlertRecord, IEnumerable<ReputationResult>>? reputation = null, string? note = null)
    {
        var sb = new StringBuilder();
        sb.Append("""
            <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
            <title>Security Investigation Report</title><style>
            body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1f24;background:#fff;max-width:1100px}
            h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid #d0d7de;padding-bottom:4px}
            table{border-collapse:collapse;width:100%;font-size:13px;margin:6px 0 14px} th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #eaeef2;vertical-align:top}
            th{background:#f6f8fa;width:180px} .sev{display:inline-block;padding:2px 8px;border-radius:10px;font-weight:600;font-size:12px}
            .Critical{background:#ffd7d5;color:#82071e}.High{background:#ffe2c2;color:#8a3b00}.Medium{background:#fff4c2;color:#6b5300}.Low{background:#dafbe1;color:#116329}.Unknown{background:#eaeef2;color:#424a53}
            ul{margin:4px 0;padding-left:20px} .muted{color:#57606a;font-size:12px} code{font-family:Consolas,monospace;font-size:12px;word-break:break-all}
            </style></head><body>
            """);
        sb.Append($"<h1>Security Investigation Report</h1><div class=\"muted\">Generated {H(DateTimeOffset.Now)} by NetHunter Monitor</div>");
        sb.Append($"<table><tr><th>Host</th><td>{H(host)}</td></tr><tr><th>Alerts in report</th><td>{alerts.Count}</td></tr><tr><th>Flows in report</th><td>{flows.Count}</td></tr></table>");
        if (note is not null) sb.Append($"<p>{H(note)}</p>");
        sb.Append("<p class=\"muted\">Scores combine multiple independent signals. \"Possible C2\" and \"suspicious\" are hypotheses for an analyst to verify, not confirmed malware verdicts.</p>");

        foreach (var a in alerts)
        {
            sb.Append($"<h2><span class=\"sev {a.Severity}\">{H(a.Severity.Label())}</span> {H(a.Title)}{(a.IsSynthetic ? " [SYNTHETIC TEST]" : "")}</h2><table>");
            sb.Append($"<tr><th>Detection</th><td>{H(a.Classification.Describe())}</td></tr>");
            sb.Append($"<tr><th>Process</th><td>{H(a.ProcessName)} (PID {H(a.Pid)})</td></tr>");
            sb.Append($"<tr><th>Path</th><td><code>{H(a.ProcessPath)}</code></td></tr>");
            sb.Append($"<tr><th>SHA-256</th><td><code>{H(a.Sha256)}</code></td></tr>");
            sb.Append($"<tr><th>Destination</th><td>{H(a.RemoteIp)}{(a.RemotePort is null ? "" : ":" + a.RemotePort)}</td></tr>");
            sb.Append($"<tr><th>Hostname</th><td>{H(a.Hostname)}</td></tr>");
            sb.Append($"<tr><th>First seen</th><td>{H(a.FirstSeen)}</td></tr><tr><th>Last seen</th><td>{H(a.LastSeen)}</td></tr>");
            sb.Append($"<tr><th>Risk score</th><td>{a.Score}/100 &nbsp; Confidence {a.Confidence}%</td></tr>");
            if (reputation is not null)
            {
                var reps = reputation(a).ToList();
                sb.Append($"<tr><th>IOC reputation</th><td>{(reps.Count == 0 ? "No reputation data (offline, not configured, or not yet queried)" : string.Join("<br>", reps.Select(r => H(r.Summary()))))}</td></tr>");
            }
            sb.Append("<tr><th>Evidence</th><td><ul>");
            foreach (var e in a.Evidence) sb.Append($"<li>{(e.Strength < 0 ? "− " : "✓ ")}{H(e.Text)} <span class=\"muted\">[{H(e.Category)}, {e.Points:+0;-0;0}]</span></li>");
            sb.Append("</ul></td></tr></table>");
        }

        if (flows.Count > 0)
        {
            sb.Append("<h2>Related network flows</h2><table><tr><th style=\"width:auto\">Process</th><th style=\"width:auto\">Destination</th><th style=\"width:auto\">Hostname</th><th style=\"width:auto\">First / last seen</th><th style=\"width:auto\">Count</th><th style=\"width:auto\">Risk</th></tr>");
            foreach (var f in flows.Take(500))
                sb.Append($"<tr><td>{H(f.ProcessName)}</td><td>{H(f.RemoteIp)}:{f.RemotePort}/{f.Protocol}</td><td>{H(f.Hostname)}</td><td>{H(f.FirstSeen)}<br>{H(f.LastSeen)}</td><td>{f.Count}</td><td><span class=\"sev {f.Assessment.Level}\">{H(f.Assessment.Level.Label())}</span> {f.Assessment.Score}</td></tr>");
            sb.Append("</table>");
        }
        sb.Append("</body></html>");
        return sb.ToString();
    }
}
