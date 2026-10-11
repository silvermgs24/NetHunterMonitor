using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Threading;
using NetHunter.Core.Engine;
using NetHunter.Core.Intel;
using NetHunter.Core.Models;
using NetHunter.Windows;

namespace NetHunter.App.Ui;

/// <summary>Bindable wrapper around a flow; updated in place so grids keep selection and scroll position.</summary>
public sealed class FlowRow : INotifyPropertyChanged
{
    public FlowRow(FlowRecord f) { Flow = f; }
    public FlowRecord Flow { get; private set; }
    public string Key => Flow.Key;
    public string ProcessName => Flow.ProcessName;
    public int? Pid => Flow.LastPid;
    public string? ProcessPath => Flow.ProcessPath;
    public string RemoteIp => Flow.RemoteIp;
    public int RemotePort => Flow.RemotePort;
    public string Protocol => Flow.Protocol.ToString().ToUpperInvariant();
    public Direction Direction => Flow.Direction;
    public string? Hostname => Flow.Hostname;
    public string? Ptr => Flow.Ptr;
    public DateTimeOffset FirstSeen => Flow.FirstSeen;
    public DateTimeOffset LastSeen => Flow.LastSeen;
    public long Count => Flow.Count;
    public string State => Flow.LastState;
    public RiskLevel Level => Flow.Assessment.Level;
    public int Score => Flow.Assessment.Score;
    public int Confidence => Flow.Assessment.Confidence;
    public DetectionClass Classification => Flow.Assessment.Classification;
    public string TopReason => Flow.Assessment.Evidence.FirstOrDefault(e => e.Strength > 0)?.Text ?? "";
    public bool IsSynthetic => Flow.IsSynthetic;

    public void Update(FlowRecord f)
    {
        Flow = f;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

public sealed class AlertRow : INotifyPropertyChanged
{
    public AlertRow(AlertRecord a) { Alert = a; }
    public AlertRecord Alert { get; private set; }
    public long Id => Alert.Id;
    public DateTimeOffset Updated => Alert.Updated;
    public DateTimeOffset Created => Alert.Created;
    public RiskLevel Severity => Alert.Severity;
    public string Title => (Alert.IsSynthetic ? "[SYNTHETIC] " : "") + Alert.Title;
    public string ProcessName => Alert.ProcessName;
    public string Destination => Alert.RemoteIp is null ? Alert.Hostname ?? "" : $"{Alert.RemoteIp}{(Alert.RemotePort is null ? "" : ":" + Alert.RemotePort)}";
    public string? Hostname => Alert.Hostname;
    public int Score => Alert.Score;
    public int Confidence => Alert.Confidence;
    public DetectionClass Classification => Alert.Classification;
    public bool Acknowledged => Alert.Acknowledged;
    public string Status => Alert.Acknowledged ? "Acknowledged" : "New";

    public void Update(AlertRecord a)
    {
        Alert = a;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>
/// UI-side state fed by engine batches (about once per second), applied on the dispatcher in one go.
/// Collections are capped so the UI stays responsive with thousands of connections; history lives in SQLite.
/// </summary>
public sealed class LiveStore
{
    public const int LiveCap = 3000;
    public const int DnsCap = 3000;
    private readonly Dispatcher _dispatcher;
    private readonly Dictionary<string, FlowRow> _flowIndex = new();
    private readonly Dictionary<long, AlertRow> _alertIndex = new();
    private readonly Queue<DateTimeOffset> _rate = new();

    public LiveStore(AppHost host, Dispatcher dispatcher)
    {
        Host = host;
        _dispatcher = dispatcher;
        foreach (var f in host.Engine.SnapshotFlows().OrderByDescending(f => f.LastSeen)) AddFlow(f);
        foreach (var a in host.Database.GetAlerts(2000)) AddAlert(a, atEnd: true);
        foreach (var e in host.Database.QueryEvents(new Core.Storage.EventFilter { Limit = 500 })) Live.Add(e);
        foreach (var d in host.Database.QueryDns(null, 500)) Dns.Add(d);
        host.Engine.BatchReady += b => _dispatcher.BeginInvoke(() => Apply(b), DispatcherPriority.Background);
        host.Reputation.ApiQueried += q => _dispatcher.BeginInvoke(() =>
        {
            ApiLog.Insert(0, q);
            while (ApiLog.Count > 500) ApiLog.RemoveAt(ApiLog.Count - 1);
        });
    }

    public AppHost Host { get; }
    public ObservableCollection<ConnectionEvent> Live { get; } = new();
    public ObservableCollection<FlowRow> Flows { get; } = new();
    public ObservableCollection<AlertRow> Alerts { get; } = new();
    public ObservableCollection<DnsEventRecord> Dns { get; } = new();
    public ObservableCollection<ApiQueryLog> ApiLog { get; } = new();
    public double EventsPerMinute { get; private set; }
    public int OpenAlerts => Alerts.Count(a => !a.Acknowledged);

    /// <summary>Raised on the UI thread after a batch has been applied.</summary>
    public event Action<EngineBatch>? Applied;
    /// <summary>Raised on the UI thread for alerts that should produce a desktop notification.</summary>
    public event Action<AlertRecord>? Notify;

    private void Apply(EngineBatch b)
    {
        foreach (var e in b.Events)
        {
            Live.Insert(0, e);
            _rate.Enqueue(e.Timestamp);
        }
        while (Live.Count > LiveCap) Live.RemoveAt(Live.Count - 1);
        var now = DateTimeOffset.Now;
        while (_rate.Count > 0 && now - _rate.Peek() > TimeSpan.FromMinutes(1)) _rate.Dequeue();
        EventsPerMinute = _rate.Count;

        foreach (var f in b.Flows)
        {
            if (_flowIndex.TryGetValue(f.Key, out var row)) row.Update(f);
            else AddFlow(f, atStart: true);
        }
        // Keep live events consistent with their flow's latest score (e.g. after reputation arrives).
        if (b.Flows.Count > 0)
        {
            var byKey = b.Flows.ToDictionary(f => f.Key);
            for (int i = 0; i < Math.Min(Live.Count, 300); i++)
            {
                var e = Live[i];
                if (byKey.TryGetValue(e.FlowKey, out var f) && (e.Level != f.Assessment.Level || e.Hostname != f.Hostname))
                {
                    // Rows bind to plain objects, so replace with an updated copy to make the grid re-render it.
                    var copy = e.Clone();
                    copy.Level = f.Assessment.Level;
                    copy.Score = f.Assessment.Score;
                    copy.Hostname ??= f.Hostname;
                    copy.Sha256 ??= f.Sha256;
                    Live[i] = copy;
                }
            }
        }

        foreach (var d in b.Dns) Dns.Insert(0, d);
        while (Dns.Count > DnsCap) Dns.RemoveAt(Dns.Count - 1);

        foreach (var a in b.Alerts)
        {
            if (_alertIndex.TryGetValue(a.Id, out var row)) row.Update(a);
            else AddAlert(a, atEnd: false);
        }
        foreach (var a in b.Notify) Notify?.Invoke(a);
        Applied?.Invoke(b);
    }

    private void AddFlow(FlowRecord f, bool atStart = false)
    {
        var row = new FlowRow(f);
        _flowIndex[f.Key] = row;
        if (atStart) Flows.Insert(0, row); else Flows.Add(row);
    }

    private void AddAlert(AlertRecord a, bool atEnd)
    {
        var row = new AlertRow(a);
        _alertIndex[a.Id] = row;
        if (atEnd) Alerts.Add(row); else Alerts.Insert(0, row);
    }

    public FlowRow? FindFlow(string key) => _flowIndex.GetValueOrDefault(key);

    public void Acknowledge(AlertRow row, bool ack)
    {
        Host.Database.AcknowledgeAlert(row.Id, ack);
        row.Alert.Acknowledged = ack;
        row.Update(row.Alert);
        Applied?.Invoke(new EngineBatch());
    }
}
