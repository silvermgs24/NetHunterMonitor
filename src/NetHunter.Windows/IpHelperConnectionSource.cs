using System.Net;
using NetHunter.Core.Engine;
using NetHunter.Core.Models;

namespace NetHunter.Windows;

/// <summary>
/// Polls the TCP table (with owning PID) and reports connections as they appear, change state and disappear.
/// Reliable and unprivileged, but connections that open and close between two polls are invisible; TIME_WAIT
/// remnants of such connections are reported with Process: Unknown because the kernel no longer records a PID.
/// </summary>
public sealed class IpHelperConnectionSource : IConnectionSource, IListeningPortProvider
{
    private readonly Func<int> _intervalMs;
    private Timer? _timer;
    private Action<ConnectionObservation>? _sink;
    private Action<string>? _log;
    private Dictionary<string, TcpRow> _previous = new();
    private int _busy;
    private int _consecutiveErrors;

    public IpHelperConnectionSource(Func<int> intervalMs) { _intervalMs = intervalMs; }

    public string Name => "IP Helper TCP table (polling)";
    public string Capabilities => "TCP connections with owning process, state changes, listening ports. No admin needed. Misses connections shorter than the poll interval.";
    public bool IsRunning => _timer is not null;

    public bool Start(Action<ConnectionObservation> sink, Action<string> log, out string? reason)
    {
        _sink = sink;
        _log = log;
        try { IpHelperTables.GetTcp(); }
        catch (Exception ex) { reason = ex.Message; return false; }
        reason = null;
        _previous = new();
        _timer = new Timer(_ => Poll(), null, 0, Math.Max(250, _intervalMs()));
        return true;
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    public void Dispose() => Stop();

    private static string Key(TcpRow r) => $"{r.LocalAddress}|{r.LocalPort}|{r.RemoteAddress}|{r.RemotePort}";

    internal void Poll()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var now = DateTimeOffset.Now;
            var rows = IpHelperTables.GetTcp();
            _consecutiveErrors = 0;

            var listeners = new HashSet<(int Pid, int Port)>();
            var listenPorts = new HashSet<int>();
            foreach (var r in rows.Where(r => r.State == TcpState.Listen))
            {
                listeners.Add((r.Pid, r.LocalPort));
                listenPorts.Add(r.LocalPort);
            }

            var current = new Dictionary<string, TcpRow>(rows.Count);
            foreach (var r in rows)
            {
                if (r.State == TcpState.Listen) continue;
                if (r.RemoteAddress.Equals(IPAddress.Any) || r.RemoteAddress.Equals(IPAddress.IPv6Any)) continue;
                current[Key(r)] = r;
            }

            foreach (var (k, r) in current)
            {
                if (_previous.TryGetValue(k, out var prev))
                {
                    if (prev.State != r.State) _sink?.Invoke(Make(r, now, ObservationKind.StateChanged, listeners, listenPorts));
                }
                else
                {
                    _sink?.Invoke(Make(r, now, ObservationKind.Opened, listeners, listenPorts));
                }
            }
            foreach (var (k, r) in _previous)
                if (!current.ContainsKey(k))
                    _sink?.Invoke(Make(r, now, ObservationKind.Closed, listeners, listenPorts));

            _previous = current;
        }
        catch (Exception ex)
        {
            if (++_consecutiveErrors <= 3) _log?.Invoke("IP Helper poll failed: " + ex.Message);
        }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }

    private static ConnectionObservation Make(TcpRow r, DateTimeOffset now, ObservationKind kind, HashSet<(int, int)> listeners, HashSet<int> listenPorts)
    {
        // PID 0 is "System Idle Process": the kernel keeps TIME_WAIT sockets without an owner. Never attribute those.
        int? pid = r.Pid == 0 ? null : r.Pid;
        bool inbound = pid is { } p ? listeners.Contains((p, r.LocalPort)) : listenPorts.Contains(r.LocalPort);
        return new ConnectionObservation
        {
            Timestamp = now, Protocol = TransportProtocol.Tcp, Direction = inbound ? Direction.Inbound : Direction.Outbound,
            LocalAddress = r.LocalAddress, LocalPort = r.LocalPort, RemoteAddress = r.RemoteAddress, RemotePort = r.RemotePort,
            Pid = pid, State = IpHelperTables.StateName(r.State), Kind = kind, Source = "IPHelper",
        };
    }

    public IReadOnlyList<ListeningEndpoint> GetListeners()
    {
        var list = new List<ListeningEndpoint>();
        foreach (var r in IpHelperTables.GetTcp().Where(r => r.State == TcpState.Listen))
            list.Add(new ListeningEndpoint { Protocol = TransportProtocol.Tcp, LocalAddress = r.LocalAddress, Port = r.LocalPort, Pid = r.Pid == 0 ? null : r.Pid });
        foreach (var r in IpHelperTables.GetUdp())
            list.Add(new ListeningEndpoint { Protocol = TransportProtocol.Udp, LocalAddress = r.LocalAddress, Port = r.LocalPort, Pid = r.Pid == 0 ? null : r.Pid });
        return list.DistinctBy(l => (l.Protocol, l.LocalAddress.ToString(), l.Port, l.Pid)).ToList();
    }
}
