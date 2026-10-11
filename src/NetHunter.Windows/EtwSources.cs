using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using NetHunter.Core.Engine;
using NetHunter.Core.Intel;
using NetHunter.Core.Models;

namespace NetHunter.Windows;

/// <summary>
/// Real-time kernel TCP/IP events (connect/accept/disconnect, UDP send/receive) with the owning PID, via ETW.
/// Requires administrator rights. Catches short-lived connections that polling misses and gives UDP peers.
/// </summary>
public sealed class EtwNetworkSource : IConnectionSource
{
    public const string SessionName = "NetHunterMonitor-KernelNet";
    private TraceEventSession? _session;
    private Thread? _thread;
    private Action<ConnectionObservation>? _sink;
    private readonly Dictionary<string, DateTime> _udpSeen = new();
    private readonly object _udpLock = new();

    public string Name => "ETW kernel TCP/IP (real-time)";
    public string Capabilities => "Every TCP connect/accept and UDP peer with PID, including very short-lived connections. Requires administrator.";
    public bool IsRunning => _session is not null;

    public bool Start(Action<ConnectionObservation> sink, Action<string> log, out string? reason)
    {
        reason = null;
        if (!Elevation.IsElevated) { reason = "requires administrator (ETW kernel tracing)"; return false; }
        _sink = sink;
        try
        {
            _session = new TraceEventSession(SessionName) { StopOnDispose = true };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
        }
        catch (Exception ex)
        {
            // Older builds only allow the single "NT Kernel Logger" session name for kernel providers.
            _session?.Dispose();
            try
            {
                _session = new TraceEventSession(KernelTraceEventParser.KernelSessionName) { StopOnDispose = true };
                _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            }
            catch (Exception ex2)
            {
                _session?.Dispose();
                _session = null;
                reason = $"could not start kernel trace: {ex.Message} / {ex2.Message}";
                return false;
            }
        }

        var k = _session.Source.Kernel;
        k.TcpIpConnect += d => Tcp(d.TimeStamp, d.saddr, d.sport, d.daddr, d.dport, d.ProcessID, Direction.Outbound, ObservationKind.Opened);
        k.TcpIpConnectIPV6 += d => Tcp(d.TimeStamp, d.saddr, d.sport, d.daddr, d.dport, d.ProcessID, Direction.Outbound, ObservationKind.Opened);
        k.TcpIpAccept += d => Tcp(d.TimeStamp, d.saddr, d.sport, d.daddr, d.dport, d.ProcessID, Direction.Inbound, ObservationKind.Opened);
        k.TcpIpAcceptIPV6 += d => Tcp(d.TimeStamp, d.saddr, d.sport, d.daddr, d.dport, d.ProcessID, Direction.Inbound, ObservationKind.Opened);
        k.TcpIpDisconnect += d => Tcp(d.TimeStamp, d.saddr, d.sport, d.daddr, d.dport, d.ProcessID, Direction.Unknown, ObservationKind.Closed);
        k.TcpIpDisconnectIPV6 += d => Tcp(d.TimeStamp, d.saddr, d.sport, d.daddr, d.dport, d.ProcessID, Direction.Unknown, ObservationKind.Closed);
        k.UdpIpSend += d => Udp(d.TimeStamp, d.saddr, d.sport, d.daddr, d.dport, d.ProcessID, Direction.Outbound);
        k.UdpIpRecv += d => Udp(d.TimeStamp, d.daddr, d.dport, d.saddr, d.sport, d.ProcessID, Direction.Inbound);
        k.UdpIpSendIPV6 += d => Udp(d.TimeStamp, d.saddr, d.sport, d.daddr, d.dport, d.ProcessID, Direction.Outbound);
        k.UdpIpRecvIPV6 += d => Udp(d.TimeStamp, d.daddr, d.dport, d.saddr, d.sport, d.ProcessID, Direction.Inbound);

        var session = _session;
        _thread = new Thread(() =>
        {
            try { session.Source.Process(); }
            catch (Exception ex) { log("ETW network trace stopped: " + ex.Message); }
        }) { IsBackground = true, Name = "ETW-KernelNet" };
        _thread.Start();
        return true;
    }

    // For TCP connect events, the kernel reports saddr/sport as the local endpoint and daddr/dport as the remote.
    // Accept events use the same layout from the server's perspective (saddr = local listening address).
    private void Tcp(DateTime ts, IPAddress local, int lport, IPAddress remote, int rport, int pid, Direction dir, ObservationKind kind)
    {
        _sink?.Invoke(new ConnectionObservation
        {
            Timestamp = new DateTimeOffset(ts), Protocol = TransportProtocol.Tcp, Direction = dir, LocalAddress = local, LocalPort = lport,
            RemoteAddress = remote, RemotePort = rport, Pid = pid > 0 ? pid : null, State = kind == ObservationKind.Closed ? "CLOSED" : "ESTABLISHED",
            Kind = kind, Source = "ETW",
        });
    }

    private void Udp(DateTime ts, IPAddress local, int lport, IPAddress remote, int rport, int pid, Direction dir)
    {
        var key = $"{pid}|{local}|{lport}|{remote}|{rport}";
        lock (_udpLock)
        {
            // UDP is per-datagram: report each peer once per minute to keep volume sane.
            if (_udpSeen.TryGetValue(key, out var last) && ts - last < TimeSpan.FromMinutes(1)) return;
            _udpSeen[key] = ts;
            if (_udpSeen.Count > 20_000) _udpSeen.Clear();
        }
        _sink?.Invoke(new ConnectionObservation
        {
            Timestamp = new DateTimeOffset(ts), Protocol = TransportProtocol.Udp, Direction = dir, LocalAddress = local, LocalPort = lport,
            RemoteAddress = remote, RemotePort = rport, Pid = pid > 0 ? pid : null, Source = "ETW",
        });
    }

    public void Stop()
    {
        try { _session?.Dispose(); } catch (Exception) { /* session already gone */ }
        _session = null;
    }

    public void Dispose() => Stop();
}

/// <summary>
/// Real-time DNS queries from the Microsoft-Windows-DNS-Client provider (event 3006 query start, 3008 completion),
/// including the requesting PID where Windows records it. Requires administrator rights.
/// </summary>
public sealed class EtwDnsSource : IDnsSource
{
    public const string SessionName = "NetHunterMonitor-Dns";
    private static readonly Guid DnsClientProvider = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
    private TraceEventSession? _session;
    private Thread? _thread;
    private Action<DnsObservation>? _sink;
    private readonly Dictionary<string, (int Pid, DateTime T)> _starts = new(StringComparer.OrdinalIgnoreCase);

    public string Name => "ETW DNS-Client (real-time)";
    public string Capabilities => "Every DNS query and answer, with the requesting process where available. Requires administrator.";
    public bool IsRunning => _session is not null;

    public bool Start(Action<DnsObservation> sink, Action<string> log, out string? reason)
    {
        reason = null;
        if (!Elevation.IsElevated) { reason = "requires administrator (ETW DNS-Client tracing)"; return false; }
        _sink = sink;
        try
        {
            _session = new TraceEventSession(SessionName) { StopOnDispose = true };
            _session.EnableProvider(DnsClientProvider, TraceEventLevel.Informational);
        }
        catch (Exception ex)
        {
            _session?.Dispose();
            _session = null;
            reason = "could not start DNS trace: " + ex.Message;
            return false;
        }

        var parser = new RegisteredTraceEventParser(_session.Source);
        parser.All += OnEvent;
        var session = _session;
        _thread = new Thread(() =>
        {
            try { session.Source.Process(); }
            catch (Exception ex) { log("ETW DNS trace stopped: " + ex.Message); }
        }) { IsBackground = true, Name = "ETW-Dns" };
        _thread.Start();
        return true;
    }

    private void OnEvent(TraceEvent e)
    {
        int id = (int)e.ID;
        if (id != 3006 && id != 3008) return;
        var name = e.PayloadByName("QueryName") as string;
        if (string.IsNullOrWhiteSpace(name)) return;
        int type = Convert.ToInt32(e.PayloadByName("QueryType") ?? 0);
        var key = name + "|" + type;
        if (id == 3006)
        {
            lock (_starts)
            {
                _starts[key] = (e.ProcessID, e.TimeStamp);
                if (_starts.Count > 10_000) _starts.Clear();
            }
            return;
        }

        int pid = e.ProcessID;
        lock (_starts)
        {
            if (_starts.Remove(key, out var s) && e.TimeStamp - s.T < TimeSpan.FromSeconds(30) && s.Pid > 0) pid = s.Pid;
        }
        int status = Convert.ToInt32(e.PayloadByName("QueryStatus") ?? 0);
        var (answers, addrs) = DnsClientResultParser.Parse(e.PayloadByName("QueryResults") as string);
        _sink?.Invoke(new DnsObservation
        {
            Timestamp = new DateTimeOffset(e.TimeStamp), Query = name, RecordType = Core.Pcap.DnsMessageParser.TypeName(type), Pid = pid > 0 ? pid : null,
            Status = status, Answers = answers, ResolvedAddresses = addrs, Source = "ETW-DNS",
        });
    }

    public void Stop()
    {
        try { _session?.Dispose(); } catch (Exception) { }
        _session = null;
    }

    public void Dispose() => Stop();
}
