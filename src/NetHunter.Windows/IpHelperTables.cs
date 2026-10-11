using System.Net;
using System.Runtime.InteropServices;
using NetHunter.Core.Models;

namespace NetHunter.Windows;

public readonly record struct TcpRow(IPAddress LocalAddress, int LocalPort, IPAddress RemoteAddress, int RemotePort, TcpState State, int Pid);
public readonly record struct UdpRow(IPAddress LocalAddress, int LocalPort, int Pid);

public enum TcpState
{
    Closed = 1, Listen = 2, SynSent = 3, SynReceived = 4, Established = 5, FinWait1 = 6, FinWait2 = 7,
    CloseWait = 8, Closing = 9, LastAck = 10, TimeWait = 11, DeleteTcb = 12,
}

/// <summary>
/// Reads the kernel's TCP/UDP endpoint tables with owning PIDs (GetExtendedTcpTable / GetExtendedUdpTable).
/// Works without administrator rights on Windows 10/11.
/// </summary>
public static class IpHelperTables
{
    public static string StateName(TcpState s) => s switch
    {
        TcpState.Closed => "CLOSED", TcpState.Listen => "LISTEN", TcpState.SynSent => "SYN_SENT", TcpState.SynReceived => "SYN_RECEIVED",
        TcpState.Established => "ESTABLISHED", TcpState.FinWait1 => "FIN_WAIT1", TcpState.FinWait2 => "FIN_WAIT2", TcpState.CloseWait => "CLOSE_WAIT",
        TcpState.Closing => "CLOSING", TcpState.LastAck => "LAST_ACK", TcpState.TimeWait => "TIME_WAIT", TcpState.DeleteTcb => "DELETE_TCB",
        _ => "UNKNOWN",
    };

    internal static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    public static List<TcpRow> GetTcp()
    {
        var list = new List<TcpRow>(512);
        ReadTable(true, Native.AF_INET, buf => ParseTcp4(buf, list));
        ReadTable(true, Native.AF_INET6, buf => ParseTcp6(buf, list));
        return list;
    }

    public static List<UdpRow> GetUdp()
    {
        var list = new List<UdpRow>(256);
        ReadTable(false, Native.AF_INET, buf => ParseUdp4(buf, list));
        ReadTable(false, Native.AF_INET6, buf => ParseUdp6(buf, list));
        return list;
    }

    private static void ReadTable(bool tcp, int af, Action<IntPtr> parse)
    {
        int size = 0;
        for (int attempt = 0; attempt < 5; attempt++)
        {
            uint rc = tcp
                ? Native.GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, Native.TCP_TABLE_OWNER_PID_ALL, 0)
                : Native.GetExtendedUdpTable(IntPtr.Zero, ref size, false, af, Native.UDP_TABLE_OWNER_PID, 0);
            if (rc != Native.ERROR_INSUFFICIENT_BUFFER && rc != 0) throw new InvalidOperationException($"IP Helper query failed (error {rc})");
            size += 4096; // the table can grow between calls
            var buf = Marshal.AllocHGlobal(size);
            try
            {
                rc = tcp
                    ? Native.GetExtendedTcpTable(buf, ref size, false, af, Native.TCP_TABLE_OWNER_PID_ALL, 0)
                    : Native.GetExtendedUdpTable(buf, ref size, false, af, Native.UDP_TABLE_OWNER_PID, 0);
                if (rc == 0) { parse(buf); return; }
                if (rc != Native.ERROR_INSUFFICIENT_BUFFER) throw new InvalidOperationException($"IP Helper query failed (error {rc})");
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        throw new InvalidOperationException("IP Helper table kept growing; giving up this cycle");
    }

    private static unsafe void ParseTcp4(IntPtr buf, List<TcpRow> list)
    {
        int n = Marshal.ReadInt32(buf);
        var rows = (Native.MIB_TCPROW_OWNER_PID*)(buf + 4);
        for (int i = 0; i < n; i++)
        {
            var r = rows[i];
            list.Add(new TcpRow(new IPAddress(r.LocalAddr), Port(r.LocalPort), new IPAddress(r.RemoteAddr), Port(r.RemotePort), (TcpState)r.State, (int)r.OwningPid));
        }
    }

    private static unsafe void ParseTcp6(IntPtr buf, List<TcpRow> list)
    {
        int n = Marshal.ReadInt32(buf);
        var rows = (Native.MIB_TCP6ROW_OWNER_PID*)(buf + 4);
        for (int i = 0; i < n; i++)
        {
            var r = rows[i];
            var la = new IPAddress(new ReadOnlySpan<byte>(r.LocalAddr, 16), r.LocalScopeId);
            var ra = new IPAddress(new ReadOnlySpan<byte>(r.RemoteAddr, 16), r.RemoteScopeId);
            list.Add(new TcpRow(la, Port(r.LocalPort), ra, Port(r.RemotePort), (TcpState)r.State, (int)r.OwningPid));
        }
    }

    private static unsafe void ParseUdp4(IntPtr buf, List<UdpRow> list)
    {
        int n = Marshal.ReadInt32(buf);
        var rows = (Native.MIB_UDPROW_OWNER_PID*)(buf + 4);
        for (int i = 0; i < n; i++) list.Add(new UdpRow(new IPAddress(rows[i].LocalAddr), Port(rows[i].LocalPort), (int)rows[i].OwningPid));
    }

    private static unsafe void ParseUdp6(IntPtr buf, List<UdpRow> list)
    {
        int n = Marshal.ReadInt32(buf);
        var rows = (Native.MIB_UDP6ROW_OWNER_PID*)(buf + 4);
        for (int i = 0; i < n; i++)
        {
            var r = rows[i];
            list.Add(new UdpRow(new IPAddress(new ReadOnlySpan<byte>(r.LocalAddr, 16), r.LocalScopeId), Port(r.LocalPort), (int)r.OwningPid));
        }
    }
}
