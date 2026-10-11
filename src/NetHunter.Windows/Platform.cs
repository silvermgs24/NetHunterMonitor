using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using NetHunter.Core.Engine;

namespace NetHunter.Windows;

public static class Elevation
{
    /// <summary>True only when the process token is elevated (UAC-filtered admin tokens report false).</summary>
    public static bool IsElevated
    {
        get
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public static readonly string[] FeaturesRequiringAdmin =
    {
        "Real-time capture of every TCP connection, including ones shorter than the polling interval (ETW kernel TCP/IP)",
        "UDP peer visibility with process attribution (ETW)",
        "DNS queries in real time with the requesting process (ETW DNS-Client)",
        "Path, SHA-256 and signature of processes owned by SYSTEM or other users (OpenProcess is denied otherwise)",
    };

    public static readonly string[] FeaturesWithoutAdmin =
    {
        "TCP connections with owning process (polled), listening TCP/UDP ports",
        "Path, SHA-256 and signature of your own processes",
        "Hostnames from the Windows DNS cache, reverse DNS (PTR)",
        "Local IOC lists, reputation APIs, beacon detection, baseline, alerts, PCAP import",
    };
}

/// <summary>API keys at rest are encrypted with DPAPI (current user scope).</summary>
public sealed class DpapiProtector : ISecretProtector
{
    private static readonly byte[] Prefix = Encoding.ASCII.GetBytes("NHM1");

    public string Protect(string plain)
    {
        var bytes = Encoding.UTF8.GetBytes(plain);
        var input = new Native.DATA_BLOB { cbData = bytes.Length, pbData = Marshal.AllocHGlobal(bytes.Length) };
        try
        {
            Marshal.Copy(bytes, 0, input.pbData, bytes.Length);
            if (!Native.CryptProtectData(ref input, "NetHunter API key", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, Native.CRYPTPROTECT_UI_FORBIDDEN, out var output))
                throw new InvalidOperationException($"DPAPI protect failed ({Marshal.GetLastWin32Error()})");
            try
            {
                var enc = new byte[output.cbData];
                Marshal.Copy(output.pbData, enc, 0, enc.Length);
                return Convert.ToBase64String(Prefix.Concat(enc).ToArray());
            }
            finally { Native.LocalFree(output.pbData); }
        }
        finally
        {
            Marshal.Copy(new byte[bytes.Length], 0, input.pbData, bytes.Length);
            Marshal.FreeHGlobal(input.pbData);
            Array.Clear(bytes);
        }
    }

    public string? Unprotect(string protectedValue)
    {
        byte[] all;
        try { all = Convert.FromBase64String(protectedValue); }
        catch (FormatException) { return null; }
        if (all.Length <= Prefix.Length || !all.AsSpan(0, Prefix.Length).SequenceEqual(Prefix)) return null;
        var enc = all[Prefix.Length..];
        var input = new Native.DATA_BLOB { cbData = enc.Length, pbData = Marshal.AllocHGlobal(enc.Length) };
        try
        {
            Marshal.Copy(enc, 0, input.pbData, enc.Length);
            // Fails (returns null) if the config was copied to another user/machine: keys must be re-entered there.
            if (!Native.CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, Native.CRYPTPROTECT_UI_FORBIDDEN, out var output)) return null;
            try
            {
                var plain = new byte[output.cbData];
                Marshal.Copy(output.pbData, plain, 0, plain.Length);
                return Encoding.UTF8.GetString(plain);
            }
            finally { Native.LocalFree(output.pbData); }
        }
        finally { Marshal.FreeHGlobal(input.pbData); }
    }
}

/// <summary>
/// Pure PTR lookups (DnsQuery_W, type PTR) through the system resolver. Deliberately not Dns.GetHostEntry, which
/// also forward-resolves the PTR name and would plant that name in the DNS cache as if an application had used it.
/// A PTR record is informational only; it does not prove who operates an address.
/// </summary>
public sealed class SystemHostnameResolver : IHostnameResolver
{
    public async Task<string?> ReverseLookupAsync(IPAddress ip, CancellationToken ct) =>
        await Task.Run(() => QueryPtr(ip), ct).WaitAsync(ct).ConfigureAwait(false);

    public static string ReverseName(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork) return $"{b[3]}.{b[2]}.{b[1]}.{b[0]}.in-addr.arpa";
        var sb = new StringBuilder();
        for (int i = b.Length - 1; i >= 0; i--) sb.Append($"{b[i] & 0xF:x}.{b[i] >> 4:x}.");
        return sb.Append("ip6.arpa").ToString();
    }

    private static string? QueryPtr(IPAddress ip)
    {
        int rc = Native.DnsQuery(ReverseName(ip), 12, 0, IntPtr.Zero, out var results, IntPtr.Zero);
        if (rc != 0 || results == IntPtr.Zero) return null;
        try
        {
            int headerSize = Marshal.SizeOf<Native.DNS_RECORD_HEADER>();
            for (var p = results; p != IntPtr.Zero;)
            {
                var h = Marshal.PtrToStructure<Native.DNS_RECORD_HEADER>(p);
                if (h.wType == 12)
                {
                    var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(p + headerSize));
                    if (!string.IsNullOrWhiteSpace(name) && !IPAddress.TryParse(name, out _)) return name.TrimEnd('.');
                }
                p = h.pNext;
            }
            return null;
        }
        finally { Native.DnsFree(results, Native.DnsFreeRecordList); }
    }
}
