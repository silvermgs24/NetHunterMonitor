using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using NetHunter.Core.Models;
using NetHunter.Core.Util;

namespace NetHunter.Windows.Tests;

/// <summary>
/// These tests run against the real Windows APIs on the machine executing them (no mocks): they open real
/// sockets in the test process and verify that the collectors attribute them to this process.
/// </summary>
public class ProcessAttributionTests
{
    [Fact]
    public async Task Tcp_table_attributes_our_own_connection_to_our_pid_path_and_hash()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using var server = await listener.AcceptTcpClientAsync();
        int clientPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;
        int myPid = Environment.ProcessId;

        var rows = IpHelperTables.GetTcp();
        var listen = Assert.Single(rows, r => r.LocalPort == port && r.State == TcpState.Listen);
        Assert.Equal(myPid, listen.Pid);
        var outbound = Assert.Single(rows, r => r.LocalPort == clientPort && r.RemotePort == port);
        Assert.Equal(myPid, outbound.Pid);
        Assert.Equal(TcpState.Established, outbound.State);

        var info = new WindowsProcessInfoProvider().Get(myPid);
        Assert.Equal(myPid, info.Pid);
        Assert.Equal(Path.GetFileName(Environment.ProcessPath), info.Name, ignoreCase: true);
        Assert.Equal(Environment.ProcessPath, info.Path, ignoreCase: true);
        Assert.NotNull(info.StartTime);
        Assert.NotNull(info.ParentName);

        var hash = new FileHasher().TryHash(info.Path!, out _);
        using var fs = File.OpenRead(Environment.ProcessPath!);
        Assert.Equal(FileHasher.ComputeSha256(fs), hash);
    }

    [Fact]
    public void Polling_source_reports_open_and_close_with_direction()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var seen = new List<ConnectionObservation>();
        var src = new IpHelperConnectionSource(() => 100000); // we drive Poll() manually
        Assert.True(src.Start(o => { lock (seen) seen.Add(o); }, _ => { }, out _));
        try
        {
            Thread.Sleep(300);
            using (var client = new TcpClient())
            {
                client.Connect(IPAddress.Loopback, port);
                using var accepted = listener.AcceptTcpClient();
                src.Poll();
                lock (seen)
                {
                    Assert.Contains(seen, o => o.Kind == ObservationKind.Opened && o.RemotePort == port && o.Direction == Direction.Outbound && o.Pid == Environment.ProcessId);
                    Assert.Contains(seen, o => o.Kind == ObservationKind.Opened && o.LocalPort == port && o.Direction == Direction.Inbound && o.Pid == Environment.ProcessId);
                }
            }
            Thread.Sleep(200);
            src.Poll();
            lock (seen) Assert.Contains(seen, o => (o.Kind is ObservationKind.Closed or ObservationKind.StateChanged) && (o.RemotePort == port || o.LocalPort == port));
        }
        finally { src.Stop(); }
    }

    [Fact]
    public void Listeners_include_our_listening_socket()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int udpPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        var l = new IpHelperConnectionSource(() => 1000).GetListeners();
        Assert.Contains(l, x => x.Protocol == TransportProtocol.Tcp && x.Port == port && x.Pid == Environment.ProcessId);
        Assert.Contains(l, x => x.Protocol == TransportProtocol.Udp && x.Port == udpPort && x.Pid == Environment.ProcessId);
    }

    [Fact]
    public void Exited_process_is_unknown_not_guessed()
    {
        var p = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit 0") { CreateNoWindow = true, UseShellExecute = false })!;
        int pid = p.Id;
        p.WaitForExit();
        p.Dispose();
        Thread.Sleep(200);
        var info = new WindowsProcessInfoProvider().Get(pid);
        // Either the PID is gone (Unknown) or it was reused by another live process; never a stale guess.
        if (!info.IsKnown) Assert.Equal("Unknown", info.Name);
        else Assert.NotNull(info.StartTime);
    }

    [Fact]
    public void System_and_idle_pids_are_handled()
    {
        var prov = new WindowsProcessInfoProvider();
        Assert.False(prov.Get(0).IsKnown);
        Assert.Equal("System", prov.Get(4).Name);
    }
}

public class SignatureTests
{
    [Fact]
    public void Windows_binary_is_signed_by_microsoft()
    {
        var s = new AuthenticodeVerifier().Verify(Path.Combine(Environment.SystemDirectory, "notepad.exe"));
        Assert.True(s.IsTrusted, s.ToString());
        Assert.True(s.IsMicrosoft, s.ToString());
    }

    [Fact]
    public void Catalog_signed_system_file_is_trusted()
    {
        // Many in-box binaries carry no embedded signature and are only signed through security catalogs.
        var candidates = new[] { "drivers\\etc\\hosts" }.Select(f => Path.Combine(Environment.SystemDirectory, f));
        var dll = Directory.EnumerateFiles(Environment.SystemDirectory, "*.dll").Take(200)
            .Select(f => new AuthenticodeVerifier().Verify(f)).FirstOrDefault(s => s.Status == SignatureStatus.CatalogSigned);
        Assert.NotNull(dll);
        Assert.True(dll!.IsTrusted);
        _ = candidates;
    }

    [Fact]
    public void Unsigned_file_is_reported_unsigned()
    {
        var path = Path.Combine(Path.GetTempPath(), "nh-unsigned-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(path, new byte[] { 0x4D, 0x5A, 0, 0, 1, 2, 3 });
        try
        {
            var s = new AuthenticodeVerifier().Verify(path);
            Assert.Equal(SignatureStatus.Unsigned, s.Status);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Tampered_signed_file_is_invalid()
    {
        // Copy a signed binary and flip a byte in the code section: the embedded signature must no longer verify.
        var src = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        var dst = Path.Combine(Path.GetTempPath(), "nh-tampered-" + Guid.NewGuid().ToString("N") + ".exe");
        var bytes = File.ReadAllBytes(src);
        var embedded = new AuthenticodeVerifier().Verify(src);
        if (embedded.Status != SignatureStatus.Signed) return; // catalog-only on this build: nothing embedded to tamper with
        bytes[0x400] ^= 0xFF;
        File.WriteAllBytes(dst, bytes);
        try { Assert.Equal(SignatureStatus.Invalid, new AuthenticodeVerifier().Verify(dst).Status); }
        finally { File.Delete(dst); }
    }
}

public class PlatformTests
{
    [Fact]
    public void Dpapi_round_trip_and_rejects_tampering()
    {
        var p = new DpapiProtector();
        var enc = p.Protect("my-api-key");
        Assert.DoesNotContain("my-api-key", enc);
        Assert.Equal("my-api-key", p.Unprotect(enc));
        var bytes = Convert.FromBase64String(enc);
        bytes[^1] ^= 0x55;
        Assert.Null(p.Unprotect(Convert.ToBase64String(bytes)));
        Assert.Null(p.Unprotect("not base64!!"));
    }

    [Fact]
    public void Reverse_names_are_built_correctly()
    {
        Assert.Equal("4.3.2.1.in-addr.arpa", SystemHostnameResolver.ReverseName(IPAddress.Parse("1.2.3.4")));
        Assert.Equal("1." + string.Concat(Enumerable.Repeat("0.", 23)) + "8.b.d.0.1.0.0.2.ip6.arpa",
            SystemHostnameResolver.ReverseName(IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public async Task Ptr_lookup_for_loopback_never_throws()
    {
        // Result depends on the resolver; the contract is "string or null", never an exception.
        _ = await new SystemHostnameResolver().ReverseLookupAsync(IPAddress.Loopback, CancellationToken.None);
    }

    [Fact]
    public void Dns_cache_can_be_read_and_grouped()
    {
        var records = DnsCacheSource.ReadCache();
        var obs = DnsCacheSource.ToObservations(records, DateTimeOffset.Now);
        Assert.All(obs, o => Assert.Equal("DNS-CACHE", o.Source));
        // Grouping logic on synthetic records (CNAME chain + A record).
        var grouped = DnsCacheSource.ToObservations(new[]
        {
            new DnsCacheRecord("www.example.com", "www.example.com", 5, 0, 60, "edge.example.net"),
            new DnsCacheRecord("www.example.com", "edge.example.net", 1, 0, 30, "93.184.216.34"),
            new DnsCacheRecord("missing.example", "missing.example", 1, 9003, 0, null),
            new DnsCacheRecord("v4only.example", "v4only.example", 28, 9501, 0, null),
        }, DateTimeOffset.Now);
        var www = grouped.Single(o => o.Query == "www.example.com");
        Assert.Equal(IPAddress.Parse("93.184.216.34"), Assert.Single(www.ResolvedAddresses));
        Assert.Contains("CNAME edge.example.net", www.Answers);
        Assert.Equal(30, www.Ttl);
        Assert.Equal(9003, grouped.Single(o => o.Query == "missing.example").Status);
        Assert.DoesNotContain(grouped, o => o.Query == "v4only.example");
    }

    [Fact]
    public void Etw_sources_refuse_cleanly_when_not_elevated()
    {
        if (Elevation.IsElevated) return; // covered by manual elevated run
        Assert.False(new EtwNetworkSource().Start(_ => { }, _ => { }, out var why));
        Assert.Contains("administrator", why);
        Assert.False(new EtwDnsSource().Start(_ => { }, _ => { }, out var why2));
        Assert.Contains("administrator", why2);
    }
}
