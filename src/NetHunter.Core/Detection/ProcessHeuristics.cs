using NetHunter.Core.Models;

namespace NetHunter.Core.Detection;

/// <summary>Process-level signals: where the binary lives, signature, masquerading, LOLBins, parentage.</summary>
public static class ProcessHeuristics
{
    // System binaries frequently impersonated by malware, with the directories they legitimately run from.
    private static readonly Dictionary<string, string[]> SystemBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost.exe"] = new[] { @"\windows\system32\", @"\windows\syswow64\" },
        ["lsass.exe"] = new[] { @"\windows\system32\" },
        ["csrss.exe"] = new[] { @"\windows\system32\" },
        ["services.exe"] = new[] { @"\windows\system32\" },
        ["winlogon.exe"] = new[] { @"\windows\system32\" },
        ["wininit.exe"] = new[] { @"\windows\system32\" },
        ["smss.exe"] = new[] { @"\windows\system32\" },
        ["spoolsv.exe"] = new[] { @"\windows\system32\" },
        ["taskhostw.exe"] = new[] { @"\windows\system32\" },
        ["dllhost.exe"] = new[] { @"\windows\system32\", @"\windows\syswow64\" },
        ["conhost.exe"] = new[] { @"\windows\system32\" },
        ["rundll32.exe"] = new[] { @"\windows\system32\", @"\windows\syswow64\" },
        ["explorer.exe"] = new[] { @"\windows\" },
        ["lsm.exe"] = new[] { @"\windows\system32\" },
        ["sihost.exe"] = new[] { @"\windows\system32\" },
        ["runtimebroker.exe"] = new[] { @"\windows\system32\" },
    };

    // Living-off-the-land binaries: legitimate tools abused for download/C2. Strength reflects how unusual
    // an external connection from them is on a typical workstation.
    private static readonly Dictionary<string, double> Lolbins = new(StringComparer.OrdinalIgnoreCase)
    {
        ["powershell.exe"] = 0.22, ["pwsh.exe"] = 0.15, ["powershell_ise.exe"] = 0.22, ["cmd.exe"] = 0.3,
        ["mshta.exe"] = 0.4, ["rundll32.exe"] = 0.3, ["regsvr32.exe"] = 0.4, ["wscript.exe"] = 0.35, ["cscript.exe"] = 0.35,
        ["certutil.exe"] = 0.35, ["bitsadmin.exe"] = 0.25, ["installutil.exe"] = 0.4, ["regasm.exe"] = 0.4, ["regsvcs.exe"] = 0.4,
        ["msbuild.exe"] = 0.3, ["wmic.exe"] = 0.3, ["hh.exe"] = 0.35, ["forfiles.exe"] = 0.35, ["msxsl.exe"] = 0.4,
        ["cmstp.exe"] = 0.4, ["odbcconf.exe"] = 0.4, ["ieexec.exe"] = 0.4, ["finger.exe"] = 0.4, ["ftp.exe"] = 0.2,
        // Processes that should essentially never talk to the Internet: classic injection targets.
        ["notepad.exe"] = 0.45, ["calc.exe"] = 0.45, ["mspaint.exe"] = 0.4, ["write.exe"] = 0.4, ["werfault.exe"] = 0.15,
    };

    private static readonly HashSet<string> OfficeApps = new(StringComparer.OrdinalIgnoreCase)
    { "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe", "visio.exe" };

    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    { "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe" };

    public static bool IsLolbin(string name) => Lolbins.ContainsKey(name);

    public static IReadOnlyList<Evidence> Analyze(ProcessInfo p, DateTimeOffset connectionTime, bool externalDestination)
    {
        var ev = new List<Evidence>();
        if (!p.IsKnown) return ev;
        var path = p.Path?.ToLowerInvariant();
        var name = p.Name;

        if (path is not null)
        {
            if (path.Contains(@"\$recycle.bin\"))
                ev.Add(new Evidence(EvidenceCategory.Process, "Executable runs from the Recycle Bin", 0.45));
            else if (path.Contains(@"\appdata\local\temp\") || path.Contains(@"\windows\temp\") || path.Contains(@"\temp\"))
                ev.Add(new Evidence(EvidenceCategory.Process, "Executable runs from a temporary directory", 0.3));
            else if (path.Contains(@"\users\public\"))
                ev.Add(new Evidence(EvidenceCategory.Process, @"Executable runs from C:\Users\Public", 0.3));
            else if (path.Contains(@"\downloads\"))
                ev.Add(new Evidence(EvidenceCategory.Process, "Executable runs from a Downloads folder", 0.15));
            else if (path.Contains(@"\appdata\roaming\"))
                ev.Add(new Evidence(EvidenceCategory.Process, @"Executable runs from AppData\Roaming (user-writable)", 0.12));
            else if (IsDirectlyUnder(path, @"\programdata\"))
                ev.Add(new Evidence(EvidenceCategory.Process, @"Executable runs from the root of C:\ProgramData", 0.15));
            else if (path.Contains(@"\appdata\local\") && !path.Contains(@"\appdata\local\microsoft\") && !path.Contains(@"\appdata\local\programs\"))
                ev.Add(new Evidence(EvidenceCategory.Process, @"Executable runs from AppData\Local (user-writable)", 0.05));

            // Must be <drive>:\windows\...\name.exe exactly; "C:\Users\x\windows\explorer.exe" is not legitimate.
            if (SystemBinaries.TryGetValue(name, out var dirs) &&
                !dirs.Any(d => path.Length > 2 && path[1] == ':' && path[2..].StartsWith(d, StringComparison.Ordinal) && IsDirectlyUnder(path, d)))
                ev.Add(new Evidence(EvidenceCategory.Process, $"'{name}' is running from an unexpected location ({p.Path}): possible masquerading", 0.6));
        }

        switch (p.Signature.Status)
        {
            case SignatureStatus.Invalid:
                ev.Add(new Evidence(EvidenceCategory.Process, "Executable has an INVALID digital signature (tampered or bad certificate)", 0.45));
                break;
            case SignatureStatus.Unsigned when externalDestination:
                ev.Add(new Evidence(EvidenceCategory.Process, "Unsigned executable communicating externally", 0.15));
                break;
            case SignatureStatus.Signed or SignatureStatus.CatalogSigned when p.Signature.IsMicrosoft && SystemBinaries.ContainsKey(name):
                break;
        }

        if (externalDestination && Lolbins.TryGetValue(name, out var lol))
            ev.Add(new Evidence(EvidenceCategory.Process, $"{name} is a living-off-the-land binary that rarely needs direct Internet access", lol));

        if (p.ParentName is { } parent)
        {
            if (OfficeApps.Contains(parent) && ScriptHosts.Contains(name))
                ev.Add(new Evidence(EvidenceCategory.Process, $"Unusual parent: {name} was started by Office application {parent}", 0.4));
            if (name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase) && !parent.Equals("services.exe", StringComparison.OrdinalIgnoreCase))
                ev.Add(new Evidence(EvidenceCategory.Process, $"Unusual parent: svchost.exe started by {parent} (expected services.exe)", 0.35));
            if (ScriptHosts.Contains(name) && (parent.Equals("wmiprvse.exe", StringComparison.OrdinalIgnoreCase) || parent.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase)))
                ev.Add(new Evidence(EvidenceCategory.Process, $"Unusual parent: {name} spawned by {parent}", 0.25));
        }

        if (externalDestination && p.StartTime is { } st && connectionTime - st is { TotalSeconds: >= 0 and < 30 })
            ev.Add(new Evidence(EvidenceCategory.Process, $"Connection started {(connectionTime - st).TotalSeconds:0} s after the process launched", 0.04));

        return ev;
    }

    private static bool IsDirectlyUnder(string path, string dir)
    {
        var i = path.IndexOf(dir, StringComparison.Ordinal);
        if (i < 0) return false;
        var rest = path[(i + dir.Length)..];
        return !rest.Contains('\\');
    }
}

public static class PortHeuristics
{
    private static readonly Dictionary<int, string> SuspiciousPorts = new()
    {
        [4444] = "Metasploit default", [4445] = "Metasploit alt", [1337] = "common RAT/backdoor", [31337] = "classic backdoor",
        [6666] = "IRC/backdoor", [6667] = "IRC (botnet C2)", [6697] = "IRC over TLS", [9001] = "Tor relay", [9030] = "Tor directory",
        [9050] = "Tor SOCKS", [9150] = "Tor Browser SOCKS", [1080] = "SOCKS proxy", [5555] = "Android debug / RAT", [12345] = "NetBus",
        [54321] = "backdoor", [2222] = "alternate SSH / RAT", [8888] = "common RAT/panel", [7777] = "common RAT", [3333] = "crypto-mining pool",
        [14444] = "crypto-mining pool", [45700] = "crypto-mining pool", [5900] = "VNC", [5938] = "TeamViewer",
    };

    private static readonly HashSet<int> CommonPorts = new()
    {
        80, 443, 53, 853, 123, 8080, 8443, 993, 995, 465, 587, 25, 143, 110, 22, 21, 3389, 5222, 5223, 5228, 1935,
        3478, 3479, 3480, 3481, 445, 139, 135, 389, 636, 88, 3268, 3269, 5985, 5986, 1433, 3306, 5432, 6379, 27017,
        9443, 4443, 8000, 8008, 8081, 7680, 1900, 5353, 5355, 137, 138, 67, 68, 500, 4500, 1194, 51820, 19302, 19305, 554,
    };

    public static bool IsCommon(int port) => CommonPorts.Contains(port);

    public static Evidence? Evaluate(int remotePort, Direction direction)
    {
        if (direction == Direction.Inbound) return null;
        if (SuspiciousPorts.TryGetValue(remotePort, out var why))
            return new Evidence(EvidenceCategory.Network, $"Destination port {remotePort} is commonly associated with {why}", remotePort is 5900 or 5938 ? 0.08 : 0.25);
        if (!CommonPorts.Contains(remotePort) && remotePort < 49152)
            return new Evidence(EvidenceCategory.Network, $"Unusual destination port {remotePort}", 0.08);
        if (remotePort >= 49152)
            return new Evidence(EvidenceCategory.Network, $"Outbound connection to an ephemeral-range port ({remotePort})", 0.1);
        return null;
    }

    /// <summary>Risk of a local listening service. Well-known risky listeners are flagged, not condemned.</summary>
    public static IReadOnlyList<Evidence> EvaluateListener(int port, bool bindsAllInterfaces, ProcessInfo p)
    {
        var ev = new List<Evidence>();
        if (SuspiciousPorts.TryGetValue(port, out var why))
            ev.Add(new Evidence(EvidenceCategory.Network, $"Listening on port {port} ({why})", 0.4));
        if (port == 3389 && bindsAllInterfaces)
            ev.Add(new Evidence(EvidenceCategory.Network, "Remote Desktop is exposed on all interfaces", 0.2));
        if (port is 445 or 139 or 5985 or 5986 && bindsAllInterfaces)
            ev.Add(new Evidence(EvidenceCategory.Network, $"Remote administration/file sharing port {port} exposed on all interfaces", 0.08));
        if (bindsAllInterfaces && !p.Signature.IsTrusted && p.Signature.Status != SignatureStatus.NotChecked && p.IsKnown)
            ev.Add(new Evidence(EvidenceCategory.Process, "Unsigned process listening on all interfaces", 0.25));
        if (!p.IsKnown)
            ev.Add(new Evidence(EvidenceCategory.Process, "Owning process could not be identified", 0.05));
        return ev;
    }
}
