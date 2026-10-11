using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using NetHunter.Core.Engine;
using NetHunter.Core.Models;

namespace NetHunter.Windows;

/// <summary>
/// PID → name/path/parent/start time. The Toolhelp snapshot gives name and parent for every process without
/// privileges; the full image path needs PROCESS_QUERY_LIMITED_INFORMATION, which is denied for some
/// SYSTEM/protected processes unless elevated — in that case the path is left empty and the reason recorded.
/// </summary>
public sealed class WindowsProcessInfoProvider : IProcessInfoProvider
{
    private readonly ConcurrentDictionary<int, (ProcessInfo Info, DateTime Fetched)> _cache = new();
    private Dictionary<int, (string Name, int Parent)> _snapshot = new();
    private DateTime _snapshotAt = DateTime.MinValue;
    private readonly object _snapLock = new();
    private readonly bool _elevated = Elevation.IsElevated;

    public ProcessInfo Get(int pid)
    {
        if (pid == 0) return ProcessInfo.Unknown;
        if (pid == 4) return new ProcessInfo { Pid = 4, Name = "System", AttributionNote = "Windows kernel (System process): kernel-mode networking such as SMB" };

        if (_cache.TryGetValue(pid, out var c) && DateTime.UtcNow - c.Fetched < TimeSpan.FromSeconds(30))
        {
            // Cheap PID-reuse check: same PID but a different creation time means a different process.
            var st = StartTime(pid);
            if (st is null || c.Info.StartTime is null || st == c.Info.StartTime) return c.Info;
            c = default;
        }

        var info = Query(pid, c.Info);
        _cache[pid] = (info, DateTime.UtcNow);
        if (_cache.Count > 4096) foreach (var k in _cache.Where(kv => DateTime.UtcNow - kv.Value.Fetched > TimeSpan.FromMinutes(5)).Select(kv => kv.Key).ToList()) _cache.TryRemove(k, out _);
        return info;
    }

    private ProcessInfo Query(int pid, ProcessInfo? previous)
    {
        var snap = Snapshot(pid);
        snap.TryGetValue(pid, out var entry);

        string? path = null;
        DateTimeOffset? start = null;
        string? note = null;
        using (var h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid))
        {
            if (!h.IsInvalid)
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (Native.QueryFullProcessImageName(h, 0, sb, ref size)) path = sb.ToString(0, size);
                if (Native.GetProcessTimes(h, out var creation, out _, out _, out _) && creation > 0) start = DateTimeOffset.FromFileTime(creation);
            }
            else
            {
                int err = Marshal.GetLastWin32Error();
                note = err == 5
                    ? (_elevated ? "Access denied (protected process)" : "Access denied: run as administrator to see this process's path and hash")
                    : err == 87 ? "Process has exited" : $"OpenProcess failed (error {err})";
            }
        }

        if (entry.Name is null && path is null)
        {
            // Process already gone and not in snapshot: keep what we knew about this PID if it is the same process.
            if (previous is { IsKnown: true }) return previous;
            return ProcessInfo.Unknown with { Pid = pid, AttributionNote = note ?? "Process exited before it could be identified" };
        }

        string name = entry.Name ?? Path.GetFileName(path!);
        string? parentName = null;
        int? parentPid = entry.Name is null ? null : entry.Parent;
        if (parentPid is { } ppid && snap.TryGetValue(ppid, out var parent))
        {
            // Guard against PID reuse: a "parent" that started after the child is not the real parent.
            var parentStart = StartTime(ppid);
            parentName = parentStart is null || start is null || parentStart <= start ? parent.Name : null;
        }

        return new ProcessInfo
        {
            Pid = pid, Name = name, Path = path, ParentPid = parentPid, ParentName = parentName, StartTime = start,
            AttributionNote = note, Signature = SignatureInfo.NotChecked,
        };
    }

    private static DateTimeOffset? StartTime(int pid)
    {
        using var h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h.IsInvalid) return null;
        return Native.GetProcessTimes(h, out var creation, out _, out _, out _) && creation > 0 ? DateTimeOffset.FromFileTime(creation) : null;
    }

    private Dictionary<int, (string Name, int Parent)> Snapshot(int wantedPid)
    {
        lock (_snapLock)
        {
            if (_snapshot.ContainsKey(wantedPid) && DateTime.UtcNow - _snapshotAt < TimeSpan.FromSeconds(30)) return _snapshot;
            if (DateTime.UtcNow - _snapshotAt < TimeSpan.FromMilliseconds(250)) return _snapshot;
            _snapshot = TakeSnapshot();
            _snapshotAt = DateTime.UtcNow;
            return _snapshot;
        }
    }

    public static Dictionary<int, (string Name, int Parent)> TakeSnapshot()
    {
        var map = new Dictionary<int, (string, int)>();
        using var snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
        if (snap.IsInvalid) return map;
        var e = new Native.PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<Native.PROCESSENTRY32W>() };
        if (!Native.Process32First(snap, ref e)) return map;
        do { map[(int)e.th32ProcessID] = (e.szExeFile, (int)e.th32ParentProcessID); }
        while (Native.Process32Next(snap, ref e));
        return map;
    }
}
