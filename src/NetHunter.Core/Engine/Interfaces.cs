using System.Net;
using NetHunter.Core.Models;

namespace NetHunter.Core.Engine;

/// <summary>A collector that reports connection observations (IP Helper polling, ETW, synthetic generator...).</summary>
public interface IConnectionSource : IDisposable
{
    string Name { get; }
    /// <summary>Human-readable description of what this source can and cannot see.</summary>
    string Capabilities { get; }
    bool IsRunning { get; }
    /// <summary>Starts the source. Returns false (with reason) when it cannot run, e.g. not elevated.</summary>
    bool Start(Action<ConnectionObservation> sink, Action<string> log, out string? reason);
    void Stop();
}

public interface IDnsSource : IDisposable
{
    string Name { get; }
    string Capabilities { get; }
    bool IsRunning { get; }
    bool Start(Action<DnsObservation> sink, Action<string> log, out string? reason);
    void Stop();
}

public interface IListeningPortProvider
{
    IReadOnlyList<ListeningEndpoint> GetListeners();
}

/// <summary>Cheap process identity (name, path, parent, start time). Must be fast; called inline.</summary>
public interface IProcessInfoProvider
{
    ProcessInfo Get(int pid);
}

/// <summary>Authenticode verification (embedded or catalog). Potentially slow; called on a background thread.</summary>
public interface ISignatureVerifier
{
    SignatureInfo Verify(string path);
}

public interface IHostnameResolver
{
    /// <summary>PTR lookup. Returns null when there is no record or on failure. Must honour cancellation/timeouts.</summary>
    Task<string?> ReverseLookupAsync(IPAddress ip, CancellationToken ct);
}

public sealed class SourceStatus
{
    public string Name { get; init; } = "";
    public string Capabilities { get; init; } = "";
    public bool Running { get; set; }
    public string? Problem { get; set; }
}
