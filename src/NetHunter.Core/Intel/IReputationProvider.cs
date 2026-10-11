using NetHunter.Core.Models;

namespace NetHunter.Core.Intel;

/// <summary>
/// Pluggable reputation source. Implementations must never throw for expected failures
/// (offline, HTTP errors, bad JSON); they return a result with the appropriate <see cref="ReputationStatus"/>.
/// </summary>
public interface IReputationProvider
{
    string Name { get; }
    /// <summary>Local providers never touch the network and are consulted before remote ones.</summary>
    bool IsLocal { get; }
    bool IsEnabled { get; }
    bool Supports(IocType type);
    Task<ReputationResult> LookupAsync(IocType type, string value, CancellationToken ct);
}

/// <summary>Remote providers expose their rate limits so the service can schedule requests.</summary>
public interface IRemoteReputationProvider : IReputationProvider
{
    RateLimiter Limiter { get; }
}
