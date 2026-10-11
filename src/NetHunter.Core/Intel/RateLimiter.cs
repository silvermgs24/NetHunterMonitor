namespace NetHunter.Core.Intel;

/// <summary>
/// Sliding-window limiter enforcing both a per-minute and a per-day budget, plus server-requested
/// back-off (HTTP 429 / Retry-After). Thread-safe. Time is injectable for tests.
/// </summary>
public sealed class RateLimiter
{
    private readonly object _lock = new();
    private readonly Queue<DateTimeOffset> _minute = new();
    private readonly Queue<DateTimeOffset> _day = new();
    private DateTimeOffset _blockedUntil = DateTimeOffset.MinValue;

    public RateLimiter(int perMinute, int perDay)
    {
        PerMinute = perMinute;
        PerDay = perDay;
    }

    public int PerMinute { get; set; }
    public int PerDay { get; set; }

    public int UsedToday { get { lock (_lock) return _day.Count; } }

    /// <summary>Consumes a slot if available. Otherwise returns false and the earliest time a slot frees up.</summary>
    public bool TryAcquire(DateTimeOffset now, out DateTimeOffset retryAt)
    {
        lock (_lock)
        {
            Trim(now);
            retryAt = now;
            if (now < _blockedUntil) { retryAt = _blockedUntil; return false; }
            if (_day.Count >= PerDay) { retryAt = _day.Peek().AddDays(1); return false; }
            if (_minute.Count >= PerMinute) { retryAt = _minute.Peek().AddMinutes(1); return false; }
            _minute.Enqueue(now);
            _day.Enqueue(now);
            return true;
        }
    }

    public void BlockUntil(DateTimeOffset until)
    {
        lock (_lock) if (until > _blockedUntil) _blockedUntil = until;
    }

    private void Trim(DateTimeOffset now)
    {
        while (_minute.Count > 0 && now - _minute.Peek() >= TimeSpan.FromMinutes(1)) _minute.Dequeue();
        while (_day.Count > 0 && now - _day.Peek() >= TimeSpan.FromDays(1)) _day.Dequeue();
    }
}
