namespace TouchQue.Relay;

/// <summary>
/// Counter storage for <see cref="FixedWindowLimiter"/>. <see cref="HitAsync"/> must
/// atomically count one hit for the key in its current fixed window and return the
/// count in that window (this hit included) and when the window ends (unix ms). A new
/// window (count 1, resetAt = now + window) starts when none is open for the key or the
/// open one has ended. Several instances: implement it over Redis (<c>INCR</c> +
/// <c>PEXPIRE</c> when the count is 1, then <c>PTTL</c>).
/// </summary>
public interface IRateLimitStore
{
    ValueTask<(int Count, long ResetAt)> HitAsync(string key, long windowMs, long nowMs, CancellationToken ct = default);
}

/// <summary>
/// In-process <see cref="IRateLimitStore"/>, bounded: once full, expired windows are
/// dropped, and if it is still full the oldest half goes.
/// </summary>
public sealed class MemoryRateLimitStore : IRateLimitStore
{
    private readonly Dictionary<string, (int Count, long ResetAt)> _entries = new();
    private readonly int _maxEntries;

    public MemoryRateLimitStore(int maxEntries = 50_000) => _maxEntries = Math.Max(2, maxEntries);

    public ValueTask<(int Count, long ResetAt)> HitAsync(string key, long windowMs, long nowMs, CancellationToken ct = default)
    {
        lock (_entries)
        {
            if (!_entries.TryGetValue(key, out var entry) || entry.ResetAt <= nowMs)
            {
                if (!_entries.ContainsKey(key) && _entries.Count >= _maxEntries) Prune(nowMs);
                entry = (0, nowMs + windowMs);
            }
            entry = (entry.Count + 1, entry.ResetAt);
            _entries[key] = entry;
            return ValueTask.FromResult(entry);
        }
    }

    private void Prune(long nowMs)
    {
        foreach (var k in _entries.Where(e => e.Value.ResetAt <= nowMs).Select(e => e.Key).ToList()) _entries.Remove(k);
        if (_entries.Count >= _maxEntries)
        {
            // Still full (a flood of distinct keys): drop the oldest half rather than grow without bound.
            foreach (var k in _entries.OrderBy(e => e.Value.ResetAt).Take(_maxEntries / 2 + 1).Select(e => e.Key).ToList()) _entries.Remove(k);
        }
    }
}

/// <summary>Rate limits of the relay's pre-auth routes.</summary>
public sealed record RateLimitOptions
{
    public TimeSpan Window { get; init; } = TimeSpan.FromMinutes(1);
    /// <summary>Requests per client IP per route per window.</summary>
    public int PerIp { get; init; } = 20;
    /// <summary>Requests per username per route per window.</summary>
    public int PerUser { get; init; } = 5;
    /// <summary>Where the counters live (default: in this process).</summary>
    public IRateLimitStore? Store { get; init; }
}

/// <summary>Fixed-window rate limiter: protects your server (and your TouchQue quota) from scripted abuse of public routes.</summary>
public sealed class FixedWindowLimiter
{
    private readonly long _windowMs;
    private readonly IRateLimitStore _store;

    public FixedWindowLimiter(RateLimitOptions? options = null)
    {
        var o = options ?? new RateLimitOptions();
        _windowMs = (long)o.Window.TotalMilliseconds;
        PerIp = o.PerIp;
        PerUser = o.PerUser;
        _store = o.Store ?? new MemoryRateLimitStore();
    }

    public int PerIp { get; }
    public int PerUser { get; }

    /// <summary>Counts one hit. Returns seconds to wait when over the limit, otherwise 0.</summary>
    public async ValueTask<int> HitAsync(string key, int limit, long? nowMs = null, CancellationToken ct = default)
    {
        var now = nowMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var (count, resetAt) = await _store.HitAsync(key, _windowMs, now, ct).ConfigureAwait(false);
        if (count <= limit) return 0;
        return Math.Max(1, (int)Math.Ceiling((resetAt - now) / 1000.0));
    }
}
