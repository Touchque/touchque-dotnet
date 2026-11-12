using Touchque.Relay;
using Xunit;

namespace Touchque.Tests;

/// <summary>The relay's POST /login: every start is charged like a fresh attempt, and guard refusals carry their state in headers.</summary>
[Collection("fake-api")]
public class RelayChargeTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public RelayChargeTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private static RelayRequest<string> Login(string user, string? token = null) => new()
    {
        Method = "POST", Path = "/login", Ip = "203.0.113.7", UserAgent = "UA", Native = user,
        Header = h => string.Equals(h, Guard.TokenHeader, StringComparison.OrdinalIgnoreCase) ? token : null,
    };

    private static string? Header(RelayResponse r, string name) =>
        r.Headers.Where(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Select(h => h.Value).LastOrDefault();

    private async Task<int> PushesAsync() => (await _api.CallsAsync()).Count(c => (string?)c!["path"] == "/login/request");

    [Fact]
    public async Task PollsThatKeepTheQrAreFreeAndEveryPushAReplayStartsIsCharged()
    {
        // 5 per user a minute (the default).
        var relay = new RelayHandler<string>(_api.Client(), new RelayOptions<string> { GetUserId = u => u, GetLoginUser = u => u });
        var first = (await relay.HandleAsync(Login("victim@acme.com")))!; // a fresh attempt: 1 of 5
        var token = (string)first.Body["token"]!;
        // Polls that only keep the QR are never charged.
        for (var i = 0; i < 8; i++)
        {
            var keep = (await relay.HandleAsync(Login("victim@acme.com", token)))!;
            Assert.Equal((202, "enroll"), (keep.Status, (string?)keep.Body["touchque"]?["state"]));
        }
        // Linked: each replay of the first token would start a push. Each is charged: 2 to 5 of 5, then 429.
        await _api.LinkAsync("victim@acme.com");
        var before = await PushesAsync();
        var statuses = new List<int>();
        for (var i = 0; i < 6; i++) statuses.Add((await relay.HandleAsync(Login("victim@acme.com", token)))!.Status);
        Assert.Equal(new[] { 202, 202, 202, 202, 429, 429 }, statuses);
        Assert.Equal(4, await PushesAsync() - before);
        var over = (await relay.HandleAsync(Login("victim@acme.com", token)))!;
        Assert.Equal(("RATE_LIMITED", "Too many attempts. Try again later."), ((string?)over.Body["error"], (string?)over.Body["message"]));
        Assert.Equal(("rate_limited", "no-store"), (Header(over, Guard.StateHeader), Header(over, "Cache-Control")));
        Assert.Equal(over.Body["retryAfter"]!.ToJsonString(), Header(over, "Retry-After"));
    }

    [Fact]
    public async Task ARenewalIsChargedEvenWhenTheQrRanOutWhileTheLinkStateWasRead()
    {
        // The poll arrives 300 ms before the QR's last 15 s; reading the link state takes 600 ms.
        var http = new HttpClient(StubHandler.Async(async (req, _) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path.StartsWith("/users/", StringComparison.Ordinal))
            {
                await Task.Delay(600);
                return StubHandler.Json(200, new { used = false });
            }
            if (path == "/login/request") return StubHandler.Json(404, new { code = "device_not_linked", error = "No linked device found for this user" });
            return StubHandler.Json(200, new { qrCodeDataUrl = "data:image/png;base64,QR2", expiresAt = DateTimeOffset.UtcNow.AddMinutes(5).ToString("O"), recoveryCodes = new[] { "r2" } });
        }));
        var tq = new TouchqueClient(new TouchqueOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, http);
        // 1 per user a minute.
        var relay = new RelayHandler<string>(tq, new RelayOptions<string>
        {
            GetUserId = u => u, GetLoginUser = u => u, RateLimit = new RateLimitOptions { PerUser = 1, PerIp = 100 },
        });
        var statuses = new List<int>();
        for (var i = 0; i < 2; i++)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var token = GuardToken.Sign("s", new GuardTokenClaims { User = "m@acme.com", Action = "LOGIN", State = "enroll", EnrollExpiresAt = now + 15_300, ExpiresAt = now + 60_000 });
            statuses.Add((await relay.HandleAsync(Login("m@acme.com", token)))!.Status);
        }
        // The first renewal takes the user's one attempt; the second is refused instead of renewing on the poll budget.
        Assert.Equal(new[] { 202, 429 }, statuses);
    }

    [Fact]
    public async Task GuardRefusalsThroughTheRelayCarryTheirState()
    {
        await _api.LinkAsync("frozen@acme.com");
        await _api.OptsAsync(new { frozen = true });
        var relay = new RelayHandler<string>(_api.Client(), new RelayOptions<string> { GetUserId = u => u, GetLoginUser = u => u });
        var frozen = (await relay.HandleAsync(Login("frozen@acme.com")))!;
        Assert.Equal((423, "frozen", "900", (string?)null), (frozen.Status, Header(frozen, Guard.StateHeader), Header(frozen, "Retry-After"), Header(frozen, Guard.ReasonHeader)));
        await _api.OptsAsync(new { frozen = false, blocked = "geo_policy" });
        var blocked = (await relay.HandleAsync(Login("frozen@acme.com")))!;
        Assert.Equal((403, "blocked", "geo_policy"), (blocked.Status, Header(blocked, Guard.StateHeader), Header(blocked, Guard.ReasonHeader)));
        await _api.OptsAsync(new { blocked = false });
        var waiting = (await relay.HandleAsync(Login("frozen@acme.com")))!;
        Assert.Equal((202, (string?)null), (waiting.Status, Header(waiting, Guard.StateHeader)));
    }
}
