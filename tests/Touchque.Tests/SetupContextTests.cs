using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.TestHost;
using Touchque.AspNetCore;
using Touchque.Internal;
using Touchque.Relay;
using Xunit;

namespace Touchque.Tests;

/// <summary>
/// 2FA setup context: a first-time QR is asked for with the end user's IP and User-Agent exactly as
/// a login request carries them (every adapter, the same trusted-proxy rules), and the validate
/// answer reads where it was asked for leniently (fixtures/setup-context.json).
/// </summary>
[Collection("fake-api")]
public class SetupContextTests : IAsyncLifetime
{
    private const string Safari = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1";
    private const string Firefox = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0";

    private readonly FakeApi _api;

    public SetupContextTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>A client whose every request is kept (path and JSON body) and answered 200 with <paramref name="answer"/>.</summary>
    private static TouchqueClient Recording(List<(string Path, JsonObject Body)> sent, Func<string, JsonNode>? answer = null) =>
        new(new TouchqueOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, new HttpClient(new StubHandler((req, body) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            sent.Add((path, (JsonObject)JsonNode.Parse(body ?? "{}")!));
            return StubHandler.Json(200, answer?.Invoke(path) ?? new JsonObject { ["secret"] = "S", ["externalUsername"] = "ada@acme.com", ["requestId"] = "r1" });
        })));

    /// <summary>The end user's IP and User-Agent in a request body, as sent (a key left out stays out).</summary>
    private static JsonObject Sent(JsonNode? body)
    {
        var o = new JsonObject();
        foreach (var key in new[] { "clientIp", "userAgent" })
        {
            if (body is JsonObject b && b.TryGetPropertyValue(key, out var v)) o[key] = v?.DeepClone();
        }
        return o;
    }

    /// <summary>The named fields of a parsed setup context, in the fixture's shape (unknown fields are kept in Extra, not here).</summary>
    private static JsonNode? Shape(SetupContext? c) => c is null ? null : new JsonObject
    {
        ["ip"] = c.Ip,
        ["location"] = c.Location is null ? null : new JsonObject { ["city"] = c.Location.City, ["country"] = c.Location.Country, ["countryCode"] = c.Location.CountryCode },
        ["device"] = c.Device is null ? null : new JsonObject { ["browser"] = c.Device.Browser, ["os"] = c.Device.Os, ["model"] = c.Device.Model },
        ["requestedAt"] = c.RequestedAt,
        ["farFromPhone"] = c.FarFromPhone,
    };

    /// <summary>The bodies of the fake's calls to <paramref name="path"/> since call number <paramref name="from"/>.</summary>
    private async Task<JsonObject[]> BodiesAsync(int from, string path) =>
        (await _api.CallsAsync()).Skip(from).Where(c => (string?)c!["path"] == path).Select(c => (JsonObject)c!["body"]!).ToArray();

    private async Task<int> CallCountAsync() => (await _api.CallsAsync()).Count;

    // ── request bodies ──────────────────────────────────────────────────

    [Fact]
    public async Task GenerateAndResetSendTheEndUsersIpAndUserAgentOnlyWhenGiven()
    {
        var sent = new List<(string Path, JsonObject Body)>();
        var tq = Recording(sent);
        await tq.Auth.GenerateSecretAsync("ada@acme.com", "203.0.113.7", Safari);
        await tq.Auth.ResetSecretAsync("ada@acme.com", "203.0.113.7", Safari);
        await tq.Auth.GenerateSecretAsync("ada@acme.com", userAgent: Safari);
        await tq.Auth.ResetSecretAsync("ada@acme.com", clientIp: "2001:db8::7");
        await tq.Auth.GenerateSecretAsync("ada@acme.com", "", "");
        await tq.Auth.ResetSecretAsync("ada@acme.com", null, null);
        await tq.Auth.GenerateSecretAsync("ada@acme.com");
        // The (externalUsername, ct) overloads send the user only, as before.
        await tq.Auth.GenerateSecretAsync("ada@acme.com", CancellationToken.None);
        await tq.Auth.ResetSecretAsync("ada@acme.com", CancellationToken.None);

        Assert.Equal(new[]
        {
            "/auth/generate-secret", "/auth/secret/reset", "/auth/generate-secret", "/auth/secret/reset", "/auth/generate-secret",
            "/auth/secret/reset", "/auth/generate-secret", "/auth/generate-secret", "/auth/secret/reset",
        }, sent.Select(s => s.Path));
        var both = new { externalUsername = "ada@acme.com", clientIp = "203.0.113.7", userAgent = Safari };
        JsonAssert.Equal(both, sent[0].Body);
        JsonAssert.Equal(both, sent[1].Body);
        JsonAssert.Equal(new { externalUsername = "ada@acme.com", userAgent = Safari }, sent[2].Body);
        JsonAssert.Equal(new { externalUsername = "ada@acme.com", clientIp = "2001:db8::7" }, sent[3].Body);
        foreach (var (_, body) in sent.Skip(4)) JsonAssert.Equal(new { externalUsername = "ada@acme.com" }, body);
    }

    [Fact]
    public async Task TheQrRequestFollowsTheLoginRequestsRulesForIpAndUserAgent()
    {
        // A login request sends each one as given (no trimming, no length cap) when it is not null or empty.
        var cases = new (string? Ip, string? UserAgent)[]
        {
            (null, null), ("", ""), (" ", "\t"), ("  203.0.113.7  ", "  " + Safari + "  "), ("::ffff:203.0.113.7", "curl/8.7.1"),
            ("not an ip", "UA\u0001with\ncontrol"), ("203.0.113.7:51234", new string('x', 2048)), ("[2001:db8::7]:443", "ü 🚀"),
        };
        foreach (var (ip, ua) in cases)
        {
            var sent = new List<(string Path, JsonObject Body)>();
            var tq = Recording(sent);
            await tq.Login.RequestAsync(new LoginRequestOptions { ExternalUsername = "ada@acme.com", ClientIp = ip, UserAgent = ua });
            await tq.Auth.GenerateSecretAsync("ada@acme.com", ip, ua);
            await tq.Auth.ResetSecretAsync("ada@acme.com", ip, ua);
            Assert.Equal(new[] { "/login/request", "/auth/generate-secret", "/auth/secret/reset" }, sent.Select(s => s.Path));
            var login = Sent(sent[0].Body);
            var expected = new JsonObject();
            if (!string.IsNullOrEmpty(ip)) expected["clientIp"] = ip;
            if (!string.IsNullOrEmpty(ua)) expected["userAgent"] = ua;
            JsonAssert.Equal(expected, login, $"login request, ip '{ip}'");
            JsonAssert.Equal(login, Sent(sent[1].Body), $"generate-secret, ip '{ip}'");
            JsonAssert.Equal(login, Sent(sent[2].Body), $"secret/reset, ip '{ip}'");
        }
    }

    // ── the validate answer ─────────────────────────────────────────────

    [Fact]
    public async Task ValidateReadsSetupContextLenientlyAsTheSharedFixtureSays()
    {
        var fixture = Paths.Fixture("setup-context.json");
        var expected = fixture["expected"]!.AsObject();
        var cases = fixture.Select(p => p.Key).Where(k => k != "expected").ToList();
        Assert.Equal(new[] { "full", "allNull", "missing", "null", "wrongTypes", "extraFields" }, cases);
        var read = new Dictionary<string, ValidateSecretResult>();
        foreach (var name in cases)
        {
            var answer = fixture[name]!;
            var sent = new List<(string Path, JsonObject Body)>();
            var v = await Recording(sent, _ => answer.DeepClone()).Auth.ValidateSecretAsync("S");
            JsonAssert.Equal(new { secret = "S" }, Assert.Single(sent).Body);
            Assert.Equal((true, "user@example.com", "int-1"), (v.Valid, v.ExternalUsername, v.IntegrationId));
            JsonAssert.Equal(expected[name], Shape(v.SetupContext), name);
            read[name] = v;
        }
        Assert.True(read["full"].SetupContext!.FarFromPhone);
        Assert.False(read["extraFields"].SetupContext!.FarFromPhone);

        // Unknown fields are kept, at every level, and never fail the answer.
        var extra = read["extraFields"];
        Assert.Equal("link", extra.Extra!["nextStep"].GetString());
        Assert.Equal(new[] { "asn", "network", "warnings" }, extra.SetupContext!.Extra!.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(new[] { "latitude", "region" }, extra.SetupContext.Location!.Extra!.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(new[] { "browserVersion", "deviceType" }, extra.SetupContext.Device!.Extra!.Keys.Order(StringComparer.Ordinal));

        // Written back (a relay forwarding the answer, say), a context is the API's JSON again.
        JsonAssert.Equal(fixture["full"]!["setupContext"], Json.ToNode(read["full"])!["setupContext"]);
    }

    [Fact]
    public async Task ASetupContextOfAnotherShapeIsNullNeverAnError()
    {
        async Task<SetupContext?> Read(JsonNode? setupContext)
        {
            var answer = new JsonObject { ["valid"] = true, ["externalUsername"] = "ada@acme.com", ["setupContext"] = setupContext };
            return (await Recording(new(), _ => answer.DeepClone()).Auth.ValidateSecretAsync("S")).SetupContext;
        }

        foreach (var wrong in new JsonNode?[] { null, "Berlin", 7, true, false, new JsonArray(), new JsonArray(new JsonObject { ["ip"] = "203.0.113.7" }) })
        {
            Assert.Null(await Read(wrong));
        }
        var nothing = new { ip = (string?)null, location = (object?)null, device = (object?)null, requestedAt = (string?)null, farFromPhone = (bool?)null };
        // An empty object: a context that knows nothing.
        JsonAssert.Equal(nothing, Shape(await Read(new JsonObject())));
        // Every field in another shape: null, field by field.
        JsonAssert.Equal(nothing, Shape(await Read(new JsonObject
        {
            ["ip"] = new JsonArray("203.0.113.7"), ["location"] = new JsonArray(), ["device"] = "Safari on iOS",
            ["requestedAt"] = 1_763_285_400_000, ["farFromPhone"] = 1,
        })));
        JsonAssert.Equal(nothing, Shape(await Read(new JsonObject
        {
            ["ip"] = false, ["location"] = 5, ["device"] = new JsonArray(new JsonObject { ["browser"] = "Safari" }),
            ["requestedAt"] = new JsonObject { ["at"] = "2026-11-16T09:30:00.000Z" }, ["farFromPhone"] = new JsonObject(),
        })));
        JsonAssert.Equal(new
        {
            ip = "203.0.113.7",
            location = new { city = (string?)null, country = (string?)null, countryCode = "DE" },
            device = new { browser = (string?)null, os = (string?)null, model = (string?)null },
            requestedAt = "2026-11-16T09:30:00.000Z",
            farFromPhone = (bool?)null,
        }, Shape(await Read(new JsonObject
        {
            ["ip"] = "203.0.113.7",
            ["location"] = new JsonObject { ["city"] = 5, ["country"] = new JsonObject(), ["countryCode"] = "DE" },
            ["device"] = new JsonObject { ["browser"] = null, ["os"] = true, ["model"] = new JsonArray("iPhone") },
            ["requestedAt"] = "2026-11-16T09:30:00.000Z",
            ["farFromPhone"] = "false",
        })));
        Assert.Equal((bool?)false, (await Read(new JsonObject { ["farFromPhone"] = false }))!.FarFromPhone);
        Assert.Equal((bool?)true, (await Read(new JsonObject { ["farFromPhone"] = true }))!.FarFromPhone);
        // Unknown keys, even ones named like the SDK's own Extra, are only kept.
        var named = (await Read(new JsonObject { ["ip"] = "203.0.113.7", ["extra"] = 5, ["Extra"] = new JsonArray() }))!;
        Assert.Equal("203.0.113.7", named.Ip);
        Assert.Equal(new[] { "Extra", "extra" }, named.Extra!.Keys.Order(StringComparer.Ordinal));
    }

    // ── end to end, against the shared fake ─────────────────────────────

    [Fact]
    public async Task TheFakeApiShowsWhereTheQrWasAskedFor()
    {
        var tq = _api.Client();
        var before = DateTimeOffset.UtcNow.AddSeconds(-5);
        var gen = await tq.Auth.GenerateSecretAsync("eve@acme.com", "203.0.113.7", Safari);
        JsonAssert.Equal(new { externalUsername = "eve@acme.com", clientIp = "203.0.113.7", userAgent = Safari }, (await _api.LastCallAsync())["body"]);
        var v = await tq.Auth.ValidateSecretAsync(gen.Secret);
        Assert.Equal((true, "eve@acme.com"), (v.Valid, v.ExternalUsername));
        var c = v.SetupContext!;
        Assert.Equal("203.0.113.7", c.Ip);
        Assert.Equal(("Berlin", "Germany", "DE"), (c.Location!.City, c.Location.Country, c.Location.CountryCode));
        Assert.Equal(("Safari", "iOS", "iPhone"), (c.Device!.Browser, c.Device.Os, c.Device.Model));
        Assert.Null(c.FarFromPhone);
        Assert.InRange(DateTimeOffset.Parse(c.RequestedAt!, CultureInfo.InvariantCulture), before, DateTimeOffset.UtcNow.AddSeconds(5));

        // A new QR for the same user, asked for from another place and browser.
        var reset = await tq.Auth.ResetSecretAsync("eve@acme.com", "198.51.100.23", Firefox);
        JsonAssert.Equal(new { externalUsername = "eve@acme.com", clientIp = "198.51.100.23", userAgent = Firefox }, (await _api.LastCallAsync())["body"]);
        var again = (await tq.Auth.ValidateSecretAsync(reset.Secret)).SetupContext!;
        Assert.Equal(("198.51.100.23", "New York", "US"), (again.Ip, again.Location!.City, again.Location.CountryCode));
        Assert.Equal(("Firefox", "Windows", (string?)null), (again.Device!.Browser, again.Device.Os, again.Device.Model));

        // Asked for without the end user's IP and User-Agent: nothing to show.
        var bare = await tq.Auth.GenerateSecretAsync("bo@acme.com");
        JsonAssert.Equal(new { externalUsername = "bo@acme.com" }, (await _api.LastCallAsync())["body"]);
        Assert.Null((await tq.Auth.ValidateSecretAsync(bare.Secret)).SetupContext);
        // An API that answers setupContext: null.
        await tq.Auth.GenerateSecretAsync("cy@acme.com", "203.0.113.7", Safari);
        await _api.OptsAsync(new { setupContextNull = true });
        var none = await tq.Auth.ValidateSecretAsync("S");
        Assert.Equal((true, "cy@acme.com"), (none.Valid, none.ExternalUsername));
        Assert.Null(none.SetupContext);
    }

    // ── adapters: the same IP and User-Agent as their login requests ───

    [Fact]
    public async Task TheGuardAsksForTheQrWithTheIpAndUserAgentOfItsLoginRequest()
    {
        var tq = _api.Client();
        var first = await Guard.RunAsync(tq, new GuardInput { User = "new@acme.com", Action = "LOGIN", Ip = "203.0.113.7", UserAgent = Safari });
        Assert.Equal("enroll", (string?)first.Body!["touchque"]!["state"]);
        var login = Sent(Assert.Single(await BodiesAsync(0, "/login/request")));
        JsonAssert.Equal(new { clientIp = "203.0.113.7", userAgent = Safari }, login);
        JsonAssert.Equal(login, Sent(Assert.Single(await BodiesAsync(0, "/auth/generate-secret"))));
        var shown = await tq.Auth.ValidateSecretAsync("S");
        Assert.Equal(("new@acme.com", "Berlin", "Safari"), (shown.ExternalUsername, shown.SetupContext!.Location!.City, shown.SetupContext.Device!.Browser));

        // The QR is renewed in its last 15 s by the poll that asks now: with that request's IP and User-Agent.
        await _api.OptsAsync(new { secretTtlMs = 10_000 });
        var near = await Guard.RunAsync(tq, new GuardInput { User = "near@acme.com", Action = "LOGIN", Ip = "203.0.113.7", UserAgent = Safari });
        var from = await CallCountAsync();
        var renewed = await Guard.RunAsync(tq, new GuardInput
        {
            User = "near@acme.com", Action = "LOGIN", Ip = "198.51.100.23", UserAgent = Firefox, Token = (string)near.Body!["token"]!,
        });
        Assert.Equal("data:image/png;base64,QR2-near@acme.com", (string?)renewed.Body!["touchque"]!["enroll"]!["qrCodeDataUrl"]);
        var poll = Sent(Assert.Single(await BodiesAsync(from, "/login/request")));
        JsonAssert.Equal(new { clientIp = "198.51.100.23", userAgent = Firefox }, poll);
        JsonAssert.Equal(poll, Sent(Assert.Single(await BodiesAsync(from, "/auth/generate-secret")))); // its 409 first
        JsonAssert.Equal(poll, Sent(Assert.Single(await BodiesAsync(from, "/auth/secret/reset"))));
        var renewedShown = (await tq.Auth.ValidateSecretAsync("S2")).SetupContext!;
        Assert.Equal(("New York", "Firefox"), (renewedShown.Location!.City, renewedShown.Device!.Browser));

        // tq.StartAsync: StartOptions.Ip and UserAgent. None given: none sent, as with the push.
        await _api.OptsAsync(new { secretTtlMs = 300_000 });
        from = await CallCountAsync();
        await tq.StartAsync("LOGIN", new StartOptions { User = "start@acme.com", Ip = "203.0.113.7", UserAgent = Firefox });
        await tq.StartAsync("LOGIN", new StartOptions { User = "bare@acme.com" });
        await Guard.RunAsync(tq, new GuardInput { User = "guard-bare@acme.com", Action = "LOGIN" });
        var pushes = await BodiesAsync(from, "/login/request");
        var secrets = await BodiesAsync(from, "/auth/generate-secret");
        Assert.Equal((3, 3), (pushes.Length, secrets.Length));
        JsonAssert.Equal(new { clientIp = "203.0.113.7", userAgent = Firefox }, Sent(secrets[0]));
        JsonAssert.Equal(new JsonObject(), Sent(secrets[1]));
        JsonAssert.Equal(new JsonObject(), Sent(secrets[2]));
        for (var i = 0; i < 3; i++) JsonAssert.Equal(Sent(pushes[i]), Sent(secrets[i]), $"start {i}");
    }

    private static RelayRequest<string> RelayPost(string path, string user, string ip, string? userAgent) => new()
    {
        Method = "POST", Path = path, Ip = ip, UserAgent = userAgent, Native = user, Header = _ => null,
    };

    [Fact]
    public async Task TheRelaysEnrollStartSendsWhatItsLoginSends()
    {
        await _api.LinkAsync("linked@acme.com");
        var relay = new RelayHandler<string>(_api.Client(), new RelayOptions<string> { GetUserId = u => u, GetLoginUser = u => u, RateLimit = null });
        var cases = new (string Ip, string? UserAgent)[] { ("203.0.113.7", Safari), ("", Firefox), ("2001:db8::7", null), ("", null) };
        for (var i = 0; i < cases.Length; i++)
        {
            var (ip, ua) = cases[i];
            var from = await CallCountAsync();
            Assert.Equal(202, (await relay.HandleAsync(RelayPost("/login", "linked@acme.com", ip, ua)))!.Status);
            var user = $"enroll-{i}@acme.com";
            var started = (await relay.HandleAsync(RelayPost("/enroll/start", user, ip, ua)))!;
            Assert.Equal((200, $"data:image/png;base64,QR-{user}"), (started.Status, (string?)started.Body["qrCodeDataUrl"]));
            // A second QR before the first was scanned: 409, then a reset, for the same request.
            var again = (await relay.HandleAsync(RelayPost("/enroll/start", user, ip, ua)))!;
            Assert.Equal((200, $"data:image/png;base64,QR2-{user}"), (again.Status, (string?)again.Body["qrCodeDataUrl"]));

            var login = Sent(Assert.Single(await BodiesAsync(from, "/login/request")));
            var expected = new JsonObject();
            if (ip.Length > 0) expected["clientIp"] = ip;
            if (ua is not null) expected["userAgent"] = ua;
            JsonAssert.Equal(expected, login, $"case {i}");
            var generated = await BodiesAsync(from, "/auth/generate-secret");
            Assert.Equal(2, generated.Length);
            foreach (var body in generated) JsonAssert.Equal(login, Sent(body), $"case {i}");
            JsonAssert.Equal(login, Sent(Assert.Single(await BodiesAsync(from, "/auth/secret/reset"))), $"case {i}");
        }
    }

    // ── ASP.NET Core: RemoteIpAddress, behind UseForwardedHeaders when configured ──

    /// <summary>The relay and a guarded endpoint. The socket's peer comes from X-Test-Peer; <paramref name="knownProxy"/> runs UseForwardedHeaders with that one proxy.</summary>
    private async Task<WebApplication> AppAsync(string? knownProxy)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddTouchque(o =>
        {
            o.ApiKey = "tq_test_key";
            o.ApiSecret = "test_secret";
            o.BaseUrl = _api.BaseUrl;
        });
        var app = builder.Build();
        app.Use((http, next) =>
        {
            var peer = http.Request.Headers["X-Test-Peer"].ToString();
            http.Connection.RemoteIpAddress = peer.Length > 0 ? IPAddress.Parse(peer) : null;
            var user = http.Request.Headers["X-User"].ToString();
            if (user.Length > 0) http.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Email, user) }, "test"));
            return next(http);
        });
        if (knownProxy is not null)
        {
            // As the README says: your load balancer as the one known proxy.
            var forwarded = new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor };
            forwarded.KnownNetworks.Clear();
            forwarded.KnownProxies.Clear();
            forwarded.KnownProxies.Add(IPAddress.Parse(knownProxy));
            app.UseForwardedHeaders(forwarded);
        }
        app.MapTouchqueRelay("/touchque", new RelayOptions<HttpContext>
        {
            GetUserId = http => http.User.TouchqueUser(),
            GetLoginUser = http => http.Request.Headers["X-Password-Ok"].ToString(),
            RateLimit = null,
        });
        app.MapPost("/guarded", () => Results.Ok()).RequireTouchque("LOGIN");
        await app.StartAsync();
        return app;
    }

    private static HttpRequestMessage Post(string path, string? peer, string? forwardedFor, string? user = null, string? loginUser = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(new { }) };
        req.Headers.TryAddWithoutValidation("User-Agent", Safari);
        if (peer is not null) req.Headers.Add("X-Test-Peer", peer);
        if (forwardedFor is not null) req.Headers.Add("X-Forwarded-For", forwardedFor);
        if (user is not null) req.Headers.Add("X-User", user);
        if (loginUser is not null) req.Headers.Add("X-Password-Ok", loginUser);
        return req;
    }

    public static TheoryData<string?, string?, string?, string?> ProxyCases => new()
    {
        // known proxy, the socket's peer, X-Forwarded-For, the client IP sent
        { null, "192.0.2.10", "198.51.100.23, 203.0.113.7", "192.0.2.10" },        // no forwarded headers: the peer, never X-Forwarded-For
        { "10.0.0.5", "10.0.0.5", "198.51.100.23, 203.0.113.7", "203.0.113.7" },   // the known proxy: the address it saw, never the leftmost
        { "10.0.0.5", "192.0.2.10", "203.0.113.7", "192.0.2.10" },                 // a peer that is not the known proxy: its header is ignored
        { null, "::ffff:203.0.113.7", null, "203.0.113.7" },                       // IPv4-mapped: as IPv4
        { null, null, "203.0.113.7", null },                                       // no address: none sent
    };

    [Theory]
    [MemberData(nameof(ProxyCases))]
    public async Task AspNetCoreSendsTheQrRequestTheIpAndUserAgentItsLoginRequestGets(string? knownProxy, string? peer, string? forwardedFor, string? clientIp)
    {
        await _api.LinkAsync("linked@acme.com");
        await using var app = await AppAsync(knownProxy);
        var client = app.GetTestClient();
        Assert.Equal(HttpStatusCode.Accepted, (await client.SendAsync(Post("/touchque/login", peer, forwardedFor, loginUser: "linked@acme.com"))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Post("/touchque/enroll/start", peer, forwardedFor, user: "relay@acme.com"))).StatusCode);
        var guarded = await client.SendAsync(Post("/guarded", peer, forwardedFor, user: "guarded@acme.com"));
        Assert.Equal(HttpStatusCode.Accepted, guarded.StatusCode);
        Assert.Equal("enroll", (string?)(await guarded.Content.ReadFromJsonAsync<JsonObject>())!["touchque"]!["state"]);

        var expected = new JsonObject();
        if (clientIp is not null) expected["clientIp"] = clientIp;
        expected["userAgent"] = Safari;
        // The relay's /login and the guard's push; the relay's /enroll/start and the guard's first-time QR.
        var logins = await BodiesAsync(0, "/login/request");
        var secrets = await BodiesAsync(0, "/auth/generate-secret");
        Assert.Equal((2, 2), (logins.Length, secrets.Length));
        foreach (var body in logins.Concat(secrets)) JsonAssert.Equal(expected, Sent(body));
        if (clientIp == "203.0.113.7")
        {
            Assert.Equal("Berlin", (await _api.Client().Auth.ValidateSecretAsync("S")).SetupContext!.Location!.City);
        }
    }
}
