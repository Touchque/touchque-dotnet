using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Touchque.AspNetCore;
using Touchque.Relay;
using Xunit;

namespace Touchque.Tests;

/// <summary>The ASP.NET Core integration in a TestServer, against the fake API.</summary>
[Collection("fake-api")]
public class AspNetCoreTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public AspNetCoreTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    public sealed record Transfer(string To, string Amount);

    private async Task<WebApplication> AppAsync(Action<WebApplication> map, Action<IServiceCollection>? services = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddTouchque(o =>
        {
            o.ApiKey = "tq_test_key";
            o.ApiSecret = "test_secret";
            o.BaseUrl = _api.BaseUrl;
        });
        builder.Services.AddControllers().AddApplicationPart(typeof(AspNetCoreTests).Assembly);
        services?.Invoke(builder.Services);
        var app = builder.Build();
        // The signed-in user, for these tests: header X-User.
        app.Use((http, next) =>
        {
            var user = http.Request.Headers["X-User"].ToString();
            if (user.Length > 0) http.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Email, user) }, "test"));
            return next(http);
        });
        map(app);
        await app.StartAsync();
        return app;
    }

    private static string? Header(HttpResponseMessage res, string name) => res.Headers.TryGetValues(name, out var v) ? string.Join(",", v) : null;

    private static HttpRequestMessage Post(string path, string? user = null, string? token = null, object? body = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body ?? new { }) };
        if (user is not null) req.Headers.Add("X-User", user);
        if (token is not null) req.Headers.Add(Guard.TokenHeader, token);
        return req;
    }

    [Fact]
    public async Task RequireTouchqueOnAMinimalApiEndpoint()
    {
        await _api.LinkAsync("ada@acme.com");
        var ran = 0;
        await using var app = await AppAsync(a => a.MapPost("/transfer", (Transfer t, HttpContext http) =>
        {
            ran++;
            return Results.Ok(new { done = true, via = http.GetTouchqueApproval()!.ConfirmedVia });
        }).RequireTouchque("SEND_MONEY", o => o.Details = c => new LoginDetail[] { ("Amount", c.Argument<Transfer>()!.Amount), ("To", c.Argument<Transfer>()!.To) }));
        var client = app.GetTestClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Post("/transfer", body: new Transfer("Bo", "250 EUR")))).StatusCode);
        var first = await client.SendAsync(Post("/transfer", "ada@acme.com", body: new Transfer("Bo", "250 EUR")));
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal("no-store", first.Headers.CacheControl!.ToString());
        var step = (await first.Content.ReadFromJsonAsync<JsonObject>())!;
        Assert.Equal(("waiting", "47"), ((string)step["touchque"]!["state"]!, (string?)step["touchque"]!["number"]));
        JsonAssert.Equal(new[] { new { label = "Amount", value = "250 EUR" }, new { label = "To", value = "Bo" } }, (await _api.LastCallAsync())["body"]!["details"]);
        var token = (string)step["token"]!;
        Assert.Equal(HttpStatusCode.Accepted, (await client.SendAsync(Post("/transfer", "ada@acme.com", token, new Transfer("Bo", "250 EUR")))).StatusCode);
        await _api.ApproveAsync();
        // Another amount with the same token is a new attempt, never the approved one.
        var other = await client.SendAsync(Post("/transfer", "ada@acme.com", token, new Transfer("Bo", "9999 EUR")));
        Assert.Equal(HttpStatusCode.Accepted, other.StatusCode);
        var done = await client.SendAsync(Post("/transfer", "ada@acme.com", token, new Transfer("Bo", "250 EUR")));
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        Assert.Equal("DEVICE", (string?)(await done.Content.ReadFromJsonAsync<JsonObject>())!["via"]);
        Assert.Equal(1, ran);
    }

    [Fact]
    public async Task WithoutKeysTheAppStartsAndAGuardedEndpointAnswers500MisconfiguredAndNeverRuns()
    {
        var logger = new ContractTests.ListLogger();
        var ran = 0;
        await using var app = await AppAsync(a =>
        {
            a.MapPost("/pay", () =>
            {
                ran++;
                return Results.Ok();
            }).RequireTouchque("SEND_MONEY");
            a.MapControllers();
        }, s => s.Configure<TouchqueOptions>(o =>
        {
            o.ApiKey = "";
            o.ApiSecret = "";
            o.Logger = logger;
        }));
        var client = app.GetTestClient();
        var anonymous = await client.SendAsync(Post("/pay"));
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        JsonAssert.Equal(new { touchque = new { state = "blocked", reason = "unauthenticated" }, error = new { code = "unauthenticated", message = "Sign in first." } },
            await anonymous.Content.ReadFromJsonAsync<JsonObject>());
        foreach (var path in new[] { "/pay", "/pay", "/payouts" })
        {
            var res = await client.SendAsync(Post(path, "ada@acme.com"));
            Assert.Equal(HttpStatusCode.InternalServerError, res.StatusCode);
            Assert.Equal("no-store", res.Headers.CacheControl!.ToString());
            Assert.Equal(("blocked", "misconfigured"), (Header(res, Guard.StateHeader), Header(res, Guard.ReasonHeader)));
            JsonAssert.Equal(new
            {
                touchque = new { state = "blocked", reason = "misconfigured" },
                error = new { code = "misconfigured", message = "Two-factor approval is not configured correctly." },
            }, await res.Content.ReadFromJsonAsync<JsonObject>(), path);
        }
        Assert.Equal(0, ran);
        // Once per process, through the SDK's logger.
        Assert.Equal(new[] { (Microsoft.Extensions.Logging.LogLevel.Error, "[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.") },
            logger.Lines);
    }

    [Fact]
    public async Task ErrorBodyKeepsTheAppsErrorShapeForRefusalsOnly()
    {
        await _api.LinkAsync("eb@acme.com");
        var calls = 0;
        var fail = false;
        object? Shape(GuardRefusal r)
        {
            calls++;
            if (fail) throw new InvalidOperationException("the error template is broken");
            return new { message = r.Message, code = r.Code };
        }
        var logger = new ContractTests.ListLogger();
        await using var app = await AppAsync(a =>
        {
            a.MapPost("/account", (HttpContext http) => Results.Ok(new { via = http.GetTouchqueApproval()!.ConfirmedVia }))
                .RequireTouchque("LOGIN", o => o.ErrorBody = Shape);
            a.MapPost("/transfer", () => Results.Ok()).RequireTouchque("SEND_MONEY", o => o.ErrorBody = r => "refused: " + r.Code);
            a.MapPost("/nothing", () => Results.Ok()).RequireTouchque("SEND_MONEY", o => o.ErrorBody = _ => null);
        }, s => s.Configure<TouchqueOptions>(o => o.Logger = logger));
        var client = app.GetTestClient();

        // The callback's object with the step under "touchque" (no token): 401 without a signed-in user.
        var anonymous = await client.SendAsync(Post("/account"));
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.Equal(("no-store", "application/json"), (anonymous.Headers.CacheControl!.ToString(), anonymous.Content.Headers.ContentType!.MediaType));
        JsonAssert.Equal(new { message = "Sign in first.", code = "unauthenticated", touchque = new { state = "blocked", reason = "unauthenticated" } },
            await anonymous.Content.ReadFromJsonAsync<JsonObject>());
        Assert.Equal(("blocked", "unauthenticated"), (Header(anonymous, Guard.StateHeader), Header(anonymous, Guard.ReasonHeader)));
        Assert.Equal(1, calls);

        // Never for a 202 step or an approval.
        var waiting = await client.SendAsync(Post("/account", "eb@acme.com"));
        Assert.Equal(HttpStatusCode.Accepted, waiting.StatusCode);
        Assert.Null(Header(waiting, Guard.StateHeader));
        var token = (string)(await waiting.Content.ReadFromJsonAsync<JsonObject>())!["token"]!;
        await _api.ApproveAsync();
        var done = await client.SendAsync(Post("/account", "eb@acme.com", token));
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        Assert.Equal(1, calls);

        // The status and headers stay.
        await _api.OptsAsync(new { frozen = true });
        var frozen = await client.SendAsync(Post("/account", "eb@acme.com"));
        Assert.Equal(((HttpStatusCode)423, "900", "no-store"), (frozen.StatusCode, frozen.Headers.RetryAfter!.ToString(), frozen.Headers.CacheControl!.ToString()));
        JsonAssert.Equal(new
        {
            message = "Too many rejected approvals. Try again later.", code = "frozen",
            touchque = new { state = "frozen", retryAfter = 900, caseCode = "REF-USE" },
        }, await frozen.Content.ReadFromJsonAsync<JsonObject>());

        // Anything but an object is sent as it is.
        var text = await client.SendAsync(Post("/transfer", "eb@acme.com"));
        Assert.Equal(((HttpStatusCode)423, "\"refused: frozen\"", "900"), (text.StatusCode, await text.Content.ReadAsStringAsync(), text.Headers.RetryAfter!.ToString()));
        Assert.Equal("application/json", text.Content.Headers.ContentType!.MediaType);
        // The state is in a header, since this body has no "touchque".
        Assert.Equal(("frozen", (string?)null), (Header(text, Guard.StateHeader), Header(text, Guard.ReasonHeader)));
        var nothing = await client.SendAsync(Post("/nothing", "eb@acme.com"));
        Assert.Equal(((HttpStatusCode)423, "null", "application/json"), (nothing.StatusCode, await nothing.Content.ReadAsStringAsync(), nothing.Content.Headers.ContentType!.MediaType));

        // A callback that throws: the default body, and a log line.
        fail = true;
        var fallback = await client.SendAsync(Post("/account", "eb@acme.com"));
        Assert.Equal((HttpStatusCode)423, fallback.StatusCode);
        var body = (await fallback.Content.ReadFromJsonAsync<JsonObject>())!;
        Assert.Equal(("frozen", false, true), ((string)body["touchque"]!["state"]!, body.ContainsKey("message"), body.ContainsKey("token")));
        Assert.Contains((Microsoft.Extensions.Logging.LogLevel.Error, "[Touchque] errorBody failed: the error template is broken"), logger.Lines);
    }

    [Fact]
    public async Task ErrorBodyIsDecidedByItsJsonEncodingWithTheAppsOptions()
    {
        await _api.LinkAsync("enc@acme.com");
        await _api.OptsAsync(new { frozen = true });
        var logger = new ContractTests.ListLogger();
        object? Shape(GuardRefusal r) => new { Message = r.Message, Code = r.Code };
        await using var app = await AppAsync(a =>
        {
            a.MapControllers();
            a.MapPost("/shape", () => Results.Ok()).RequireTouchque("SEND_MONEY", o => o.ErrorBody = Shape);
            a.MapPost("/keys", () => Results.Ok()).RequireTouchque("SEND_MONEY", o => o.ErrorBody = r => new Dictionary<string, object?>
            {
                ["Touchque"] = "mine", ["TOUCHQUE"] = 1, ["a"] = 1, ["A"] = 2, ["code"] = r.Code,
            });
            a.MapPost("/element", () => Results.Ok()).RequireTouchque("SEND_MONEY", o => o.ErrorBody = _ => System.Text.Json.JsonDocument.Parse("{\"a\":1}").RootElement);
            a.MapPost("/type", () => Results.Ok()).RequireTouchque("SEND_MONEY", o => o.ErrorBody = _ => typeof(string));
        }, s =>
        {
            s.AddControllers().AddJsonOptions(o => o.JsonSerializerOptions.PropertyNamingPolicy = null);
            s.ConfigureAll<TouchqueGuardOptions>(o => o.ErrorBody = Shape);
            s.Configure<TouchqueOptions>(o => o.Logger = logger);
        });
        var client = app.GetTestClient();
        // Read case-sensitively: "a" and "A" are two keys.
        async Task<JsonObject> Body(string path) => (JsonObject)JsonNode.Parse(await (await client.SendAsync(Post(path, "enc@acme.com"))).Content.ReadAsStringAsync())!;
        var step = new { state = "frozen", retryAfter = 900, caseCode = "REF-USE" };

        // A controller writes it with MVC's options (PascalCase here), an endpoint with the minimal APIs' ones (camelCase).
        JsonAssert.Equal(new { Message = "Too many rejected approvals. Try again later.", Code = "frozen", touchque = step }, await Body("/payouts"));
        JsonAssert.Equal(new { message = "Too many rejected approvals. Try again later.", code = "frozen", touchque = step }, await Body("/shape"));
        // Keys keep their case; only the SDK's "touchque" is left, whatever the spelling of the others.
        var keys = await Body("/keys");
        Assert.Equal(new[] { "A", "a", "code", "touchque" }, keys.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
        JsonAssert.Equal(step, keys["touchque"]);
        // A JsonElement that encodes to an object is an object.
        JsonAssert.Equal(new { a = 1, touchque = step }, await Body("/element"));
        // What the serializer cannot write: the default body, and a log line.
        var unwritable = await Body("/type");
        Assert.Equal(("frozen", true), ((string)unwritable["touchque"]!["state"]!, unwritable.ContainsKey("token")));
        Assert.Contains(logger.Lines, l => l.Message.StartsWith("[Touchque] errorBody failed: ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RequireTouchqueOnAController()
    {
        await _api.LinkAsync("bo@acme.com");
        await _api.OptsAsync(new { frozen = true });
        await using var app = await AppAsync(a => a.MapControllers());
        var res = await app.GetTestClient().SendAsync(Post("/payouts", "bo@acme.com"));
        Assert.Equal((HttpStatusCode)423, res.StatusCode);
        Assert.Equal("900", res.Headers.RetryAfter!.ToString());
        Assert.Equal("frozen", Header(res, Guard.StateHeader));
        await _api.OptsAsync(new { frozen = false });
        var waiting = await app.GetTestClient().SendAsync(Post("/payouts", "bo@acme.com"));
        Assert.Equal(HttpStatusCode.Accepted, waiting.StatusCode);
    }

    [Fact]
    public async Task RelayLoginWithAFirstFactorAndOnAuthenticated()
    {
        await _api.LinkAsync("cy@acme.com");
        var opened = new List<string>();
        await using var app = await AppAsync(a => a.MapTouchqueRelay("/touchque", new RelayOptions<HttpContext>
        {
            GetUserId = http => http.User.TouchqueUser(),
            GetLoginUser = http => http.Request.Headers["X-Password-Ok"].ToString(),
            OnAuthenticated = (http, response, info) =>
            {
                opened.Add($"{info.ExternalUsername}:{info.Via}");
                response.AddHeader("Set-Cookie", "app_session=1; Path=/; HttpOnly");
                return Task.CompletedTask;
            },
        }));
        var client = app.GetTestClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Post("/touchque/login"))).StatusCode);
        var req = Post("/touchque/login", body: new { externalUsername = "attacker@evil.com" });
        req.Headers.Add("X-Password-Ok", "cy@acme.com");
        var first = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal("cy@acme.com", (string?)(await _api.LastCallAsync())["body"]!["externalUsername"]);
        var token = (string)(await first.Content.ReadFromJsonAsync<JsonObject>())!["token"]!;
        await _api.ApproveAsync();
        var poll = Post("/touchque/login", token: token);
        poll.Headers.Add("X-Password-Ok", "cy@acme.com");
        var done = await client.SendAsync(poll);
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        Assert.Contains("app_session=1; Path=/; HttpOnly", done.Headers.GetValues("Set-Cookie"));
        Assert.Equal("success", (string?)(await done.Content.ReadFromJsonAsync<JsonObject>())!["status"]);
        Assert.Equal(new[] { "cy@acme.com:login" }, opened);

        // Signed-in routes; a phone is linked, so adding a passkey waits for the phone first.
        var status = new HttpRequestMessage(HttpMethod.Get, "/touchque/enroll/status");
        status.Headers.Add("X-User", "cy@acme.com");
        JsonAssert.Equal(new { linked = true, used = true, deviceId = "dev-1" }, await (await client.SendAsync(status)).Content.ReadFromJsonAsync<JsonObject>());
        var register = await client.SendAsync(Post("/touchque/passkey/register/options", "cy@acme.com"));
        Assert.Equal(HttpStatusCode.Accepted, register.StatusCode);
        Assert.Equal("PASSKEY_ENROLL", (string?)(await _api.LastCallAsync())["body"]!["type"]);
        Assert.Equal(HttpStatusCode.NotFound, (await client.SendAsync(Post("/touchque/nope"))).StatusCode);
    }

    [Fact]
    public async Task RelayMappedOnANestedGroupWithARouteParameter()
    {
        await _api.LinkAsync("fay@acme.com");
        await using var app = await AppAsync(a => a.MapGroup("/api/{tenant}").MapTouchqueRelay("/touchque", new RelayOptions<HttpContext>
        {
            GetUserId = http => http.User.TouchqueUser(),
            GetLoginUser = http => http.Request.Headers["X-Password-Ok"].ToString(),
        }));
        var client = app.GetTestClient();
        var login = Post("/api/acme/touchque/login");
        login.Headers.Add("X-Password-Ok", "fay@acme.com");
        Assert.Equal(HttpStatusCode.Accepted, (await client.SendAsync(login)).StatusCode);
        var status = new HttpRequestMessage(HttpMethod.Get, "/api/acme/touchque/enroll/status");
        status.Headers.Add("X-User", "fay@acme.com");
        JsonAssert.Equal(new { linked = true, used = true, deviceId = "dev-1" }, await (await client.SendAsync(status)).Content.ReadFromJsonAsync<JsonObject>());
        var delete = new HttpRequestMessage(HttpMethod.Delete, "/api/acme/touchque/passkey/credentials/cred-1");
        delete.Headers.Add("X-User", "fay@acme.com");
        Assert.True((bool?)(await (await client.SendAsync(delete)).Content.ReadFromJsonAsync<JsonObject>())!["deleted"]);
        Assert.Equal("/webauthn/credentials/cred-1", (string?)(await _api.LastCallAsync())["path"]);
    }

    [Fact]
    public async Task RelayRateLimitsAndKeepsOfflineOffWithoutAFirstFactor()
    {
        await _api.LinkAsync("dee@acme.com");
        await using var app = await AppAsync(a => a.MapTouchqueRelay("/tq", new RelayOptions<HttpContext>
        {
            GetUserId = _ => null,
            RateLimit = new RateLimitOptions { PerUser = 2, PerIp = 100 },
        }));
        var client = app.GetTestClient();
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(Post("/tq/offline/challenge", body: new { externalUsername = "dee@acme.com" }))).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await client.SendAsync(Post("/tq/login", body: new { externalUsername = "dee@acme.com" }))).StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, (await client.SendAsync(Post("/tq/login", body: new { externalUsername = "dee@acme.com" }))).StatusCode);
        var limited = await client.SendAsync(Post("/tq/login", body: new { externalUsername = "dee@acme.com" }));
        Assert.Equal((HttpStatusCode)429, limited.StatusCode);
        Assert.True(int.Parse(limited.Headers.RetryAfter!.ToString()) > 0);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Post("/tq/enroll/start"))).StatusCode);
    }

    [Fact]
    public async Task WebhookEndpointVerifiesAndSkipsReplays()
    {
        var events = new List<string>();
        await using var app = await AppAsync(a => a.MapTouchqueWebhook("/webhooks/touchque", (e, http) =>
        {
            events.Add((string)e["event"]!);
            return Task.CompletedTask;
        }));
        var client = app.GetTestClient();
        var payload = new JsonObject { ["event"] = "APPROVAL_REVOKED", ["requestId"] = "r1", ["timestamp"] = DateTimeOffset.UtcNow.ToString("O"), ["jti"] = "jti-77" };
        using var h = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes("test_secret"));
        var sig = Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(WebhookResource.Canonicalize(payload.ToJsonString())))).ToLowerInvariant();
        HttpRequestMessage Delivery(string signature)
        {
            var req = new HttpRequestMessage(HttpMethod.Post, "/webhooks/touchque") { Content = new StringContent(payload.ToJsonString(), Encoding.UTF8, "application/json") };
            req.Headers.Add("x-signature", signature);
            return req;
        }
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Delivery(sig))).StatusCode);
        var again = await client.SendAsync(Delivery(sig));
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.True((bool?)(await again.Content.ReadFromJsonAsync<JsonObject>())!["duplicate"]);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Delivery(new string('0', 64)))).StatusCode);
        Assert.Equal(new[] { "APPROVAL_REVOKED" }, events);
    }

    [Fact]
    public async Task HostedLoginEndpointsSignInWithACookie()
    {
        using var tenant = new FakeTenant();
        await using var app = await AppAsync(a =>
        {
            a.UseAuthentication();
            a.UseAuthorization();
            a.MapTouchqueLogin();
            a.MapGet("/account", (ClaimsPrincipal user) => Results.Ok(new { email = user.FindFirstValue(ClaimTypes.Email) })).RequireAuthorization();
        }, s =>
        {
            s.AddTouchqueLogin(o =>
            {
                o.Domain = FakeTenant.Issuer;
                o.ClientId = FakeTenant.ClientId;
                o.ClientSecret = "s3cret";
            });
            s.AddSingleton(new HostedLogin(new HostedLoginOptions { Domain = FakeTenant.Issuer, ClientId = FakeTenant.ClientId, ClientSecret = "s3cret", HttpClient = tenant.Client() }));
            s.AddAuthorization();
        });
        var server = app.GetTestServer();
        server.BaseAddress = new Uri("https://app.example/");
        var cookies = new CookieContainer();
        async Task<HttpResponseMessage> Get(string path)
        {
            var req = new HttpRequestMessage(HttpMethod.Get, path);
            var header = cookies.GetCookieHeader(new Uri("https://app.example/"));
            if (header.Length > 0) req.Headers.Add("Cookie", header);
            var res = await server.CreateClient().SendAsync(req);
            if (res.Headers.TryGetValues("Set-Cookie", out var set))
            {
                foreach (var c in set) cookies.SetCookies(new Uri("https://app.example/"), c);
            }
            return res;
        }

        var denied = await Get("/account");
        Assert.Equal(HttpStatusCode.Redirect, denied.StatusCode);
        Assert.StartsWith("https://app.example/login?returnTo=%2Faccount", denied.Headers.Location!.ToString());
        var login = await Get(denied.Headers.Location.PathAndQuery);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var authorize = login.Headers.Location!.ToString();
        Assert.Equal("https://app.example/callback", HostedLogin.ParseQuery(authorize)["redirect_uri"]);
        var (code, state) = tenant.Authorize(authorize);
        var callback = await Get($"/callback?code={code}&state={Uri.EscapeDataString(state)}");
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/account", callback.Headers.Location!.ToString());
        var account = await Get("/account");
        Assert.Equal(HttpStatusCode.OK, account.StatusCode);
        Assert.Equal("a@acme.test", (string?)(await account.Content.ReadFromJsonAsync<JsonObject>())!["email"]);
        var logout = await Get("/logout");
        Assert.StartsWith(FakeTenant.Issuer + "/oidc/logout?client_id=client-123&id_token_hint=", logout.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.Redirect, (await Get("/account")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Get("/callback?code=x&state=y")).StatusCode);
    }

    [Fact]
    public async Task BearerHandlerChecksTouchqueLoginAccessTokens()
    {
        using var tenant = new FakeTenant();
        await using var app = await AppAsync(a =>
        {
            a.UseAuthentication();
            a.UseAuthorization();
            a.MapGet("/orders", (ClaimsPrincipal user) => Results.Ok(new { sub = user.FindFirstValue(ClaimTypes.NameIdentifier) }))
                .RequireAuthorization(p => p.AddAuthenticationSchemes(TouchqueBearerOptions.DefaultScheme).RequireAuthenticatedUser());
        }, s =>
        {
            s.AddAuthentication(TouchqueBearerOptions.DefaultScheme).AddTouchqueBearer(o =>
            {
                o.Domain = FakeTenant.Issuer;
                o.Audience = "https://api.acme.test";
                o.RequiredScopes = new[] { "read:orders" };
                o.Backchannel = tenant.Client();
            });
            s.AddAuthorization();
        });
        var client = app.GetTestClient();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string Token(string scope, string aud = "https://api.acme.test") => tenant.Jwt(new JsonObject
        {
            ["iss"] = FakeTenant.Issuer, ["sub"] = "usr_9", ["aud"] = aud, ["exp"] = now + 300, ["iat"] = now, ["scope"] = scope,
        }, "at+jwt");
        HttpRequestMessage Get(string? token)
        {
            var req = new HttpRequestMessage(HttpMethod.Get, "/orders");
            if (token is not null) req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            return req;
        }
        var ok = await client.SendAsync(Get(Token("openid read:orders")));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal("usr_9", (string?)(await ok.Content.ReadFromJsonAsync<JsonObject>())!["sub"]);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Get(null))).StatusCode);
        var wrongAud = await client.SendAsync(Get(Token("read:orders", "https://other.test")));
        Assert.Equal(HttpStatusCode.Unauthorized, wrongAud.StatusCode);
        Assert.Contains("invalid_token", wrongAud.Headers.WwwAuthenticate.ToString());
        var scope = await client.SendAsync(Get(Token("openid")));
        Assert.Equal(HttpStatusCode.Forbidden, scope.StatusCode);
        Assert.Contains("insufficient_scope", scope.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task McpEndpointsServeMetadataAndRefuseWithoutAToken()
    {
        var auth = new McpAuth(new McpAuthOptions { Issuer = _api.BaseUrl + "/mcp-as", Resource = "http://localhost/mcp", Tools = new Dictionary<string, string> { ["search"] = "tickets:read" } });
        await using var app = await AppAsync(a =>
        {
            a.MapTouchqueMcpMetadata(auth);
            a.MapPost("/mcp", (HttpContext http) => Results.Ok(new { sub = http.GetTouchqueMcpClaims()!.Sub })).RequireTouchqueMcp(auth);
        });
        var client = app.GetTestClient();
        var meta = await client.GetFromJsonAsync<JsonObject>("/.well-known/oauth-protected-resource/mcp");
        Assert.Equal("http://localhost/mcp", (string?)meta!["resource"]);
        var refused = await client.PostAsync("/mcp", null);
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Contains("resource_metadata=", refused.Headers.WwwAuthenticate.ToString());
        var token = (string)(await _api.PostAsync("/__test/mcp-token", new { aud = "http://localhost/mcp", scope = "tickets:read" }))!["token"]!;
        var req = new HttpRequestMessage(HttpMethod.Post, "/mcp");
        req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        var ok = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal("user-1", (string?)(await ok.Content.ReadFromJsonAsync<JsonObject>())!["sub"]);
    }

    [Fact]
    public async Task SafeReturnTo()
    {
        Assert.Equal("/a?b=1", TouchqueLoginExtensions.SafeReturnTo("/a?b=1"));
        foreach (var bad in new[] { "https://evil.example", "//evil.example", "/\\evil.example", "", null })
        {
            Assert.Equal("/", TouchqueLoginExtensions.SafeReturnTo(bad));
        }
        await Task.CompletedTask;
    }
}

[Microsoft.AspNetCore.Mvc.ApiController]
public sealed class PayoutsController : Microsoft.AspNetCore.Mvc.ControllerBase
{
    [Microsoft.AspNetCore.Mvc.HttpPost("/payouts")]
    [RequireTouchque("SEND_MONEY")]
    public IResult Create() => Results.Ok(new { via = HttpContext.GetTouchqueApproval()?.ConfirmedVia });
}
