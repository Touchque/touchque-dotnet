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
using TouchQue.AspNetCore;
using TouchQue.Relay;
using Xunit;

namespace TouchQue.Tests;

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
        builder.Services.AddTouchQue(o =>
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

    private static HttpRequestMessage Post(string path, string? user = null, string? token = null, object? body = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body ?? new { }) };
        if (user is not null) req.Headers.Add("X-User", user);
        if (token is not null) req.Headers.Add(Guard.TokenHeader, token);
        return req;
    }

    [Fact]
    public async Task RequireTouchQueOnAMinimalApiEndpoint()
    {
        await _api.LinkAsync("ada@acme.com");
        var ran = 0;
        await using var app = await AppAsync(a => a.MapPost("/transfer", (Transfer t, HttpContext http) =>
        {
            ran++;
            return Results.Ok(new { done = true, via = http.GetTouchQueApproval()!.ConfirmedVia });
        }).RequireTouchQue("SEND_MONEY", o => o.Details = c => new LoginDetail[] { ("Amount", c.Argument<Transfer>()!.Amount), ("To", c.Argument<Transfer>()!.To) }));
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
    public async Task RequireTouchQueOnAController()
    {
        await _api.LinkAsync("bo@acme.com");
        await _api.OptsAsync(new { frozen = true });
        await using var app = await AppAsync(a => a.MapControllers());
        var res = await app.GetTestClient().SendAsync(Post("/payouts", "bo@acme.com"));
        Assert.Equal((HttpStatusCode)423, res.StatusCode);
        Assert.Equal("900", res.Headers.RetryAfter!.ToString());
        await _api.OptsAsync(new { frozen = false });
        var waiting = await app.GetTestClient().SendAsync(Post("/payouts", "bo@acme.com"));
        Assert.Equal(HttpStatusCode.Accepted, waiting.StatusCode);
    }

    [Fact]
    public async Task RelayLoginWithAFirstFactorAndOnAuthenticated()
    {
        await _api.LinkAsync("cy@acme.com");
        var opened = new List<string>();
        await using var app = await AppAsync(a => a.MapTouchQueRelay("/touchque", new RelayOptions<HttpContext>
        {
            GetUserId = http => http.User.TouchQueUser(),
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
        await using var app = await AppAsync(a => a.MapGroup("/api/{tenant}").MapTouchQueRelay("/touchque", new RelayOptions<HttpContext>
        {
            GetUserId = http => http.User.TouchQueUser(),
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
        await using var app = await AppAsync(a => a.MapTouchQueRelay("/tq", new RelayOptions<HttpContext>
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
        await using var app = await AppAsync(a => a.MapTouchQueWebhook("/webhooks/touchque", (e, http) =>
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
            a.MapTouchQueLogin();
            a.MapGet("/account", (ClaimsPrincipal user) => Results.Ok(new { email = user.FindFirstValue(ClaimTypes.Email) })).RequireAuthorization();
        }, s =>
        {
            s.AddTouchQueLogin(o =>
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
    public async Task BearerHandlerChecksTouchQueLoginAccessTokens()
    {
        using var tenant = new FakeTenant();
        await using var app = await AppAsync(a =>
        {
            a.UseAuthentication();
            a.UseAuthorization();
            a.MapGet("/orders", (ClaimsPrincipal user) => Results.Ok(new { sub = user.FindFirstValue(ClaimTypes.NameIdentifier) }))
                .RequireAuthorization(p => p.AddAuthenticationSchemes(TouchQueBearerOptions.DefaultScheme).RequireAuthenticatedUser());
        }, s =>
        {
            s.AddAuthentication(TouchQueBearerOptions.DefaultScheme).AddTouchQueBearer(o =>
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
            a.MapTouchQueMcpMetadata(auth);
            a.MapPost("/mcp", (HttpContext http) => Results.Ok(new { sub = http.GetTouchQueMcpClaims()!.Sub })).RequireTouchQueMcp(auth);
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
        Assert.Equal("/a?b=1", TouchQueLoginExtensions.SafeReturnTo("/a?b=1"));
        foreach (var bad in new[] { "https://evil.example", "//evil.example", "/\\evil.example", "", null })
        {
            Assert.Equal("/", TouchQueLoginExtensions.SafeReturnTo(bad));
        }
        await Task.CompletedTask;
    }
}

[Microsoft.AspNetCore.Mvc.ApiController]
public sealed class PayoutsController : Microsoft.AspNetCore.Mvc.ControllerBase
{
    [Microsoft.AspNetCore.Mvc.HttpPost("/payouts")]
    [RequireTouchQue("SEND_MONEY")]
    public IResult Create() => Results.Ok(new { via = HttpContext.GetTouchQueApproval()?.ConfirmedVia });
}
