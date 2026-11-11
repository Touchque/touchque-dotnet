using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Touchque.Internal;
using Xunit;

namespace Touchque.Tests;

/// <summary>An in-process fake Touchque Login tenant: JWKS, /oauth/token with PKCE, /bc-authorize, My Account.</summary>
public sealed class FakeTenant : IDisposable
{
    public const string Issuer = "https://acme.login.touchque.com";
    public const string ClientId = "client-123";

    private readonly RSA _key = RSA.Create(2048);
    private readonly Dictionary<string, (string Challenge, string Nonce)> _codes = new();

    public RSA? SignWith { get; set; }
    public string? NonceOverride { get; set; }
    public List<(string Path, Dictionary<string, string> Fields, HttpRequestMessage Request)> Posts { get; } = new();
    public int Polls { get; set; }

    public string Jwt(JsonObject payload, string typ = "JWT", RSA? key = null)
    {
        var input = Base64Url.Encode(new JsonObject { ["alg"] = "RS256", ["typ"] = typ, ["kid"] = "k1" }.ToJsonString()) + "." + Base64Url.Encode(payload.ToJsonString());
        var sig = (key ?? _key).SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return input + "." + Base64Url.Encode(sig);
    }

    public (string Code, string State) Authorize(string url)
    {
        var q = HostedLogin.ParseQuery(url);
        var code = "code-" + _codes.Count;
        _codes[code] = (q["code_challenge"], q["nonce"]);
        return (code, q["state"]);
    }

    public HttpClient Client() => new(new StubHandler((req, body) => Answer(req, body)));

    private HttpResponseMessage Answer(HttpRequestMessage req, string? body)
    {
        var path = req.RequestUri!.AbsolutePath;
        if (path == "/.well-known/jwks.json")
        {
            var p = _key.ExportParameters(false);
            return StubHandler.Json(200, new { keys = new[] { new { kty = "RSA", kid = "k1", use = "sig", n = Base64Url.Encode(p.Modulus!), e = Base64Url.Encode(p.Exponent!) } } });
        }
        var f = HostedLogin.ParseQuery(body ?? "");
        if (req.Method == HttpMethod.Post) Posts.Add((path, f, req));
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (path == "/bc-authorize") return StubHandler.Json(200, new { auth_req_id = "req-1", expires_in = 300, interval = 0, binding_code = "42" });
        if (path == "/me/v1/profile" && req.Method == HttpMethod.Patch) return StubHandler.Json(200, new { profile = JsonNode.Parse(body!) });
        if (path == "/me/v1/password") return StubHandler.Json(401, new { error = "insufficient_user_authentication", error_description = "Sign in again", max_age = 0 });
        if (path == "/me/v1/sessions/s1") return new HttpResponseMessage(HttpStatusCode.NoContent);
        if (path != "/oauth/token") return StubHandler.Json(404, new { });
        switch (f.GetValueOrDefault("grant_type"))
        {
            case "authorization_code":
            {
                if (!_codes.TryGetValue(f["code"], out var c) || c.Challenge != Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(f["code_verifier"]))))
                {
                    return StubHandler.Json(400, new { error = "invalid_grant" });
                }
                var at = Jwt(new JsonObject { ["iss"] = Issuer, ["sub"] = "usr_1", ["aud"] = new JsonArray("https://api.acme.test"), ["exp"] = now + 300, ["iat"] = now, ["client_id"] = ClientId, ["scope"] = "openid read:orders" }, "at+jwt");
                var id = Jwt(new JsonObject
                {
                    ["iss"] = Issuer, ["sub"] = "usr_1", ["aud"] = ClientId, ["exp"] = now + 300, ["iat"] = now, ["nonce"] = NonceOverride ?? c.Nonce, ["email"] = "a@acme.test",
                    ["at_hash"] = Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(at)).AsSpan(0, 16)),
                }, "JWT", SignWith);
                return StubHandler.Json(200, new { access_token = at, token_type = "Bearer", expires_in = 300, scope = "openid", id_token = id, refresh_token = "tqr_1" });
            }
            case "refresh_token":
                return StubHandler.Json(200, new { access_token = "x", token_type = "Bearer", expires_in = 300, refresh_token = "tqr_2" });
            case "urn:ietf:params:oauth:grant-type:token-exchange" when f.GetValueOrDefault("requested_token_type") == HostedLogin.ConnectionTokenType:
                return StubHandler.Json(200, new { access_token = "ya29.g", token_type = "Bearer", expires_in = 3500, scope = "openid email", connection = f["connection"] });
            case "urn:ietf:params:oauth:grant-type:token-exchange":
                return StubHandler.Json(200, new { access_token = "at-x", token_type = "Bearer", expires_in = 120, issued_token_type = "urn:ietf:params:oauth:token-type:access_token" });
            case "urn:openid:params:grant-type:ciba":
                Polls++;
                if (Polls == 1) return StubHandler.Json(400, new { error = "authorization_pending" });
                if (f["auth_req_id"] == "denied") return StubHandler.Json(400, new { error = "access_denied" });
                return StubHandler.Json(200, new { access_token = "at-c", token_type = "Bearer", expires_in = 300, authorization_details = new[] { new { type = "payment_initiation" } } });
        }
        return StubHandler.Json(400, new { error = "unsupported_grant_type" });
    }

    public void Dispose() => _key.Dispose();
}

public class HostedLoginTests : IDisposable
{
    private readonly FakeTenant _tenant = new();

    public void Dispose() => _tenant.Dispose();

    private HostedLogin Login(string? secret = null) => new(new HostedLoginOptions
    {
        Domain = FakeTenant.Issuer, ClientId = FakeTenant.ClientId, ClientSecret = secret, RedirectUri = "https://app/cb", HttpClient = _tenant.Client(),
    });

    [Fact]
    public void AuthorizationUrl()
    {
        var req = new HostedLogin(new HostedLoginOptions { Domain = "acme.login.touchque.com", ClientId = FakeTenant.ClientId, RedirectUri = "https://app/cb", Audience = "https://api.acme.test" })
            .AuthorizationUrl(new AuthorizationOptions { ScreenHint = "signup" });
        var q = HostedLogin.ParseQuery(req.Url);
        Assert.StartsWith(FakeTenant.Issuer + "/authorize?", req.Url);
        Assert.Equal(Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(req.CodeVerifier))), q["code_challenge"]);
        Assert.Equal(("S256", req.State, "signup", "https://api.acme.test"), (q["code_challenge_method"], q["state"], q["screen_hint"], q["audience"]));
    }

    [Fact]
    public void PlainHttpIssuerOnlyOnLocalhost()
    {
        HostedLogin Make(string domain) => new(new HostedLoginOptions { Domain = domain, ClientId = FakeTenant.ClientId });
        foreach (var domain in new[] { "http://acme.login.touchque.com", "http://10.0.0.5:8080", "http://localhost.evil.com/" })
        {
            Assert.Equal("config", Assert.Throws<HostedLoginException>(() => Make(domain)).ErrorCode);
        }
        Assert.Equal("config", Assert.Throws<MyAccountException>(() => new MyAccount("http://acme.login.touchque.com", "at")).ErrorCode);
        foreach (var domain in new[] { "http://localhost:3000", "http://127.0.0.1:3000", "http://[::1]:3000", "http://acme.localhost:3000", "https://acme.login.touchque.com" })
        {
            Assert.Equal(domain, Make(domain + "/").Issuer);
        }
        Assert.Equal("https://acme.login.touchque.com", Make("acme.login.touchque.com").Issuer);
        Assert.Equal("http://localhost:3000/account", new MyAccount("http://localhost:3000", "at").AccountPageUrl());
    }

    [Fact]
    public async Task CallbackRefreshAndAccessToken()
    {
        var login = Login("s3cret");
        var req = login.AuthorizationUrl();
        var (code, state) = _tenant.Authorize(req.Url);
        var tokens = await login.HandleCallbackAsync($"https://app/cb?code={code}&state={Uri.EscapeDataString(state)}&iss={Uri.EscapeDataString(FakeTenant.Issuer)}",
            new CallbackChecks { State = req.State, Nonce = req.Nonce, CodeVerifier = req.CodeVerifier });
        Assert.Equal(("usr_1", "tqr_1"), ((string?)tokens.Claims["sub"], tokens.RefreshToken));
        var basic = _tenant.Posts[0].Request.Headers.Authorization!;
        Assert.Equal(("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(FakeTenant.ClientId + ":s3cret"))), (basic.Scheme, basic.Parameter));
        Assert.Equal("tqr_2", (await login.RefreshAsync("tqr_1")).RefreshToken);
        Assert.Equal("usr_1", (string?)(await login.VerifyAccessTokenAsync(tokens.AccessToken, "https://api.acme.test", new[] { "read:orders" }))["sub"]);
        Assert.Equal("insufficient_scope", (await Assert.ThrowsAsync<HostedLoginException>(() => login.VerifyAccessTokenAsync(tokens.AccessToken, "https://api.acme.test", new[] { "write:orders" }))).ErrorCode);
        await Assert.ThrowsAsync<HostedLoginException>(() => login.VerifyAccessTokenAsync(tokens.IdToken!, FakeTenant.ClientId));
    }

    [Fact]
    public async Task Refusals()
    {
        var login = Login();
        var req = login.AuthorizationUrl();
        var (code, state) = _tenant.Authorize(req.Url);
        var checks = new CallbackChecks { State = req.State, Nonce = req.Nonce, CodeVerifier = req.CodeVerifier };
        foreach (var (p, want) in new[]
        {
            (new Dictionary<string, string> { ["code"] = code, ["state"] = "x" }, "state_mismatch"),
            (new Dictionary<string, string> { ["error"] = "access_denied", ["state"] = state }, "access_denied"),
            (new Dictionary<string, string> { ["code"] = code, ["state"] = state, ["iss"] = "https://evil" }, "issuer_mismatch"),
        })
        {
            Assert.Equal(want, (await Assert.ThrowsAsync<HostedLoginException>(() => login.HandleCallbackAsync(p, checks))).ErrorCode);
        }
        _tenant.NonceOverride = "replayed";
        var req2 = login.AuthorizationUrl();
        var a2 = _tenant.Authorize(req2.Url);
        Assert.Equal("nonce_mismatch", (await Assert.ThrowsAsync<HostedLoginException>(() => login.HandleCallbackAsync(
            new Dictionary<string, string> { ["code"] = a2.Code, ["state"] = a2.State }, new CallbackChecks { State = req2.State, Nonce = req2.Nonce, CodeVerifier = req2.CodeVerifier }))).ErrorCode);
        _tenant.NonceOverride = null;
        using var other = RSA.Create(2048);
        _tenant.SignWith = other;
        var req3 = login.AuthorizationUrl();
        var a3 = _tenant.Authorize(req3.Url);
        var bad = await Assert.ThrowsAsync<HostedLoginException>(() => login.HandleCallbackAsync(
            new Dictionary<string, string> { ["code"] = a3.Code, ["state"] = a3.State }, new CallbackChecks { State = req3.State, Nonce = req3.Nonce, CodeVerifier = req3.CodeVerifier }));
        Assert.Contains("Bad signature", bad.Message);
    }

    [Fact]
    public async Task IssThisIssuerOrNoneIsAcceptedAForeignOrEmptyOneIsRefusedBeforeTheExchange()
    {
        var login = Login();
        var req = login.AuthorizationUrl();
        var (code, state) = _tenant.Authorize(req.Url);
        var checks = new CallbackChecks { State = req.State, Nonce = req.Nonce, CodeVerifier = req.CodeVerifier };
        foreach (var iss in new[] { "https://evil", FakeTenant.Issuer + ".evil", FakeTenant.Issuer + "/", "" })
        {
            var p = new Dictionary<string, string> { ["code"] = code, ["state"] = state, ["iss"] = iss };
            Assert.Equal("issuer_mismatch", (await Assert.ThrowsAsync<HostedLoginException>(() => login.HandleCallbackAsync(p, checks))).ErrorCode);
        }
        Assert.Equal("issuer_mismatch", (await Assert.ThrowsAsync<HostedLoginException>(
            () => login.HandleCallbackAsync($"https://app/cb?code={code}&state={Uri.EscapeDataString(state)}&iss=", checks))).ErrorCode);
        // A foreign error answer is reported as the issuer mismatch, not as its own error.
        Assert.Equal("issuer_mismatch", (await Assert.ThrowsAsync<HostedLoginException>(() => login.HandleCallbackAsync(
            new Dictionary<string, string> { ["error"] = "access_denied", ["state"] = state, ["iss"] = "https://evil" }, checks))).ErrorCode);
        Assert.Empty(_tenant.Posts);
        var tokens = await login.HandleCallbackAsync(new Dictionary<string, string> { ["code"] = code, ["state"] = state, ["iss"] = FakeTenant.Issuer }, checks);
        Assert.Equal("usr_1", (string?)tokens.Claims!["sub"]);

        // No iss (an older server): no field in the URL, or a null value for a missing field.
        var req2 = login.AuthorizationUrl();
        var a2 = _tenant.Authorize(req2.Url);
        var noIss = new Dictionary<string, string> { ["code"] = a2.Code, ["state"] = a2.State, ["iss"] = null! };
        tokens = await login.HandleCallbackAsync(noIss, new CallbackChecks { State = req2.State, Nonce = req2.Nonce, CodeVerifier = req2.CodeVerifier });
        Assert.Equal("usr_1", (string?)tokens.Claims!["sub"]);
        var req3 = login.AuthorizationUrl();
        var a3 = _tenant.Authorize(req3.Url);
        tokens = await login.HandleCallbackAsync($"https://app/cb?code={a3.Code}&state={Uri.EscapeDataString(a3.State)}",
            new CallbackChecks { State = req3.State, Nonce = req3.Nonce, CodeVerifier = req3.CodeVerifier });
        Assert.Equal("usr_1", (string?)tokens.Claims!["sub"]);
    }

    [Fact]
    public async Task ExchangeTokenCibaAndTokenVault()
    {
        var login = Login("s3cret");
        var ex = await login.ExchangeTokenAsync("user-at", "https://api.acme.test", "payments:create");
        Assert.Equal(("at-x", "urn:ietf:params:oauth:token-type:access_token"), (ex.AccessToken, ex.IssuedTokenType));
        Assert.Equal("user-at", _tenant.Posts[0].Fields["subject_token"]);
        var ask = await login.AskUserAsync("ada@acme.test", "openid payments:create", new AskUserOptions { BindingMessage = "Pay invoice 42", AuthorizationDetails = new[] { new { type = "payment_initiation" } } });
        Assert.Equal(("req-1", "42"), (ask.AuthReqId, ask.BindingCode));
        JsonAssert.Equal(new[] { new { type = "payment_initiation" } }, JsonNode.Parse(_tenant.Posts[1].Fields["authorization_details"]));
        var approved = await login.WaitForUserAsync(ask);
        JsonAssert.Equal(new[] { new { type = "payment_initiation" } }, approved.AuthorizationDetails);
        _tenant.Polls = 0;
        Assert.Equal("access_denied", (await Assert.ThrowsAsync<HostedLoginException>(() => login.WaitForUserAsync(ask with { AuthReqId = "denied" }))).ErrorCode);
        var vaulted = await login.GetConnectionTokenAsync("user-at", "google", "email");
        Assert.Equal(("ya29.g", "google"), (vaulted.AccessToken, vaulted.Connection));
        var last = _tenant.Posts[^1].Fields;
        Assert.Equal("email", last["scope"]);
        Assert.False(last.ContainsKey("audience"));
    }

    [Fact]
    public async Task MyAccountCallsAndStepUp()
    {
        var account = Login().MyAccount("at-me");
        var updated = await account.UpdateProfileAsync(new { name = "Ada", userMetadata = new { theme = (string?)null } });
        JsonAssert.Equal(JsonNode.Parse("""{"name":"Ada","userMetadata":{"theme":null}}"""), updated["profile"]);
        await account.EndSessionAsync("s1");
        var e = await Assert.ThrowsAsync<MyAccountException>(() => account.SetPasswordAsync("n3w-passw0rd"));
        Assert.True(e.IsStepUp);
        Assert.Equal((401, 0), (e.Status, e.MaxAge));
        Assert.Equal(FakeTenant.Issuer + "/account/security", account.AccountPageUrl("security"));
    }
}
