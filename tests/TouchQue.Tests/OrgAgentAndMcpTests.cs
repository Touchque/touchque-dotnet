using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using TouchQue.Internal;
using Xunit;

namespace TouchQue.Tests;

/// <summary>An organization's AI agent on TouchQue SSO, and McpAuth, against the fake API.</summary>
[Collection("fake-api")]
public class OrgAgentAndMcpTests : IAsyncLifetime
{
    private const string App = "tqapp_paymentsapi0000000000";
    private const string Resource = "https://mcp.acme.example/mcp";
    private readonly FakeApi _api;

    public OrgAgentAndMcpTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(int Status, JsonObject Body)> ResourceAsync(IReadOnlyDictionary<string, string> headers)
    {
        using var http = new HttpClient();
        using var req = new HttpRequestMessage(HttpMethod.Get, _api.BaseUrl + "/__test/resource");
        foreach (var (k, v) in headers) req.Headers.TryAddWithoutValidation(k, v);
        using var res = await http.SendAsync(req);
        return ((int)res.StatusCode, Json.ParseObject(await res.Content.ReadAsStringAsync()));
    }

    [Fact]
    public async Task OwnKeyTokenAndCalls()
    {
        var keys = AgentKeys.Generate();
        const string id = "oagt_abcdefghijkmnpqrstuv";
        await _api.PostAsync("/__test/org-agent", new { agentId = id, publicKey = keys.PublicJwk, audiences = new[] { App }, scopes = new[] { "invoices:read", "payments:create" } });
        using var agent = new TouchQueOrgAgent(new TouchQueOrgAgentOptions { AgentId = id, PrivateKey = keys.PrivateJwk, Issuer = _api.BaseUrl });
        var token = await agent.GetTokenAsync(scope: "invoices:read");
        Assert.Equal(("DPoP", 300, "invoices:read"), (token.TokenType, token.ExpiresIn, token.Scope));
        Assert.Same(token, await agent.GetTokenAsync(scope: "invoices:read"));
        var headers = await agent.AuthorizationAsync("GET", _api.BaseUrl + "/__test/resource", scope: "invoices:read");
        var (status, body) = await ResourceAsync(headers);
        Assert.Equal(200, status);
        JsonAssert.Equal(new { ok = true, sub = id, aud = App, via = "key" }, body);
        Assert.Equal(401, (await ResourceAsync(headers)).Status); // a proof is for one request
        Assert.Equal("invalid_scope", (await Assert.ThrowsAsync<TouchQueApiException>(() => agent.GetTokenAsync(scope: "payments:refund"))).Code);
    }

    [Fact]
    public async Task PlatformToken()
    {
        const string id = "oagt_bbbbbbbbbbbbbbbbbbbb";
        await _api.PostAsync("/__test/org-agent", new { agentId = id, workload = new { subject = "repo:acme/payments:ref:refs/heads/main", audience = "touchque" }, audiences = new[] { App }, scopes = new[] { "invoices:read" } });
        Func<string, Func<CancellationToken, Task<string>>> platform = sub => async _ => (string)(await _api.PostAsync("/__test/workload-token", new { sub, aud = "touchque" }))!["token"]!;
        using var agent = new TouchQueOrgAgent(new TouchQueOrgAgentOptions { AgentId = id, Issuer = _api.BaseUrl, Assertion = platform("repo:acme/payments:ref:refs/heads/main") });
        Assert.Equal("workload", (string?)(await ResourceAsync(await agent.AuthorizationAsync("GET", _api.BaseUrl + "/__test/resource"))).Body["via"]);
        using var wrong = new TouchQueOrgAgent(new TouchQueOrgAgentOptions { AgentId = id, Issuer = _api.BaseUrl, Assertion = platform("repo:evil/x") });
        await Assert.ThrowsAsync<TouchQueApiException>(() => wrong.GetTokenAsync());
    }

    [Fact]
    public async Task ForAMember()
    {
        var keys = AgentKeys.Generate("EdDSA");
        const string id = "oagt_cccccccccccccccccccc";
        await _api.PostAsync("/__test/org-agent", new { agentId = id, publicKey = keys.PublicJwk, audiences = new[] { App }, scopes = new[] { "payments:create" }, delegation = new[] { "token_exchange", "ciba" }, sharedAccounts = new[] { "k3JInstagramAcme01" } });
        using var agent = new TouchQueOrgAgent(new TouchQueOrgAgentOptions { AgentId = id, PrivateKey = keys.PrivateJwk, Issuer = _api.BaseUrl });
        var url = _api.BaseUrl + "/__test/resource";
        async Task<JsonObject> Call(string t) => (await ResourceAsync(new Dictionary<string, string> { ["Authorization"] = "DPoP " + t, ["DPoP"] = agent.DpopProof("GET", url, t) })).Body;

        var exchanged = await agent.ExchangeTokenAsync("member:ada@acme.com");
        Assert.Equal("ada@acme.com", (string?)(await Call(exchanged.AccessToken))["sub"]);
        var google = await agent.GetConnectionTokenAsync("member:ada@acme.com", "google", "email");
        Assert.Equal(("ya29.ada@acme.com", "Bearer", 3599, "email", "google"), (google.AccessToken, google.TokenType, google.ExpiresIn, google.Scope, google.Connection));
        Assert.Equal("invalid_grant", (await Assert.ThrowsAsync<TouchQueApiException>(() => agent.GetConnectionTokenAsync("member:ada@acme.com", "github"))).Code);

        var payment = new { type = "payment_initiation", instructedAmount = new { currency = "TRY", amount = "500.00" } };
        var ask = await agent.AskMemberAsync("ada@acme.com", new AskMemberOptions { BindingMessage = "Pay invoice 42", AuthorizationDetails = new[] { payment } });
        Assert.Equal(("42", 1), (ask.BindingCode, ask.Interval));
        await _api.PostAsync("/__test/ciba-answer", new { authReqId = ask.AuthReqId, approve = true });
        var approved = await agent.WaitForMemberAsync(ask);
        JsonAssert.Equal(new[] { payment }, approved.AuthorizationDetails);
        Assert.Equal(id, (string?)(await Call(approved.AccessToken))["act"]);

        var shared = await agent.AskToOpenSharedAccountAsync("k3JInstagramAcme01", "ada@acme.com", "Post the launch photo");
        Assert.Equal("waiting_member", shared.Status);
        Assert.Contains("/agent-ask?ask=" + shared.AskId, shared.OpenUrl);
        await _api.PostAsync("/__test/shared-ask-answer", new { askId = shared.AskId, status = "declined" });
        var ended = await agent.WaitForSharedAccountAsync(shared, TimeSpan.FromMilliseconds(50));
        Assert.Equal(("declined", (string?)null, (string?)null), (ended.Status, ended.Reason, ended.CaseCode));

        var no = await agent.AskMemberAsync("ada@acme.com");
        await _api.PostAsync("/__test/ciba-answer", new { authReqId = no.AuthReqId, approve = false });
        Assert.Equal("access_denied", (await Assert.ThrowsAsync<TouchQueApiException>(() => agent.WaitForMemberAsync(no))).Code);
    }

    [Fact]
    public void OrgAgentConfigurationMistakes()
    {
        Assert.Throws<TouchQueConfigException>(() => new TouchQueOrgAgent(new TouchQueOrgAgentOptions
        {
            AgentId = "oagt_abcdefghijkmnpqrstuv", Issuer = "http://sso.example.com", Assertion = _ => Task.FromResult("x"),
        }));
        Assert.Throws<TouchQueConfigException>(() => new TouchQueOrgAgent(new TouchQueOrgAgentOptions { AgentId = "agt_nope", Assertion = _ => Task.FromResult("x") }));
    }

    private async Task<string> McpTokenAsync(object? claims = null)
    {
        var body = (claims is null ? new JsonObject() : (JsonObject)System.Text.Json.JsonSerializer.SerializeToNode(claims)!);
        body.TryAdd("aud", Resource);
        body.TryAdd("scope", "tickets:read");
        return (string)(await _api.PostAsync("/__test/mcp-token", body))!["token"]!;
    }

    private McpAuth Mcp() => new(new McpAuthOptions
    {
        Issuer = _api.BaseUrl + "/mcp-as", Resource = Resource,
        Tools = new Dictionary<string, string> { ["search_tickets"] = "tickets:read", ["delete_ticket"] = "tickets:delete" },
    });

    [Fact]
    public async Task McpMetadataTokensAndScopes()
    {
        var auth = Mcp();
        Assert.Equal(new[] { "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp" }, auth.MetadataPaths());
        Assert.Equal(_api.BaseUrl + "/mcp-as", (string?)auth.ProtectedResourceMetadata()["authorization_servers"]![0]);
        var claims = await auth.VerifyAsync("POST", Resource, new Dictionary<string, string> { ["Authorization"] = "Bearer " + await McpTokenAsync() });
        Assert.Equal(("user-1", false, "https://tool.example/client.json"), (claims.Sub, claims.DpopBound, claims.ClientId));
        Assert.Equal(new[] { "tickets:read" }, claims.Scopes);
        auth.RequireTool(claims, "search_tickets");
        var e = Assert.Throws<TouchQueMcpAuthException>(() => auth.RequireTool(claims, "delete_ticket"));
        Assert.Equal(403, e.Status);
        Assert.Contains("scope=\"tickets:delete\"", e.WwwAuthenticate);
        e = await Assert.ThrowsAsync<TouchQueMcpAuthException>(() => auth.VerifyAsync("POST", Resource, new Dictionary<string, string>()));
        Assert.Equal((401, "Bearer resource_metadata=\"https://mcp.acme.example/.well-known/oauth-protected-resource/mcp\""), (e.Status, e.WwwAuthenticate));
        foreach (var bad in new object[] { new { aud = "https://other.example/mcp" }, new { iss = "https://evil.example/mcp" }, new { expiresIn = -120 }, new { typ = "JWT" } })
        {
            var token = await McpTokenAsync(bad);
            Assert.Equal("invalid_token", (await Assert.ThrowsAsync<TouchQueMcpAuthException>(() => auth.VerifyAsync("POST", Resource, new Dictionary<string, string> { ["Authorization"] = "Bearer " + token }))).Error);
        }
    }

    [Fact]
    public async Task McpDpopBound()
    {
        var auth = Mcp();
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ec.ExportParameters(false);
        var jwk = new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Base64Url.Encode(p.Q.X!), ["y"] = Base64Url.Encode(p.Q.Y!) };
        var token = await McpTokenAsync(new { jkt = AgentKeys.Thumbprint(jwk) });
        string Proof(string htu = Resource)
        {
            var h = Base64Url.Encode(new JsonObject { ["typ"] = "dpop+jwt", ["alg"] = "ES256", ["jwk"] = jwk.DeepClone() }.ToJsonString());
            var c = Base64Url.Encode(new JsonObject
            {
                ["htm"] = "POST", ["htu"] = htu, ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["jti"] = Guid.NewGuid().ToString("N"), ["ath"] = AgentKeys.AccessTokenHash(token),
            }.ToJsonString());
            return h + "." + c + "." + Base64Url.Encode(ec.SignData(Encoding.ASCII.GetBytes(h + "." + c), HashAlgorithmName.SHA256));
        }
        await Assert.ThrowsAsync<TouchQueMcpAuthException>(() => auth.VerifyAsync("POST", Resource, new Dictionary<string, string> { ["Authorization"] = "Bearer " + token }));
        var good = Proof();
        Assert.True((await auth.VerifyAsync("POST", Resource, new Dictionary<string, string> { ["Authorization"] = "DPoP " + token, ["DPoP"] = good })).DpopBound);
        Assert.Equal("invalid_dpop_proof", (await Assert.ThrowsAsync<TouchQueMcpAuthException>(() => auth.VerifyAsync("POST", Resource, new Dictionary<string, string> { ["Authorization"] = "DPoP " + token, ["DPoP"] = good }))).Error);
        await Assert.ThrowsAsync<TouchQueMcpAuthException>(() => auth.VerifyAsync("POST", Resource, new Dictionary<string, string> { ["Authorization"] = "DPoP " + token, ["DPoP"] = Proof("https://other.example/mcp") }));
    }

    [Fact]
    public async Task OutageVerifiersFetchThenMatchOffline()
    {
        await _api.LinkAsync("vpn@example.com");
        var tq = _api.Client();
        var now = DateTimeOffset.UtcNow;
        var step = now.ToUnixTimeSeconds() / 30;
        var v = await tq.Offline.TotpVerifiersAsync(new[] { "vpn@example.com", "nobody@example.com" }, step - 1, 4);
        var user = Assert.Single(v.Users);
        Assert.Equal("vpn@example.com", user.ExternalUsername);
        Assert.Equal(step, OfflineResource.MatchTotpVerifier(v, user, "k7p-2qxa", now));
        Assert.Null(OfflineResource.MatchTotpVerifier(v, user, "K7P2QXB", now));
        Assert.Null(OfflineResource.MatchTotpVerifier(v, user, "K7P2QXA", now.AddHours(1)));
        Assert.Null(OfflineResource.MatchTotpVerifier(v, user, "K7P2QX1", now));
        await _api.OptsAsync(new { outageVerifiersDisabled = true });
        await Assert.ThrowsAsync<TouchQueApiException>(() => tq.Offline.TotpVerifiersAsync(new[] { "vpn@example.com" }));
    }
}
