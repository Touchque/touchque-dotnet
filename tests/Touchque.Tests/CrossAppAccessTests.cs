using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Touchque.Internal;
using Xunit;

namespace Touchque.Tests;

/// <summary>
/// Cross App Access (ID-JAG) and A2A agent card signatures against the fake API: an app
/// trades a member's ID token for an ID-JAG at the identity provider and redeems it; an
/// authorization server checks one (issuer, audience, client, expiry, typ, once); a card
/// signed in RFC 8785 form by the fake (JavaScript) verifies here with keys from its own
/// host and fails when changed or pointed elsewhere.
/// </summary>
[Collection("fake-api")]
public class CrossAppAccessTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public CrossAppAccessTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private IdJagVerifier Verifier() => new(new IdJagVerifierOptions { Issuer = _api.BaseUrl + "/idp", Audience = "https://rs.example" });

    private static async Task<string> Reason(Func<Task> f)
    {
        try
        {
            await f();
            return "accepted";
        }
        catch (TouchqueIdJagException e)
        {
            return e.Message;
        }
    }

    [Fact]
    public async Task RequestRedeemAndVerify()
    {
        var idp = _api.BaseUrl + "/idp";
        var jag = await CrossAppAccess.RequestIdJagAsync(new() { Issuer = idp, ClientId = "tqapp_test", ClientSecret = "tqs_test", IdToken = "idtoken:ada", Audience = "https://rs.example", Resource = "https://rs.example/files" });
        Assert.Equal("files:read", jag.Scope);
        var refused = await Assert.ThrowsAsync<TouchqueIdJagException>(() => CrossAppAccess.RequestIdJagAsync(new() { Issuer = idp, ClientId = "tqapp_test", ClientSecret = "wrong", IdToken = "idtoken:ada", Audience = "https://rs.example" }));
        Assert.Equal(("invalid_client", (int?)401), (refused.Error, refused.Status));

        var v = Verifier();
        var claims = await v.VerifyAsync(jag.Assertion, "acme-at-rs");
        Assert.Equal(("ada", "acme-at-rs", "files:read", "https://rs.example/files"), (claims.Sub, claims.ClientId, string.Join(' ', claims.Scopes), claims.Resource));
        Assert.Equal("already used", await Reason(() => v.VerifyAsync(jag.Assertion, "acme-at-rs")));
        var tokens = await CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = _api.BaseUrl + "/rs/token", ClientId = "acme-at-rs", Assertion = jag.Assertion });
        Assert.Equal("Bearer", Json.Str(tokens, "token_type"));
    }

    [Fact]
    public async Task Refusals()
    {
        var v = Verifier();
        async Task<string> Mint(JsonObject? claims = null, string? typ = null)
        {
            var body = new JsonObject { ["claims"] = claims ?? new JsonObject() };
            if (typ is not null) body["typ"] = typ;
            return Json.Str(await _api.PostAsync("/__test/id-jag", body), "assertion")!;
        }
        Assert.Equal("issued to another client", await Reason(async () => await v.VerifyAsync(await Mint(), "someone-else")));
        Assert.Equal("not for this authorization server", await Reason(async () => await v.VerifyAsync(await Mint(new() { ["aud"] = "https://evil.example" }), "acme-at-rs")));
        Assert.Equal("not for this authorization server", await Reason(async () => await v.VerifyAsync(await Mint(new() { ["aud"] = new JsonArray("https://rs.example", "https://b.example") }), "acme-at-rs")));
        Assert.Equal("another issuer", await Reason(async () => await v.VerifyAsync(await Mint(new() { ["iss"] = "https://evil.example" }), "acme-at-rs")));
        Assert.Equal("not an ID-JAG (typ oauth-id-jag+jwt)", await Reason(async () => await v.VerifyAsync(await Mint(null, "at+jwt"), "acme-at-rs")));
        Assert.Equal("expired", await Reason(async () => await v.VerifyAsync(await Mint(new() { ["exp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 600 }), "acme-at-rs")));
        var parts = (await Mint()).Split('.');
        var c = Json.ParseObject(Encoding.UTF8.GetString(Base64Url.Decode(parts[1])));
        c["sub"] = "mallory";
        Assert.Equal("signature does not verify", await Reason(() => v.VerifyAsync(parts[0] + "." + Base64Url.Encode(c.ToJsonString()) + "." + parts[2], "acme-at-rs")));
    }

    [Fact]
    public async Task DpopBoundRequestRedeemAndVerify()
    {
        // An identity provider and an authorization server that check the proof and bind to its key.
        var seen = new List<(string Path, JsonObject Header, JsonObject Payload, string Jkt)>();
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var app = builder.Build();
        app.Run(async http =>
        {
            http.Response.ContentType = "application/json";
            var proof = JwsVerify.Split(http.Request.Headers["DPoP"].ToString());
            var jwk = proof?.Header["jwk"] as JsonObject;
            if (proof is not { } p || jwk is null || !JwsVerify.Verify("ES256", jwk, p.Input, p.Signature))
            {
                http.Response.StatusCode = 400;
                await http.Response.WriteAsync("{\"error\":\"invalid_dpop_proof\"}");
                return;
            }
            var path = http.Request.Path + http.Request.QueryString;
            var jkt = AgentKeys.Thumbprint(jwk);
            lock (seen) seen.Add((path, p.Header, p.Claims, jkt));
            if (path == "/idp/token?x=1")
            {
                var jag = Base64Url.Encode("{\"typ\":\"oauth-id-jag+jwt\",\"alg\":\"RS256\"}") + "." + Base64Url.Encode(new JsonObject { ["cnf"] = new JsonObject { ["jkt"] = jkt } }.ToJsonString()) + ".sig";
                await http.Response.WriteAsync(new JsonObject { ["access_token"] = jag, ["issued_token_type"] = CrossAppAccess.IdJagTokenType, ["token_type"] = "N_A" }.ToJsonString());
                return;
            }
            await http.Response.WriteAsync("{\"access_token\":\"at\",\"token_type\":\"DPoP\"}");
        });
        await app.StartAsync();
        var local = app.Urls.First().TrimEnd('/');

        using var key = CrossAppAccess.CreateIdJagDpopKey();
        var got = await CrossAppAccess.RequestIdJagAsync(new() { TokenEndpoint = local + "/idp/token?x=1", ClientId = "tqapp_test", ClientSecret = "tqs_test", IdToken = "idtoken:ada", Audience = "https://rs.example", DpopKey = key });
        Assert.True(got.DpopBound);
        var tokens = await CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = local + "/rs/token", ClientId = "acme-at-rs", Assertion = got.Assertion, DpopKey = key });
        Assert.Equal("DPoP", Json.Str(tokens, "token_type"));
        Assert.Equal(2, seen.Count);
        Assert.Equal(("dpop+jwt", "ES256", key.Thumbprint), (Json.Str(seen[0].Header, "typ"), Json.Str(seen[0].Header, "alg"), seen[0].Jkt));
        Assert.False(((JsonObject)seen[0].Header["jwk"]!).ContainsKey("d"));
        Assert.Equal(("POST", local + "/idp/token"), (Json.Str(seen[0].Payload, "htm"), Json.Str(seen[0].Payload, "htu")));
        Assert.Equal((local + "/rs/token", key.Thumbprint), (Json.Str(seen[1].Payload, "htu"), seen[1].Jkt));
        Assert.NotEqual(Json.Str(seen[0].Payload, "jti"), Json.Str(seen[1].Payload, "jti"));

        // An identity provider that ignores DPoP answers with a bearer ID-JAG: DpopBound false.
        using var other = CrossAppAccess.CreateIdJagDpopKey();
        var plainJag = await CrossAppAccess.RequestIdJagAsync(new() { Issuer = _api.BaseUrl + "/idp", ClientId = "tqapp_test", ClientSecret = "tqs_test", IdToken = "idtoken:ada", Audience = "https://rs.example", DpopKey = other });
        Assert.False(plainJag.DpopBound);

        // The verifier: a bound ID-JAG needs the proof key's thumbprint, refused before it is used up.
        var v = Verifier();
        async Task<string> Mint(JsonObject claims) => Json.Str(await _api.PostAsync("/__test/id-jag", new JsonObject { ["claims"] = claims }), "assertion")!;
        var bound = await Mint(new() { ["cnf"] = new JsonObject { ["jkt"] = "right-key-thumbprint" } });
        Assert.Equal("bound to a DPoP key: a DPoP proof with that key is required", await Reason(() => v.VerifyAsync(bound, "acme-at-rs")));
        Assert.Equal("the DPoP proof was made with another key", await Reason(() => v.VerifyAsync(bound, "acme-at-rs", "other-key")));
        Assert.Equal("right-key-thumbprint", (await v.VerifyAsync(bound, "acme-at-rs", "right-key-thumbprint")).CnfJkt);
        var odd = await Mint(new() { ["cnf"] = new JsonObject { ["x5t"] = "abc" } });
        Assert.Equal("unsupported confirmation method (only DPoP cnf.jkt)", await Reason(() => v.VerifyAsync(odd, "acme-at-rs", "x")));
        // Unbound: as before, with or without a proof key.
        Assert.Null((await v.VerifyAsync(await Mint(new()), "acme-at-rs", "any")).CnfJkt);
    }

    private static async Task<string> Code(Func<Task> f)
    {
        try
        {
            await f();
            return "verified";
        }
        catch (TouchqueAgentCardException e)
        {
            return e.Error;
        }
    }

    [Fact]
    public async Task AgentCards()
    {
        using var http = new HttpClient();
        var url = _api.BaseUrl + "/.well-known/agent-card.json";
        var card = await http.GetStringAsync(url);
        Assert.Equal(new AgentCardVerification("a2a-1", "ES256", "jku"), await AgentCard.VerifyAsync(card, new() { CardUrl = url }));
        var tampered = await http.GetStringAsync(url + "?tamper=1");
        Assert.Equal("invalid_signature", await Code(() => AgentCard.VerifyAsync(tampered, new() { CardUrl = url })));
        Assert.Equal("untrusted_key", await Code(() => AgentCard.VerifyAsync(card, new() { CardUrl = "https://agent.example/.well-known/agent-card.json" })));
        Assert.Equal("unsigned", await Code(() => AgentCard.VerifyAsync("{\"name\":\"x\"}")));

        var keys = AgentKeys.Generate("EdDSA");
        var signed = AgentCard.Sign("{\"name\":\"Mine\",\"url\":\"https://mine.example/a2a\",\"skills\":[]}", keys.PrivateJwk, "k1");
        var jwk = (JsonObject)keys.PublicJwk.DeepClone();
        jwk["kid"] = "k1";
        Assert.Equal(new AgentCardVerification("k1", "EdDSA", "keys"), await AgentCard.VerifyAsync(signed, new() { Keys = new[] { jwk } }));
        Assert.Equal("invalid_signature", await Code(() => AgentCard.VerifyAsync(signed.Replace("mine.example", "evil.example"), new() { Keys = new[] { jwk } })));

        var value = JsonNode.Parse("{\"€\":\"Euro\",\"\\r\":\"CR\",\"😀\":\"smile\",\"1\":\"one\",\"a\":[1e21,1e-7,0.5,-0,\"tab\\there\",1e-5,100.0]}");
        Assert.Equal("{\"\\r\":\"CR\",\"1\":\"one\",\"a\":[1e+21,1e-7,0.5,0,\"tab\\there\",0.00001,100],\"€\":\"Euro\",\"😀\":\"smile\"}", AgentCard.CanonicalJson(value));
    }
}
