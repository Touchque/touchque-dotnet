using System.Text;
using System.Text.Json.Nodes;
using TouchQue.Internal;
using Xunit;

namespace TouchQue.Tests;

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
        catch (TouchQueIdJagException e)
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
        var refused = await Assert.ThrowsAsync<TouchQueIdJagException>(() => CrossAppAccess.RequestIdJagAsync(new() { Issuer = idp, ClientId = "tqapp_test", ClientSecret = "wrong", IdToken = "idtoken:ada", Audience = "https://rs.example" }));
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

    private static async Task<string> Code(Func<Task> f)
    {
        try
        {
            await f();
            return "verified";
        }
        catch (TouchQueAgentCardException e)
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
