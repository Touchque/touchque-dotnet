using System.Text.Json.Nodes;
using Touchque.Internal;
using Xunit;

namespace Touchque.Tests;

/// <summary>
/// A JWS whose header or claims repeat a member name (also through an escape), or hold a lone surrogate:
/// System.Text.Json parses it and throws ArgumentException or InvalidOperationException only when a value is
/// first read. Every verifier refuses it with its own error instead, before any key is fetched.
/// </summary>
public class RepeatedMemberTests
{
    private static string Jws(string header, string claims) => Base64Url.Encode(header) + "." + Base64Url.Encode(claims) + ".c2ln";

    /// <summary>Tokens that would pass a verifier's typ and alg checks but for the repeated member.</summary>
    private static string[] Bad(string typ, string alg) =>
    [
        Jws($"{{\"typ\":\"{typ}\",\"typ\":\"{typ}\",\"alg\":\"{alg}\",\"kid\":\"k1\"}}", "{\"sub\":\"ada\"}"),
        Jws($"{{\"typ\":\"{typ}\",\"alg\":\"{alg}\",\"kid\":\"k1\",\"kid\":\"k2\"}}", "{\"sub\":\"ada\"}"),
        Jws($"{{\"typ\":\"{typ}\",\"t\\u0079p\":\"{typ}\",\"alg\":\"{alg}\",\"kid\":\"k1\"}}", "{\"sub\":\"ada\"}"),
        Jws($"{{\"typ\":\"{typ}\",\"alg\":\"{alg}\",\"kid\":\"k1\"}}", "{\"sub\":\"ada\",\"sub\":\"mallory\"}"),
        Jws($"{{\"typ\":\"{typ}\",\"alg\":\"{alg}\",\"kid\":\"k1\"}}", "{\"sub\":\"ada\",\"cnf\":{\"jkt\":\"a\",\"jkt\":\"b\"}}"),
        Jws($"{{\"typ\":\"{typ}\",\"alg\":\"{alg}\",\"kid\":\"\\ud800\"}}", "{\"sub\":\"ada\"}"),
        Jws($"{{\"typ\":\"{typ}\",\"alg\":\"{alg}\",\"kid\":\"k1\"}}", "{\"\\udc00\":\"ada\"}"),
    ];

    private static Task<JsonObject> NoFetch(string url, CancellationToken ct) => throw new InvalidOperationException("no key fetch expected: " + url);

    [Fact]
    public void SplitRefusesThemAndKeepsWellFormedParts()
    {
        foreach (var token in Bad("JWT", "ES256")) Assert.Null(JwsVerify.Split(token));
        var fine = JwsVerify.Split(Jws("{\"typ\":\"JWT\",\"alg\":\"ES256\",\"kid\":\"\\ud83d\\ude00\"}", "{\"a\":{\"a\":1},\"b\":[{\"a\":1},{\"a\":2}],\"Sub\":\"x\",\"sub\":\"y\"}"));
        Assert.NotNull(fine);
        Assert.Equal(("\U0001F600", "x", "y"), (Json.Str(fine.Value.Header, "kid"), Json.Str(fine.Value.Claims, "Sub"), Json.Str(fine.Value.Claims, "sub")));
        Assert.True(Json.IsIJson("{\"a\":[{\"b\":1},{\"b\":2}],\"c\":{\"b\":3}}"));
        Assert.False(Json.IsIJson("{\"a\":[{\"b\":1,\"b\":2}]}"));
    }

    [Fact]
    public async Task IdJagVerifierAnswersInvalidGrant()
    {
        var verifier = new IdJagVerifier(new IdJagVerifierOptions { Issuer = "https://sso.touchque.com", Audience = "https://rs.example", Fetch = NoFetch });
        foreach (var token in Bad("oauth-id-jag+jwt", "ES256"))
        {
            var e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => verifier.VerifyAsync(token, "acme-at-rs", "jkt"));
            Assert.Equal(("invalid_grant", "assertion is not a JWT"), (e.Error, e.Message));
            e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => verifier.VerifyAsync(token, "acme-at-rs"));
            Assert.Equal("invalid_grant", e.Error);
        }
    }

    [Fact]
    public async Task HostedLoginAnswersInvalidToken()
    {
        using var tenant = new FakeTenant();
        var login = new HostedLogin(new HostedLoginOptions { Domain = FakeTenant.Issuer, ClientId = FakeTenant.ClientId, HttpClient = tenant.Client() });
        foreach (var token in Bad("at+jwt", "RS256"))
        {
            Assert.Equal("invalid_token", (await Assert.ThrowsAsync<HostedLoginException>(() => login.VerifyAccessTokenAsync(token, "https://api.acme.test"))).ErrorCode);
            Assert.Equal("invalid_token", (await Assert.ThrowsAsync<HostedLoginException>(() => login.VerifyIdTokenAsync(token))).ErrorCode);
        }
    }

    [Fact]
    public void ApprovalTokensAreNotApprovalTokens()
    {
        var jwks = new JsonObject { ["keys"] = new JsonArray() };
        foreach (var token in Bad("touchque-approval+jwt", "ES256"))
        {
            Assert.Equal("Touchque: not an approval token", Assert.Throws<TouchqueApprovalMismatchException>(() => ApprovalToken.Decode(token)).Message);
            Assert.Equal("Touchque: not an approval token", Assert.Throws<TouchqueApprovalMismatchException>(() => ApprovalToken.VerifyWith(token, jwks, "touchque:workspace:w1")).Message);
        }
    }

    [Fact]
    public async Task McpAuthAnswersInvalidToken()
    {
        var auth = new McpAuth(new McpAuthOptions { Issuer = "https://sso.touchque.com/mcp", Resource = "https://mcp.acme.example/mcp", Fetch = NoFetch });
        foreach (var token in Bad("at+jwt", "ES256"))
        {
            foreach (var scheme in new[] { "Bearer ", "DPoP " })
            {
                var e = await Assert.ThrowsAsync<TouchqueMcpAuthException>(() => auth.VerifyAsync("POST", "https://mcp.acme.example/mcp", new Dictionary<string, string> { ["Authorization"] = scheme + token }));
                Assert.Equal((401, "invalid_token", "The token is malformed"), (e.Status, e.Error, e.Message));
            }
        }
    }

    [Fact]
    public async Task SecurityEventVerifierAnswersInvalidRequest()
    {
        var verifier = new SecurityEventVerifier(new SecurityEventVerifierOptions { Issuer = "https://sso.touchque.com", Audience = "https://app.example.com", Fetch = NoFetch });
        foreach (var token in Bad("secevent+jwt", "RS256"))
        {
            var e = await Assert.ThrowsAsync<TouchqueSecurityEventException>(() => verifier.VerifyAsync(token));
            Assert.Equal(("invalid_request", "not a JWT"), (e.Error, e.Message));
        }
    }

    [Fact]
    public async Task AgentCardsAreMalformedOrTheirSignatureIsSkipped()
    {
        var keys = AgentKeys.Generate("EdDSA");
        var jwk = (JsonObject)keys.PublicJwk.DeepClone();
        jwk["kid"] = "k1";
        var options = new AgentCardVerifyOptions { Keys = new[] { jwk } };
        var signed = AgentCard.Sign("{\"name\":\"Mine\",\"skills\":[{\"id\":\"a\"}]}", keys.PrivateJwk, "k1");
        Assert.Equal("k1", (await AgentCard.VerifyAsync(signed, options)).Kid);

        // A repeated member in the card (at any depth): malformed, from Sign too.
        foreach (var card in new[] { signed.Replace("\"name\":\"Mine\"", "\"name\":\"Mine\",\"name\":\"Evil\""), signed.Replace("{\"id\":\"a\"}", "{\"id\":\"a\",\"id\":\"b\"}") })
        {
            Assert.Equal("malformed", (await Assert.ThrowsAsync<TouchqueAgentCardException>(() => AgentCard.VerifyAsync(card, options))).Error);
            Assert.Equal("malformed", Assert.Throws<TouchqueAgentCardException>(() => AgentCard.Sign(card, keys.PrivateJwk, "k2")).Error);
        }

        // A signature whose protected header repeats a member or holds a lone surrogate is skipped.
        foreach (var header in new[] { "{\"alg\":\"EdDSA\",\"alg\":\"EdDSA\",\"kid\":\"k1\"}", "{\"alg\":\"EdDSA\",\"kid\":\"k1\",\"typ\":\"\\ud800\"}" })
        {
            var card = JsonNode.Parse(signed)!.AsObject();
            card["signatures"]![0]!["protected"] = Base64Url.Encode(header);
            Assert.Equal("invalid_signature", (await Assert.ThrowsAsync<TouchqueAgentCardException>(() => AgentCard.VerifyAsync(card.ToJsonString(), options))).Error);
        }
    }

    /// <summary>
    /// A webhook body that repeats a member name (Touchque never sends one) is the webhook's usual signature
    /// error, not an ArgumentException from the first read of the payload; a lone surrogate in a value is
    /// what JSON.stringify writes for one, and a signed delivery with it still verifies.
    /// </summary>
    [Fact]
    public async Task WebhooksAnswerTheirSignatureError()
    {
        const string secret = "whsec_test";
        var webhook = new TouchqueClient(new TouchqueOptions { ApiKey = "tq_x", ApiSecret = secret }).Webhook;
        static string Sign(string body)
        {
            using var h = new System.Security.Cryptography.HMACSHA256(System.Text.Encoding.UTF8.GetBytes(secret));
            return Convert.ToHexString(h.ComputeHash(System.Text.Encoding.UTF8.GetBytes(WebhookResource.Canonicalize(body)))).ToLowerInvariant();
        }
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture);
        var body = "{\"event\":\"APPROVAL_REVOKED\",\"requestId\":\"r1\",\"timestamp\":\"" + now + "\",\"jti\":\"j1\"}";
        var signature = Sign(body);
        Assert.Equal("r1", (string?)webhook.Verify(body, signature)["requestId"]);

        foreach (var repeated in new[]
        {
            // Touchque's signature still matches: the canonical form keeps the last of the two.
            body.Replace("\"requestId\":\"r1\"", "\"requestId\":\"r1\",\"requestId\":\"r1\""),
            body.Replace("\"jti\":\"j1\"", "\"jti\":\"j1\",\"j\\u0074i\":\"j1\""),
            "{\"signature\":\"" + signature + "\",\"signature\":\"" + signature + "\"}",
            "{\"a\":1,\"a\":2}", "{\"a\":[{\"b\":1,\"b\":2}]}", "{\"\\ud800\":1}",
        })
        {
            foreach (var header in new[] { signature, null })
            {
                Assert.Equal("Touchque: webhook rejected: invalid JSON payload", Assert.Throws<TouchqueWebhookSignatureException>(() => webhook.Verify(repeated, header)).Message);
                await Assert.ThrowsAsync<TouchqueWebhookSignatureException>(() => webhook.VerifyAsync(repeated, header, 300, new MemoryReplayCache()));
            }
        }
        // A lone surrogate in the body's signature: not a signature (it threw InvalidOperationException on its read).
        Assert.Equal("Touchque: webhook rejected: invalid signature", Assert.Throws<TouchqueWebhookSignatureException>(() => webhook.Verify("{\"signature\":\"\\ud800\"}")).Message);

        // A lone surrogate in another value, as JSON.stringify escapes it: verified as before.
        var odd = "{\"event\":\"DEVICE_LINKED\",\"externalUsername\":\"ada\\ud83d\",\"timestamp\":\"" + now + "\",\"jti\":\"j2\"}";
        Assert.Equal("j2", (string?)(await webhook.VerifyAsync(odd, Sign(odd), 300, new MemoryReplayCache()))["jti"]);
    }
}
