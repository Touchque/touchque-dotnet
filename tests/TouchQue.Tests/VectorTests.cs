using System.Text;
using System.Text.Json.Nodes;
using TouchQue.Internal;
using Xunit;

namespace TouchQue.Tests;

/// <summary>
/// The cross-language fixtures (fixtures/): every SDK signs, canonicalizes,
/// verifies and matches exactly like the server and the other SDKs.
/// </summary>
public class VectorTests
{
    [Fact]
    public void SignatureVectors()
    {
        var fx = Paths.Fixture("signature-vectors.json");
        var vectors = (JsonArray)fx["vectors"]!;
        Assert.NotEmpty(vectors);
        foreach (var v in vectors)
        {
            var sig = TouchQueHttp.Sign((string)fx["secret"]!, (string)v!["method"]!, (string)v["signed_path"]!, (string)v["body"]!, (string)v["timestamp"]!, (string)v["nonce"]!);
            Assert.Equal((string)v["expected_signature"]!, sig);
        }
    }

    [Fact]
    public void WebhookVectors()
    {
        var fx = Paths.Fixture("webhook-vectors.json");
        var webhook = new TouchQueClient(new TouchQueOptions { ApiKey = "tq_x", ApiSecret = (string)fx["secret"]! }).Webhook;
        foreach (var v in (JsonArray)fx["vectors"]!)
        {
            var body = (string)v!["delivered_body"]!;
            Assert.Equal((string)v["expected_canonical"]!, WebhookResource.Canonicalize(body));
            // The fixtures carry a fixed past timestamp: no freshness check.
            var payload = webhook.Verify(body, null, 0);
            Assert.Equal((string?)v["payload"]!["requestId"], (string?)payload["requestId"]);
        }
    }

    [Fact]
    public async Task WebhookSignatureTimestampAndReplay()
    {
        const string secret = "whsec_test";
        var webhook = new TouchQueClient(new TouchQueOptions { ApiKey = "tq_x", ApiSecret = secret }).Webhook;
        string Sign(JsonObject payload)
        {
            using var h = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var sig = Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(WebhookResource.Canonicalize(payload.ToJsonString())))).ToLowerInvariant();
            payload["signature"] = sig;
            return payload.ToJsonString();
        }
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'");
        var fresh = Sign(new JsonObject { ["status"] = "SUCCESS", ["requestId"] = "r1", ["timestamp"] = now, ["jti"] = "j1", ["note"] = "Zoë Ångström / €" });
        var cache = new MemoryReplayCache();
        Assert.Equal("r1", (string?)(await webhook.VerifyAsync(fresh, null, 300, cache))["requestId"]);
        var replay = await Assert.ThrowsAsync<TouchQueWebhookReplayException>(() => webhook.VerifyAsync(fresh, null, 300, cache));
        Assert.Equal("j1", replay.Jti);

        var old = Sign(new JsonObject { ["status"] = "SUCCESS", ["timestamp"] = "2020-01-01T00:00:00.000Z" });
        Assert.Throws<TouchQueWebhookSignatureException>(() => webhook.Verify(old));
        var tampered = fresh.Replace("\"r1\"", "\"r2\"");
        var e = Assert.Throws<TouchQueWebhookSignatureException>(() => webhook.Verify(tampered));
        Assert.DoesNotContain("expected", e.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Throws<TouchQueWebhookSignatureException>(() => webhook.Verify("not json"));
        Assert.Throws<TouchQueWebhookSignatureException>(() => webhook.Verify(Sign(new JsonObject { ["status"] = "SUCCESS" })));
    }

    [Fact]
    public async Task SilentSignInRiskCheckVectors()
    {
        var fx = Paths.Fixture("silent-sign-in-vectors.json");
        foreach (var c in (JsonArray)fx["riskCheck"]!["cases"]!)
        {
            var response = c!["response"]!;
            var expected = c["expected"]!;
            var http = new HttpClient(new StubHandler((_, _) => StubHandler.Json(200, response.DeepClone())));
            var tq = new TouchQueClient(new TouchQueOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, http);
            foreach (var res in new[] { RiskResource.ParseCheck(response), await tq.Risk.CheckAsync(new RiskCheckOptions { ExternalUsername = "jane@acme.com" }) })
            {
                Assert.Equal((bool)expected["prompt"]!, res.Prompt);
                Assert.Equal(((JsonArray)expected["reasonCodes"]!).Select(x => (string)x!), res.Reasons.Select(r => r.Code));
                Assert.Equal((string)expected["assurance"]!, res.Assurance);
            }
        }
    }

    [Fact]
    public void ApprovalProofVectors()
    {
        var fx = Paths.Fixture("approval-proof-vectors.json");
        foreach (var c in (JsonArray)fx["digest_cases"]!)
        {
            var details = c!["details"] is JsonArray ? Details.FromJson(c["details"]) : Details.FromJson(c["details_object"]);
            Assert.Equal((string)c["digest"]!, Details.Digest(details));
        }
        foreach (var c in (JsonArray)fx["cases"]!)
        {
            var o = c!["options"]!;
            var options = new ApprovalProofOptions
            {
                RequestId = (string)o["requestId"]!,
                Type = (string)o["type"]!,
                ChallengeCode = (string?)o["challengeCode"],
                Details = o["details"] is null ? null : Details.FromJson(o["details"]),
                ExpectedPublicKey = (string?)o["expectedPublicKey"],
                AllowUnpinnedKey = (bool?)o["allowUnpinnedKey"] ?? false,
            };
            Assert.True((bool)c["expected"]! == ApprovalProof.Verify(c["proof"] as JsonObject, options), (string?)c["name"]);
        }
        Assert.False(ApprovalProof.Verify(new JsonObject { ["version"] = "v2", ["algorithm"] = "ECDSA-P256-SHA256", ["publicKey"] = "!!", ["message"] = "x", ["signature"] = "%%" },
            new ApprovalProofOptions { RequestId = "r", Type = "LOGIN", AllowUnpinnedKey = true }));
    }

    [Fact]
    public void AgentThumbprintAthApprovalTokenAndMatchingVectors()
    {
        var fx = Paths.Fixture("agent-vectors.json");
        foreach (var v in (JsonArray)fx["thumbprints"]!) Assert.Equal((string)v!["thumbprint"]!, AgentKeys.Thumbprint((JsonObject)v["jwk"]!));
        foreach (var v in (JsonArray)fx["ath"]!) Assert.Equal((string)v!["ath"]!, AgentKeys.AccessTokenHash((string)v["accessToken"]!));

        var at = fx["approvalToken"]!;
        var jwks = (JsonObject)at["jwks"]!;
        var verifyAt = DateTimeOffset.FromUnixTimeSeconds((long)at["verifyAt"]!);
        var claims = ApprovalToken.VerifyWith((string)at["token"]!, jwks, (string)at["audience"]!, new ApprovalExpectation
        {
            User = "ayse@example.com", Type = "PAY_INVOICE",
            AuthorizationDetails = new { instructedAmount = new { currency = "TRY", amount = "500" }, creditorAccount = new { iban = "TR33 0006 1005 1978 6457 8413 26" } },
        }, verifyAt);
        JsonAssert.Equal(at["claims"], claims);
        var own = (string)at["audience"]!;
        Assert.Throws<TouchQueApprovalMismatchException>(() => ApprovalToken.VerifyWith((string)at["tampered"]!, jwks, own, null, verifyAt));
        Assert.Throws<TouchQueApprovalMismatchException>(() => ApprovalToken.VerifyWith((string)at["wrongType"]!, jwks, own, null, verifyAt));
        Assert.Throws<TouchQueApprovalMismatchException>(() => ApprovalToken.VerifyWith((string)at["token"]!, jwks, own, null, verifyAt.AddHours(1)));
        Assert.Throws<TouchQueApprovalMismatchException>(() => ApprovalToken.VerifyWith((string)at["token"]!, jwks, own, new ApprovalExpectation { User = "mallory@example.com" }, verifyAt));
        // The audience is required, and a token without aud is refused.
        Assert.Contains("another workspace", Assert.Throws<TouchQueApprovalMismatchException>(() => ApprovalToken.VerifyWith((string)at["token"]!, jwks, "touchque:workspace:other", null, verifyAt)).Message);
        Assert.Contains("audience is required", Assert.Throws<TouchQueApprovalMismatchException>(() => ApprovalToken.VerifyWith((string)at["token"]!, jwks, null, null, verifyAt)).Message);
        Assert.Contains("audience is required", Assert.Throws<TouchQueApprovalMismatchException>(() => ApprovalToken.VerifyWith((string)at["token"]!, jwks, "", null, verifyAt)).Message);
        var noAud = at["noAudience"]!;
        Assert.Contains("names no workspace", Assert.Throws<TouchQueApprovalMismatchException>(() => ApprovalToken.VerifyWith((string)noAud["token"]!, (JsonObject)noAud["jwks"]!, own, null, verifyAt)).Message);

        var details = at["claims"]!["authorization_details"];
        foreach (var m in (JsonArray)fx["matching"]!)
        {
            Assert.True((bool)m!["matches"]! == ApprovalToken.Matches(details, m["expect"]!.DeepClone()), (string?)m["name"]);
        }
    }

    [Fact]
    public void GuardTokensAreBoundAndExpire()
    {
        var claims = new JsonObject { ["u"] = "a", ["a"] = "LOGIN", ["d"] = "", ["r"] = null, ["exp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 60_000 };
        var token = Steps.SignGuardToken("secret", claims);
        Assert.Equal("a", (string?)Steps.VerifyGuardToken("secret", token)!["u"]);
        Assert.Null(Steps.VerifyGuardToken("other", token));
        Assert.Null(Steps.VerifyGuardToken("secret", token[..^2] + "xx"));
        claims["exp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 1;
        Assert.Null(Steps.VerifyGuardToken("secret", Steps.SignGuardToken("secret", claims)));
    }

    [Fact]
    public void ConfigRefusesSwappedKeysAndPlainHttp()
    {
        Assert.Throws<TouchQueConfigException>(() => new TouchQueClient(new TouchQueOptions { ApiKey = "secret", ApiSecret = "tq_key" }));
        Assert.Throws<TouchQueConfigException>(() => new TouchQueClient(new TouchQueOptions { ApiKey = "tq_k", ApiSecret = "s", BaseUrl = "http://api.example.com" }));
        Assert.NotNull(new TouchQueClient(new TouchQueOptions { ApiKey = "tq_k", ApiSecret = "s", BaseUrl = "http://127.0.0.1:9" }));
    }

    [Fact]
    public async Task ErrorsCarryCodeCaseCodeAndRetryAfter()
    {
        var http = new HttpClient(new StubHandler((_, _) =>
        {
            var res = StubHandler.Json(429, new { code = "rate_limited", error = "too_many_login_requests", caseCode = "REF-USE" });
            res.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(60));
            return res;
        }));
        var tq = new TouchQueClient(new TouchQueOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, http);
        var e = await Assert.ThrowsAsync<TouchQueApiException>(() => tq.Login.RequestAsync("a@b.com"));
        Assert.Equal((429, "rate_limited", "REF-USE", 60), (e.Status, e.Code, e.CaseCode, e.RetryAfter));

        var down = new HttpClient(new StubHandler((_, _) => throw new HttpRequestException("connection refused")));
        var tq2 = new TouchQueClient(new TouchQueOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, down);
        await Assert.ThrowsAsync<TouchQueNetworkException>(() => tq2.Login.StatusAsync("r1"));

        var redirect = new HttpClient(new StubHandler((_, _) => new HttpResponseMessage(System.Net.HttpStatusCode.Found) { Headers = { Location = new Uri("https://evil.example/") } }));
        var tq3 = new TouchQueClient(new TouchQueOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, redirect);
        Assert.Equal(302, (await Assert.ThrowsAsync<TouchQueApiException>(() => tq3.Login.StatusAsync("r1"))).Status);
    }
}
