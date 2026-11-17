using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace Touchque.Tests;

/// <summary>
/// Touchque Login's passkey domain (PUT /identity/tenant { passkeyDomain }), custom domains
/// (/identity/custom-domains) and the user store (/identity/user-store): what goes out against the fake API,
/// what comes back and how refusals map (in-process answers shaped like the API's), and the user store's own
/// requests, checked like webhooks.
/// </summary>
[Collection("fake-api")]
public class UserStoreAndPasskeyDomainTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public UserStoreAndPasskeyDomainTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => _api.OptsAsync(new { featureRefused = (string?)null });

    [Fact]
    public async Task UserStoreSendsOnlyTheArgumentsGiven()
    {
        var tq = _api.Client();
        // The endpoint travels in the JSON body as it is: a query and non-ASCII characters are not URL-encoded.
        const string url = "https://api.acme.test/touchque/user-store?region=eu&v=2";
        const string other = "https://api.acme.test/café/ping";
        await tq.Identity.SetUserStoreAsync(url);
        await tq.Identity.SetUserStoreAsync(enabled: false);
        await tq.Identity.SetUserStoreAsync();
        await tq.Identity.TestUserStoreAsync(other);
        await tq.Identity.TestUserStoreAsync();
        await tq.Identity.TestUserStoreAsync("");   // like null: the endpoint set is pinged
        var calls = (await _api.CallsAsync()).Select(c => c!.AsObject()).ToList();
        Assert.Equal(new[] { "PUT /identity/user-store", "PUT /identity/user-store", "PUT /identity/user-store", "POST /identity/user-store/test", "POST /identity/user-store/test", "POST /identity/user-store/test" },
            calls.Select(c => (string)c["method"]! + " " + (string)c["url"]!));
        JsonAssert.Equal(new { url }, calls[0]["body"]);
        JsonAssert.Equal(new { enabled = false }, calls[1]["body"]);
        JsonAssert.Equal(new JsonObject(), calls[2]["body"]);
        JsonAssert.Equal(new { url = other }, calls[3]["body"]);
        JsonAssert.Equal(new JsonObject(), calls[4]["body"]);
        JsonAssert.Equal(new JsonObject(), calls[5]["body"]);
    }

    [Fact]
    public async Task PasskeyDomainSendsTheValueAsGiven()
    {
        var tq = _api.Client();
        await tq.Identity.SetPasskeyDomainAsync("acme.com");
        await tq.Identity.SetPasskeyDomainAsync("");     // the API reads "" as none, like null
        await tq.Identity.SetPasskeyDomainAsync(null);   // sent as null, never left out (left out changes nothing)
        var calls = (await _api.CallsAsync()).Select(c => c!.AsObject()).ToList();
        Assert.All(calls, c => Assert.Equal("PUT /identity/tenant", (string)c["method"]! + " " + (string)c["url"]!));
        JsonAssert.Equal(JsonNode.Parse("""[{"passkeyDomain":"acme.com"},{"passkeyDomain":""},{"passkeyDomain":null}]"""),
            new JsonArray(calls.Select(c => c["body"]!.DeepClone()).ToArray()));
    }

    [Fact]
    public async Task AFeatureRefusalIsTheFeatureException()
    {
        await _api.OptsAsync(new { featureRefused = "feature_read_only", feature = "ciam" });
        var e = await Assert.ThrowsAsync<TouchqueFeatureReadOnlyException>(() => _api.Client().Identity.SetUserStoreAsync("https://api.acme.test/u"));
        Assert.Equal((403, "ciam"), (e.Status, e.Feature));
    }

    [Fact]
    public async Task AnswersComeBackWhole()
    {
        var store = JsonNode.Parse("""
            {"url":"https://api.acme.test/touchque/user-store","enabled":true,"active":true,"movedIn":12,
             "lastCall":{"at":"2026-11-17T06:40:00.000Z","event":"user_store.verify_password","ok":true,"status":200,"ms":84,"error":null},
             "paused":false,"updatedAt":"2026-11-17T06:30:00.000Z","signing":"Signed like Touchque webhooks: HMAC-SHA256 with your API secret (x-signature); check it with your SDK's webhook verify."}
            """)!;
        var tenant = JsonNode.Parse("""{"slug":"acme","issuer":"https://login.acme.com","passkeyDomain":"acme.com","signInMethods":{"password":true,"passkey":true,"emailCode":false}}""")!;
        var domains = JsonNode.Parse("""
            {"domains":[{"id":"dom_1","domain":"login.acme.com","status":"verified","primary":true,"proof":"organization_domain","organizationDomain":"acme.com",
              "dns":{"at":"2026-11-17T06:35:00.000Z","expected":"acme.login.touchque.com","points":"here","cname":["acme.login.touchque.com"],"addresses":[],"cloudflareProxy":false,"caa":null,"caaBlocks":false,"problems":[]},
              "autoCheckUntil":"2026-11-19T20:00:00.000Z"}],
             "verifiedDomains":["acme.com"],"slugPasskeys":2}
            """)!;
        var seen = new List<(string Call, string? Body)>();
        var tq = Stubbed((req, body) =>
        {
            seen.Add((req.Method + " " + req.RequestUri!.PathAndQuery, body));
            return (req.Method.Method, req.RequestUri!.AbsolutePath) switch
            {
                ("GET", "/identity/user-store") => StubHandler.Json(200, store.DeepClone()),
                ("PUT", "/identity/user-store") => StubHandler.Json(201, store.DeepClone()),
                ("POST", "/identity/user-store/test") => StubHandler.Json(200, new { ok = false, error = "answered 500", ms = 12 }),
                ("DELETE", "/identity/user-store") => new HttpResponseMessage(HttpStatusCode.NoContent),
                ("PUT", "/identity/tenant") => StubHandler.Json(200, tenant.DeepClone()),
                ("GET", "/identity/custom-domains") => StubHandler.Json(200, domains.DeepClone()),
                _ => StubHandler.Json(404, new { error = "no route" }),
            };
        });

        JsonAssert.Equal(store, await tq.Identity.GetUserStoreAsync());
        JsonAssert.Equal(store, await tq.Identity.SetUserStoreAsync("https://api.acme.test/touchque/user-store", true));   // 201 the first time
        var ping = await tq.Identity.TestUserStoreAsync();   // a failed ping is an answer
        Assert.Equal((false, "answered 500", 12), ((bool)ping["ok"]!, (string?)ping["error"], (int)ping["ms"]!));
        Assert.Empty(await tq.Identity.RemoveUserStoreAsync());   // 204
        Assert.Equal("acme.com", (string?)(await tq.Identity.SetPasskeyDomainAsync("acme.com"))["passkeyDomain"]);
        // The list answer whole, typed (verifiedDomains, slugPasskeys); ListAsync keeps its domains, each with dns and autoCheckUntil.
        var overview = await tq.Identity.CustomDomains.OverviewAsync();
        JsonAssert.Equal(domains["domains"], overview.Domains);
        Assert.Equal(new[] { "acme.com" }, overview.VerifiedDomains);
        Assert.Equal(2, overview.SlugPasskeys);
        JsonAssert.Equal(domains["domains"], await tq.Identity.CustomDomains.ListAsync());

        Assert.Equal(new (string, string?)[]
        {
            ("GET /identity/user-store", null),
            ("PUT /identity/user-store", """{"url":"https://api.acme.test/touchque/user-store","enabled":true}"""),
            ("POST /identity/user-store/test", "{}"),
            ("DELETE /identity/user-store", null),
            ("PUT /identity/tenant", """{"passkeyDomain":"acme.com"}"""),
            ("GET /identity/custom-domains", null),
            ("GET /identity/custom-domains", null),
        }, seen);
    }

    /// <summary>
    /// Custom domains: OverviewAsync, and GetCustomDomainsAsync its alias, read the list
    /// answer whole; GetAsync finds a domain in the list (the API has no read by id), through the IdentityCrud type
    /// too, and answers like the API's 404 when it is not there.
    /// </summary>
    [Fact]
    public async Task CustomDomainsOverviewAndGetReadTheList()
    {
        var answer = JsonNode.Parse("""
            {"domains":[
               {"id":"dom_1","domain":"login.acme.com","status":"verified","primary":true,"proof":"organization_domain","organizationDomain":"acme.com",
                "records":[{"type":"CNAME","name":"login.acme.com","value":"acme.login.touchque.com"}],
                "dns":{"points":"here","cloudflareProxy":false,"caaBlocks":false,"problems":[]},"autoCheckUntil":"2026-11-19T20:00:00.000Z"},
               {"id":"dom 2/é","domain":"signin.acme.org","status":"pending","primary":false,"proof":"txt","organizationDomain":null,
                "dns":null,"autoCheckUntil":"2026-11-20T08:00:00.000Z"}],
             "verifiedDomains":["acme.com"],"slugPasskeys":2,"addedLater":"kept"}
            """)!.AsObject();
        var seen = new List<string>();
        var tq = Stubbed((req, _) =>
        {
            seen.Add(req.Method + " " + req.RequestUri!.PathAndQuery);
            return StubHandler.Json(200, answer.DeepClone());
        });

        foreach (var overview in new[] { await tq.Identity.CustomDomains.OverviewAsync(), await tq.Identity.GetCustomDomainsAsync() })
        {
            JsonAssert.Equal(answer["domains"], overview.Domains);
            Assert.Equal(new[] { "acme.com" }, overview.VerifiedDomains);
            Assert.Equal(2, overview.SlugPasskeys);
            Assert.Equal("kept", overview.Extra!["addedLater"].GetString());   // a field the type does not name is kept
        }
        JsonAssert.Equal(answer["domains"], await tq.Identity.CustomDomains.ListAsync());   // as before: the domains only

        var second = await tq.Identity.CustomDomains.GetAsync("dom 2/é");
        JsonAssert.Equal(answer["domains"]![1], second);
        _ = new JsonObject { ["domain"] = second };   // a node of its own, not one of the list's
        IdentityCrud crud = tq.Identity.CustomDomains;
        JsonAssert.Equal(answer["domains"]![0], await crud.GetAsync("dom_1"));
        var e = await Assert.ThrowsAsync<TouchqueApiException>(() => tq.Identity.CustomDomains.GetAsync("dom_3"));
        Assert.Equal((404, "not_found", "No custom domain with this id"), (e.Status, e.Error, e.Message));
        JsonAssert.Equal(new { error = "not_found", message = "No custom domain with this id" }, e.Body);
        Assert.Equal(Enumerable.Repeat("GET /identity/custom-domains", 6), seen);   // never a GET by id

        // Your organization's verified domains could not be read: null.
        answer["verifiedDomains"] = null;
        Assert.Null((await tq.Identity.CustomDomains.OverviewAsync()).VerifiedDomains);
    }

    /// <summary>VerifyAsync over a real round trip: POST {} to the id's own path segment, signed; GetAsync of an id the list lacks is 404 not_found.</summary>
    [Fact]
    public async Task CustomDomainVerifyGoesOutSigned()
    {
        var tq = _api.Client();
        JsonAssert.Equal(new { ok = true }, await tq.Identity.CustomDomains.VerifyAsync("dom 2/é"));   // the fake's answer, whole
        var missing = await Assert.ThrowsAsync<TouchqueApiException>(() => tq.Identity.CustomDomains.GetAsync("dom_1"));   // the fake lists none
        Assert.Equal((404, "not_found"), (missing.Status, missing.Error));
        var calls = (await _api.CallsAsync()).Select(c => c!.AsObject()).ToList();
        Assert.Equal(new[] { "POST /identity/custom-domains/dom%202%2F%C3%A9/verify", "GET /identity/custom-domains" }, calls.Select(c => (string)c["method"]! + " " + (string)c["url"]!));
        JsonAssert.Equal(new JsonObject(), calls[0]["body"]);
    }

    public static TheoryData<string, int, string, string?> Refusals => new()
    {
        // The API's answers, each to the call that gets it.
        { "set", 409, """{"error":"passwords_off","field":"enabled","message":"Moving users in checks their passwords: turn passwords on first"}""", "enabled" },
        { "set", 400, """{"error":"invalid_request","field":"url","message":"url must use https"}""", "url" },
        { "test", 400, """{"error":"invalid_request","field":"url","message":"url is required"}""", "url" },
        { "get", 404, """{"error":"not_enabled","message":"PUT /identity/tenant first"}""", null },
        // DELETE is idempotent (204 with nothing set): a 404 is Touchque Login not set up, not "already removed".
        { "remove", 404, """{"error":"not_enabled","message":"PUT /identity/tenant first"}""", null },
        { "remove", 403, """{"error":"forbidden","message":"Only workspace owners and admins can change this"}""", null },
        { "passkeyDomain", 409, """{"error":"passkeys_exist","field":"passkeyDomain","count":3,"message":"3 customer passkeys belong to the current setting and would stop working"}""", "passkeyDomain" },
        { "passkeyDomain", 409, """{"error":"not_your_domain","field":"passkeyDomain","message":"acme.com must be one of your verified custom domains, or a domain above one that your organization verified (Organization → Domains)"}""", "passkeyDomain" },
        { "passkeyDomain", 409, """{"error":"organization_unavailable","field":"passkeyDomain","message":"Your organization’s verified domains could not be read; try again"}""", "passkeyDomain" },
        { "passkeyDomain", 400, """{"error":"invalid_request","field":"passkeyDomain","message":"passkeyDomain must be a domain like example.com, or null"}""", "passkeyDomain" },
        // Before Touchque Login is set up, PUT /identity/tenant would make the tenant: it asks for its slug first.
        { "passkeyDomain", 400, """{"error":"invalid_request","field":"slug","message":"slug must be 3–63 lowercase letters, digits or hyphens"}""", "slug" },
        // The API's own 404 for a domain id it does not have: no message (the exception's is the code).
        { "verify", 404, """{"error":"not_found"}""", null },
    };

    [Theory]
    [MemberData(nameof(Refusals))]
    public async Task RefusalsAreApiExceptionsWithTheApiError(string call, int status, string answer, string? field)
    {
        var body = JsonNode.Parse(answer)!.AsObject();
        var tq = Stubbed((_, _) => StubHandler.Json(status, body.DeepClone()));
        Func<Task> run = call switch
        {
            "set" => () => tq.Identity.SetUserStoreAsync("http://api.acme.test/u", true),
            "test" => () => tq.Identity.TestUserStoreAsync(),
            "get" => () => tq.Identity.GetUserStoreAsync(),
            "remove" => () => tq.Identity.RemoveUserStoreAsync(),
            "verify" => () => tq.Identity.CustomDomains.VerifyAsync("dom_9"),
            _ => () => tq.Identity.SetPasskeyDomainAsync("acme.com"),
        };
        var e = await Assert.ThrowsAsync<TouchqueApiException>(run);   // exactly the API exception, not a feature one
        var message = (string?)body["message"] ?? (string?)body["error"];
        Assert.Equal((status, (string?)body["error"], message, field), (e.Status, e.Error, e.Message, (string?)e.Body["field"]));
        JsonAssert.Equal(body, e.Body);   // nothing dropped: count of passkeys_exist too
    }

    [Fact]
    public async Task UserStoreRequestsAreCheckedLikeWebhooks()
    {
        var tq = new TouchqueClient(new TouchqueOptions { ApiKey = "tq_x", ApiSecret = "test_secret", BaseUrl = "https://api.example" });
        var (body, signature) = UserStoreRequest.Build("test_secret", "user_store.verify_password", ("email", "\"ada@acme.com\""), ("password", UserStoreRequest.Password));
        var cache = new MemoryReplayCache();
        var e = await tq.Webhook.VerifyAsync(body, signature, replayCache: cache);
        Assert.Equal(("user_store.verify_password", "acme", "ada@acme.com", "pa\"ss wärd"), ((string?)e["event"], (string?)e["tenant"], (string?)e["email"], (string?)e["password"]));
        Assert.Equal("ada@acme.com", (string?)tq.Webhook.Verify(body)["email"]);   // the signature in the body serves too
        await Assert.ThrowsAsync<TouchqueWebhookReplayException>(() => tq.Webhook.VerifyAsync(body, signature, replayCache: cache));
        Assert.Throws<TouchqueWebhookSignatureException>(() => tq.Webhook.Verify(body.Replace("wärd", "word"), signature));
        Assert.Throws<TouchqueWebhookSignatureException>(() => tq.Webhook.Verify(UserStoreRequest.Build("another_secret", "user_store.get_user", ("email", "\"ada@acme.com\"")).Body));
        Assert.Equal("user_store.ping", (string?)tq.Webhook.Verify(UserStoreRequest.Build("test_secret", "user_store.ping").Body)["event"]);
    }

    private static TouchqueClient Stubbed(Func<HttpRequestMessage, string?, HttpResponseMessage> answer) =>
        new(new TouchqueOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, new HttpClient(new StubHandler(answer)));
}

/// <summary>
/// A request to a partner's user store as Touchque makes it:
/// the body is JSON.stringify of { event, tenant, ...fields, timestamp, jti, signature }, and the signature is
/// HMAC-SHA256 (hex) with the API secret over JSON.stringify of that payload without signature, its top-level
/// keys sorted. Field values are given as the JSON text JSON.stringify writes for them.
/// </summary>
internal static class UserStoreRequest
{
    /// <summary>The password <c>pa"ss wärd</c> as JSON.stringify writes it: only the quote escaped.</summary>
    public const string Password = "\"pa\\\"ss wärd\"";

    public static (string Body, string Signature) Build(string secret, string ev, params (string Key, string Json)[] fields)
    {
        var members = new List<(string Key, string Json)> { ("event", Quote(ev)), ("tenant", Quote("acme")) };
        members.AddRange(fields);
        members.Add(("timestamp", Quote(DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture))));
        members.Add(("jti", Quote(Guid.NewGuid().ToString())));
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var signature = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(Text(members.OrderBy(m => m.Key, StringComparer.Ordinal))))).ToLowerInvariant();
        members.Add(("signature", Quote(signature)));
        return (Text(members), signature);
    }

    private static string Text(IEnumerable<(string Key, string Json)> members) => "{" + string.Join(",", members.Select(m => Quote(m.Key) + ":" + m.Json)) + "}";

    private static string Quote(string plain) => "\"" + plain + "\"";
}
