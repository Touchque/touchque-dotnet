using System.Text.Json.Nodes;
using Xunit;

namespace Touchque.Tests;

/// <summary>Silent sign-ins, Never Locked Out, help desk, Mobile SDK and the Management API against the fake API.</summary>
[Collection("fake-api")]
public class ResourceTests : IAsyncLifetime
{
    private const string User = "jane@acme.com";
    private static readonly string[] SilentCodes = { "known_browser", "recent_approval", "same_phone", "familiar_network", "no_risk_signal" };
    private readonly FakeApi _api;
    private readonly string _proof;
    private readonly string _thumbprint;

    public ResourceTests(FakeApi api)
    {
        _api = api;
        var vectors = Paths.Fixture("silent-sign-in-vectors.json")["browserProof"]!;
        _proof = (string)((JsonArray)vectors["cases"]!).First(c => (string)c!["name"]! == "validHeaderEncoding")!["proof"]!;
        _thumbprint = (string)vectors["thumbprint"]!["expected"]!;
    }

    public async Task InitializeAsync()
    {
        await _api.ResetAsync();
        await _api.LinkAsync(User);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<List<string>> PathsAsync() => (await _api.CallsAsync()).Select(c => (string)c!["path"]!).ToList();

    private async Task<List<JsonNode>> LoginRequestsAsync() =>
        (await _api.CallsAsync()).Where(c => (string)c!["path"]! == "/login/request").Select(c => c!["body"]!).ToList();

    private GuardInput G(string? proof, SilentSignInOptions? silent, string action = "LOGIN", string? token = null) => new()
    {
        User = User, Action = action, Ip = "203.0.113.7", UserAgent = "UA", Token = token, BrowserProof = proof, SilentSignIn = silent,
    };

    [Fact]
    public async Task RiskCheckAsksForANewBrowserAndSendsNothingToThePhone()
    {
        var tq = _api.Client();
        var none = await tq.Risk.CheckAsync(new RiskCheckOptions { ExternalUsername = User });
        Assert.Equal((true, "normal", "enforce", "CHK-2QX"), (none.Prompt, none.Assurance, none.SilentMode, none.CaseCode));
        Assert.Equal(new[] { "no_browser_key" }, none.Reasons.Select(r => r.Code));
        var res = await tq.Risk.CheckAsync(new RiskCheckOptions { ExternalUsername = User, Type = "LOGIN", ClientIp = "203.0.113.7", UserAgent = "UA", BrowserProof = _proof, MaxAgeSeconds = 3600 });
        Assert.Equal(new RiskReason { Code = "new_browser", Text = "This browser has not been approved on the phone for this account" }, Assert.Single(res.Reasons));
        JsonAssert.Equal(new { externalUsername = User, type = "LOGIN", clientIp = "203.0.113.7", userAgent = "UA", browserProof = _proof, maxAgeSeconds = 3600 }, await _api.LastCheckAsync());
        Assert.Equal(new[] { "/risk/check", "/risk/check" }, await PathsAsync());
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.Risk.CheckAsync(new RiskCheckOptions { ExternalUsername = User, MaxAgeSeconds = -1 }));

        await _api.OptsAsync(new { silent = true });
        var silent = await tq.Risk.CheckAsync(new RiskCheckOptions { ExternalUsername = User, BrowserProof = _proof });
        Assert.False(silent.Prompt);
        Assert.Equal(SilentCodes, silent.Reasons.Select(r => r.Code));
        Assert.True((await tq.Risk.CheckAsync(new RiskCheckOptions { ExternalUsername = User, Type = "SEND_MONEY", BrowserProof = _proof })).Prompt);
    }

    [Fact]
    public async Task AnApprovalMakesTheBrowserKnownUntilForgotten()
    {
        var tq = _api.Client();
        var first = await tq.Login.RequestAsync(new LoginRequestOptions { ExternalUsername = User, BrowserProof = _proof });
        Assert.Equal(_proof, (string)(await LoginRequestsAsync())[0]["browserProof"]!);
        Assert.Empty(await tq.Risk.BrowsersAsync(User));
        await _api.ApproveAsync(first.RequestId);
        var browser = Assert.Single(await tq.Risk.BrowsersAsync(User));
        Assert.Equal((_thumbprint, "push", (string?)null), (browser.Thumbprint, browser.LastMfaMethod, browser.LastSilentAt));
        Assert.Contains("/risk/browsers?externalUsername=jane%40acme.com", (await _api.CallsAsync()).Select(c => (string)c!["url"]!));
        Assert.Equal(0, await tq.Risk.ForgetBrowsersAsync(User, "other"));
        Assert.Equal(1, await tq.Risk.ForgetBrowsersAsync(User, _thumbprint));
        Assert.Empty(await tq.Risk.BrowsersAsync(User));
    }

    [Fact]
    public async Task AKnownBrowserWithNothingNewIsApprovedAtOnceWithNoPush()
    {
        await _api.OptsAsync(new { silent = true });
        var res = await Guard.RunAsync(_api.Client(), G(_proof, new SilentSignInOptions()));
        Assert.Equal(200, res.Status);
        var a = res.Approved!;
        Assert.Equal(("silent", User, "LOGIN", "SILENT", "silent"), (a.RequestId, a.User, a.Action, a.ConfirmedVia, a.Assurance!.Method));
        Assert.Equal(SilentCodes, a.Reasons!.Select(r => r.Code));
        Assert.Equal(new[] { "/risk/check" }, await PathsAsync());
    }

    [Fact]
    public async Task OtherwiseThePushStartsWithTheProofAndPollsNeverAskAgain()
    {
        var tq = _api.Client();
        var first = await Guard.RunAsync(tq, G(_proof, new SilentSignInOptions()));
        Assert.Equal(202, first.Status);
        Assert.Equal(new[] { "/risk/check", "/login/request" }, await PathsAsync());
        await _api.OptsAsync(new { silent = true });
        var poll = await Guard.RunAsync(tq, G(_proof, new SilentSignInOptions(), token: (string)first.Body!["token"]!));
        Assert.Equal("waiting", (string)poll.Body!["touchque"]!["state"]!);
        Assert.Single(await PathsAsync(), p => p == "/risk/check");
        await _api.ApproveAsync();
        var done = await Guard.RunAsync(tq, G(_proof, new SilentSignInOptions(), token: (string)first.Body!["token"]!));
        Assert.Equal(("DEVICE", "push"), (done.Approved!.ConfirmedVia, done.Approved.Assurance!.Method));
        Assert.Null(done.Approved.Reasons);
    }

    [Fact]
    public async Task SilentSignInFailsClosedAndIsOffByDefault()
    {
        await _api.OptsAsync(new { silent = true });
        var tq = _api.Client();
        var critical = await Guard.RunAsync(tq, G(_proof, new SilentSignInOptions(), "SEND_MONEY"));
        Assert.Equal(("waiting", "47"), ((string)critical.Body!["touchque"]!["state"]!, (string?)critical.Body["touchque"]!["number"]));
        await _api.ResetAsync();
        await _api.LinkAsync(User);
        await _api.OptsAsync(new { silent = true });
        var off = await Guard.RunAsync(tq, G(_proof, null));
        Assert.Equal(202, off.Status);
        Assert.Equal(_proof, (string)(await LoginRequestsAsync())[0]["browserProof"]!);
        Assert.Equal(202, (await Guard.RunAsync(tq, G(new string('x', 5000), new SilentSignInOptions()))).Status);
        Assert.Null((await LoginRequestsAsync())[1]["browserProof"]);
        Assert.DoesNotContain("/risk/check", await PathsAsync());

        await Guard.RunAsync(tq, G(_proof, new SilentSignInOptions { MaxAgeSeconds = 0 }));
        Assert.Equal(0, (int)(await _api.LastCheckAsync())!["maxAgeSeconds"]!);

        // Anything but prompt: false (or an error) starts the push.
        foreach (var answer in new JsonNode?[] { new JsonObject { ["prompt"] = "false" }, new JsonObject { ["prompt"] = 0 }, new JsonObject(), null })
        {
            var http = new HttpClient(new StubHandler((req, _) => req.RequestUri!.AbsolutePath == "/risk/check"
                ? (answer is null ? StubHandler.Json(500, new { error = "boom" }) : StubHandler.Json(200, answer.DeepClone()))
                : StubHandler.Json(200, new { requestId = "r1", expiresAt = "soon" })));
            var stubbed = new TouchqueClient(new TouchqueOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, http);
            Assert.Equal(202, (await Guard.RunAsync(stubbed, G(_proof, new SilentSignInOptions()))).Status);
        }
    }

    [Fact]
    public async Task NeverLockedOut()
    {
        foreach (var u in new[] { "ada@acme.com", "bo@acme.com", "cy@acme.com" }) await _api.LinkAsync(u);
        var tq = _api.Client();
        var out1 = await tq.Recovery.SetVouchersAsync("ada@acme.com", new[] { "bo@acme.com", "zed@acme.com" });
        Assert.Equal(new[] { (true, (string?)null), (false, "no_phone") }, out1.Vouchers.Select(v => (v.Eligible, v.Reason)));
        Assert.Equal("bo@acme.com", (await tq.Recovery.VouchersAsync("ada@acme.com")).Vouchers[0].ExternalUsername);

        var e = await Assert.ThrowsAsync<TouchqueApiException>(() => tq.Recovery.StartAsync(new StartRecoveryOptions { ExternalUsername = "cy@acme.com" }));
        Assert.Equal((409, "not_enough_vouchers"), (e.Status, e.Code));

        await tq.Recovery.SetVouchersAsync("ada@acme.com", new[] { "bo@acme.com", "cy@acme.com" });
        var r = await tq.Recovery.StartAsync(new StartRecoveryOptions { ExternalUsername = "ada@acme.com", ClientIp = "203.0.113.7", DisplayName = "Ada", CoolOffMinutes = 90 });
        Assert.Equal("AWAITING_DEVICE", r.Status);
        Assert.StartsWith("touchque://recover?id=", r.BindUri);
        JsonAssert.Equal(new { externalUsername = "ada@acme.com", clientIp = "203.0.113.7", displayName = "Ada", coolOffMinutes = 90 }, (await _api.LastCallAsync())["body"]);
        await _api.RecoveryAsync("VOUCHING");
        var now = await tq.Recovery.StatusAsync(r.RecoveryId);
        Assert.Equal(new[] { "11", "12" }, now.Vouchers.Select(v => v.Code));
        Assert.True(now.IsOpen);
        Assert.Equal(r.RecoveryId, Assert.Single(await tq.Recovery.ListAsync(open: true)).RecoveryId);
        var vetoed = await tq.Recovery.VetoAsync(r.RecoveryId, "admin@acme.com");
        Assert.Equal(("VETOED", "admin@acme.com"), (vetoed.Status, vetoed.EndedBy));
        Assert.Empty(await tq.Recovery.ListAsync(open: true));
        Assert.Equal(r.RecoveryId, Assert.Single(await tq.Recovery.ListAsync("ada@acme.com")).RecoveryId);

        await _api.ResetAsync();
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.Recovery.StartAsync(new StartRecoveryOptions { ExternalUsername = "" }));
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.Recovery.StatusAsync(""));
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.Recovery.ListAsync());
        Assert.Empty(await _api.CallsAsync());
    }

    [Fact]
    public async Task HelpDesk()
    {
        await _api.LinkAsync("ayse@acme.com");
        var tq = _api.Client();
        var s = await tq.Assist.OpenAsync(new OpenAssistOptions { ExternalUsername = "ayse@acme.com", Agent = new AssistAgent { Name = "Deniz Kaya", Title = "IT help desk" }, Reason = "Ticket 4411" });
        Assert.Equal(("OPEN", true, true), (s.Status, s.Notified, s.Phone));
        var check = await tq.Assist.VerifyAsync(s.Id, "reset_2fa", "reset your two-step verification");
        Assert.Matches("^[0-9]{2}$", check.ChallengeCode);
        await _api.PostAsync("/__test/assist", new { requestId = check.RequestId, action = "approve" });
        Assert.True((await tq.Assist.GetAsync(s.Id)).CheckPassed(check.RequestId));
        Assert.Equal(428, (await Assert.ThrowsAsync<TouchqueApiException>(() => tq.Assist.SpendAsync(s.Id, check.RequestId, "reset_password"))).Status);
        Assert.False((await tq.Assist.SpendAsync(s.Id, check.RequestId, "reset_2fa")).CheckPassed(check.RequestId));
        Assert.Equal(s.Id, (await tq.Assist.ListAsync("ayse@acme.com"))[0].Id);

        var notMe = await tq.Assist.VerifyAsync(s.Id, "activation_link");
        await _api.PostAsync("/__test/assist", new { requestId = notMe.RequestId, action = "not_me" });
        Assert.True((await tq.Assist.GetAsync(s.Id)).Frozen);
        var unlock = await tq.Assist.VerifyAsync(s.Id, "unlock");
        await _api.PostAsync("/__test/assist", new { requestId = unlock.RequestId, action = "approve" });
        var unfrozen = await tq.Assist.UnfreezeAsync(s.Id, unlock.RequestId);
        Assert.Equal((true, false), (unfrozen.Unfrozen, unfrozen.Session!.Frozen));
        Assert.Equal("ENDED", (await tq.Assist.EndAsync(s.Id)).Status);
        Assert.Equal("assist_not_open", (await Assert.ThrowsAsync<TouchqueApiException>(() => tq.Assist.VerifyAsync(s.Id, "unlock"))).Code);

        await tq.Auth.GenerateSecretAsync("can@acme.com");
        var noPhone = await tq.Assist.OpenAsync(new OpenAssistOptions { ExternalUsername = "can@acme.com", Agent = new AssistAgent { Name = "Deniz Kaya" }, Notify = false });
        Assert.False(noPhone.Phone);
        var e = await Assert.ThrowsAsync<TouchqueApiException>(() => tq.Assist.VerifyAsync(noPhone.Id, "new_phone"));
        Assert.Equal(("no_phone", "never_locked_out"), (e.Code, e.Route));
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.Assist.ListAsync());
    }

    [Fact]
    public async Task MobileSdkServerSide()
    {
        var tq = _api.Client();
        var first = await tq.Mobile.CreateEnrollmentAsync("ada@shop.example");
        Assert.Matches("^tqe_[A-Za-z0-9_-]{43}$", first.EnrollmentToken);
        var device = await _api.PostAsync("/__test/mobile-enroll", new { enrollmentToken = first.EnrollmentToken, platform = "android" });
        Assert.Equal("already_enrolled", (await Assert.ThrowsAsync<TouchqueApiException>(() => tq.Mobile.CreateEnrollmentAsync("ada@shop.example"))).Code);
        var second = await tq.Mobile.CreateEnrollmentAsync("ada@shop.example", replace: true, ttlSeconds: 300);
        Assert.Equal((string)device!["deviceId"]!, second.ReplacesDeviceId);
        await _api.PostAsync("/__test/mobile-enroll", new { enrollmentToken = second.EnrollmentToken });
        var active = (await tq.Mobile.ListDevicesAsync("ada@shop.example")).Devices;
        Assert.Equal("ios", Assert.Single(active).Platform);
        Assert.Equal("replaced", (await tq.Mobile.GetDeviceAsync((string)device["deviceId"]!)).RevokedReason);
        var push = await tq.Mobile.TestPushAsync(active[0].DeviceId);
        Assert.Equal(("webhook", true), (push.Via, push.Ok));
        JsonAssert.Equal(new { removed = true, wasLinked = true }, await tq.Mobile.RemoveDeviceAsync(active[0].DeviceId));

        Assert.Equal("optional", (await tq.Mobile.SettingsAsync()).Attestation);
        var s = await tq.Mobile.UpdateSettingsAsync(new { iosAppIds = new[] { "ABCDE12345.com.shop.app" }, attestation = "required" });
        Assert.Equal(new[] { "ABCDE12345.com.shop.app" }, s.IosAppIds);
        Assert.Equal(600, s.EnrollTtlSeconds);
        s = await tq.Mobile.UpdateSettingsAsync(new JsonObject
        {
            ["apns"] = new JsonObject { ["keyId"] = "ABC123DEFG", ["teamId"] = "TEAM123456", ["topic"] = "com.shop.app", ["key"] = "-----BEGIN PRIVATE KEY-----" },
            ["fcm"] = new JsonObject { ["serviceAccount"] = new JsonObject { ["project_id"] = "shop", ["client_email"] = "push@shop.iam.gserviceaccount.com", ["private_key"] = "x" } },
        });
        Assert.Equal(("touchque", "shop", "push@shop.iam.gserviceaccount.com"), (s.Push!.Ios, s.Push.Fcm!.ProjectId, s.Push.Fcm.ClientEmail));
        Assert.Equal("webhook", (await tq.Mobile.UpdateSettingsAsync(new JsonObject { ["apns"] = null })).Push!.Ios);
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.Mobile.UpdateSettingsAsync(new { nope = 1 }));
    }

    [Fact]
    public void MobilePushWebhookBecomesTheApnsPayloadAndFcmData()
    {
        var e = JsonNode.Parse("""
            {"event":"MOBILE_PUSH","externalUsername":"ada@shop.example","deviceId":"d1","platform":"ios","pushToken":"apns-token","kind":"approval","requestId":"r1",
             "expiresAt":"2026-10-26T10:00:30.000Z","alert":{"title":"Change delivery address","body":"Demo Shop is waiting for your approval."},
             "data":{"touchque":"{\"v\":1,\"k\":\"approval\",\"did\":\"d1\",\"rid\":\"r1\"}"}}
            """)!.AsObject();
        var push = MobileResource.PushFromWebhook(e)!;
        JsonAssert.Equal(new JsonObject
        {
            ["aps"] = new JsonObject { ["sound"] = "default", ["interruption-level"] = "time-sensitive", ["alert"] = e["alert"]!.DeepClone() },
            ["touchque"] = (string)e["data"]!["touchque"]!,
        }, push.Apns);
        Assert.Equal((string)e["data"]!["touchque"]!, push.FcmData["touchque"]);
        Assert.Null(MobileResource.PushFromWebhook(new JsonObject { ["event"] = "DEVICE_LINKED" }));
        Assert.True(push.IsExpired(DateTimeOffset.Parse("2026-10-26T10:01:00Z")));
        Assert.False(push.IsExpired(DateTimeOffset.Parse("2026-10-26T10:00:00Z")));
    }

    [Fact]
    public async Task ManagementApiCalls()
    {
        var tq = _api.Client();
        await _api.ResetAsync();
        await tq.Identity.Users.ListAsync(new { q = "ayse", limit = 10 });
        await tq.Identity.Users.CreateAsync(new { email = "a@x.com", passwordHash = "$2b$10$abc" });
        await tq.Identity.Users.UpdateAsync("usr_1", new { appMetadata = new { plan = (string?)null } });
        await tq.Identity.Users.BlockAsync("usr_1", "fraud");
        await tq.Identity.Users.DeleteAsync("usr_1");
        await tq.Identity.Users.ResetMfaAsync("usr_1");
        await tq.Identity.Users.PasswordResetAsync("usr_1", false);
        await tq.Identity.Users.AddRolesAsync("usr_1", new[] { "rol_1" }, "org_1");
        await tq.Identity.Users.RemoveRoleAsync("usr_1", "rol_1", "org_1");
        await tq.Identity.Imports.StartAsync(new { users = new[] { new { email = "b@x.com" } }, upsert = true });
        await tq.Identity.Organizations.InviteAsync("org_1", new { email = "c@x.com", clientId = "cli", roleIds = new[] { "rol_1" } });
        Assert.Empty(await tq.Identity.Roles.ListAsync());
        await tq.Identity.UpdateTenantAsync(new { slug = "acme", displayName = "Acme" });
        Assert.Equal("done", (string?)(await tq.Identity.Exports.WaitAsync("job_1", TimeSpan.FromMilliseconds(1)))["status"]);
        await tq.Identity.SetDeliveryAsync("email", new { provider = "postmark", from = "login@acme.test", serverToken = "pm" });
        await tq.Identity.TestDeliveryAsync("sms", "+905321234567");
        await tq.Identity.SetAttackProtectionAsync(new { bot = new { provider = "turnstile", siteKey = "k", secret = "s", mode = "risky" } });
        await tq.Identity.Clients.RotateSecretAsync("cli_1");
        await tq.Identity.Users.EndSessionAsync("usr_1", "ses_1");
        Assert.Contains("ok", await tq.Identity.Exports.FileAsync("job_1"));
        await tq.Identity.SetApproverAppNameAsync("Acme Pay");
        await tq.Identity.SetCustomDomainOnlyAsync(true);
        await tq.Identity.CheckDomainCertificateAsync("dom_1");

        var calls = (await _api.CallsAsync()).Where(c => ((string)c!["path"]!).StartsWith("/identity", StringComparison.Ordinal)).ToList();
        Assert.Equal(new[]
        {
            "GET /identity/users?limit=10&q=ayse", "POST /identity/users", "PATCH /identity/users/usr_1", "POST /identity/users/usr_1/block",
            "DELETE /identity/users/usr_1", "DELETE /identity/users/usr_1/mfa", "POST /identity/users/usr_1/password-reset", "POST /identity/users/usr_1/roles",
            "DELETE /identity/users/usr_1/roles/rol_1?organizationId=org_1", "POST /identity/users-imports", "POST /identity/organizations/org_1/invitations",
            "GET /identity/roles", "PUT /identity/tenant", "GET /identity/users-exports/job_1", "PUT /identity/delivery/email", "POST /identity/delivery/sms/test",
            "PUT /identity/attack-protection", "POST /identity/clients/cli_1/rotate-secret", "DELETE /identity/users/usr_1/sessions/ses_1",
            "GET /identity/users-exports/job_1/file", "PUT /identity/tenant", "PUT /identity/tenant",
            "POST /identity/custom-domains/dom_1/check-certificate",
        }, calls.Select(c => (string)c!["method"]! + " " + (string)c["url"]!));
        JsonAssert.Equal(new { branding = new { approverAppName = "Acme Pay" } }, calls[20]!["body"]);
        JsonAssert.Equal(new { customDomainOnly = true }, calls[21]!["body"]);
        JsonAssert.Equal(new { email = "a@x.com", passwordHash = "$2b$10$abc" }, calls[1]!["body"]);
        JsonAssert.Equal(JsonNode.Parse("""{"appMetadata":{"plan":null}}"""), calls[2]!["body"]);
        JsonAssert.Equal(new { roleIds = new[] { "rol_1" }, organizationId = "org_1" }, calls[7]!["body"]);
    }

    [Fact]
    public async Task PasskeyBackendCalls()
    {
        var tq = _api.Client();
        await _api.ResetAsync();
        await _api.LinkAsync("pk@acme.com");
        var e = await Assert.ThrowsAsync<TouchqueApiException>(() => tq.WebAuthn.RegisterOptionsAsync("pk@acme.com", true));
        Assert.Equal((403, "enrollment_approval_required"), (e.Status, e.Code));
        Assert.Empty(await tq.WebAuthn.ListCredentialsAsync("pk@acme.com"));
        await tq.WebAuthn.DeleteCredentialAsync("cred 1", "pk@acme.com");
        Assert.Equal("/webauthn/credentials/cred%201?externalUsername=pk%40acme.com", (string)(await _api.LastCallAsync())["url"]!);
        var availability = await tq.WebAuthn.PrimaryAvailabilityAsync();
        Assert.True(availability.Enabled);
        Assert.Equal("preferred", availability.UserVerification);
    }
}
