using System.Text.Json.Nodes;
using Xunit;

namespace TouchQue.Tests;

/// <summary>
/// Against the shared fake TouchQue API: a real HTTP round trip, so request signing is
/// verified too. Same scenarios as the Node/Python/PHP/Go step-up tests.
/// </summary>
[Collection("fake-api")]
public class ContractTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public ContractTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private static GuardInput G(string user, string? token = null, bool offline = false, string? code = null, string? codeType = null, string action = "LOGIN") =>
        new() { User = user, Action = action, Token = token, Offline = offline, Code = code, CodeType = codeType };

    private static JsonNode Step(GuardResult r) => r.Body!["touchque"]!;

    private static string Token(GuardResult r) => (string)r.Body!["token"]!;

    [Fact]
    public async Task LoginRequestStatusVerifyAndReportFraud()
    {
        await _api.LinkAsync("ada@acme.com");
        var tq = _api.Client();
        var sent = await tq.Login.RequestAsync(new LoginRequestOptions
        {
            ExternalUsername = "ada@acme.com", Type = "LOGIN", ClientIp = "203.0.113.7", UserAgent = "UA", Details = new LoginDetail[] { ("Amount", "250 EUR") },
            ChallengeDigits = 3, ExpiresIn = 120, Locale = "en",
        });
        Assert.Equal("K7P-2QX", sent.CaseCode);
        JsonAssert.Equal(new
        {
            externalUsername = "ada@acme.com", type = "LOGIN", clientIp = "203.0.113.7", userAgent = "UA", challengeDigits = 3, expiresIn = 120,
            details = new[] { new { label = "Amount", value = "250 EUR" } }, locale = "en",
        }, (await _api.LastCallAsync())["body"]);
        Assert.Equal("PENDING", (await tq.Login.StatusAsync(sent.RequestId)).Status);
        await _api.ApproveAsync(sent.RequestId);
        var status = await tq.Login.StatusAsync(sent.RequestId);
        Assert.Equal(("CONFIRMED", "push"), (status.Status, status.Assurance!.Method));

        var report = await tq.Login.ReportFraudAsync(sent.RequestId, "chargeback", "card holder disputed it");
        Assert.True(report.Reported && !report.AlreadyReported);
        Assert.True((await tq.Login.ReportFraudAsync(sent.RequestId)).AlreadyReported);
        await Assert.ThrowsAsync<TouchQueConfigException>(() => tq.Login.ReportFraudAsync(""));
    }

    [Fact]
    public async Task VerifyRunsOnChallengeBeforeTheWaitAndThrowsOnRejection()
    {
        await _api.LinkAsync("bo@acme.com");
        await _api.OptsAsync(new { numberMatch = true });
        var tq = _api.Client();
        VerifyChallenge? seen = null;
        var verifying = tq.Login.VerifyAsync(new LoginRequestOptions
        {
            ExternalUsername = "bo@acme.com",
            Timeout = TimeSpan.FromSeconds(10),
            OnChallenge = async c =>
            {
                seen = c;
                await _api.ApproveAsync(c.RequestId);
            },
        });
        var result = await verifying;
        Assert.True(result.Approved);
        Assert.Equal("47", seen!.ChallengeCode);
        Assert.Equal("K7P-2QX", seen.CaseCode);
        Assert.Contains(seen.Reasons!, r => r.Code == "number_match_requested");

        var rejected = tq.Login.VerifyAsync(new LoginRequestOptions { ExternalUsername = "bo@acme.com", OnChallenge = c => _api.RejectAsync(c.RequestId) });
        await Assert.ThrowsAsync<TouchQueRejectedException>(() => rejected);

        await _api.OptsAsync(new { passkeyOnly = true });
        var passkey = await Assert.ThrowsAsync<TouchQuePasskeyRequiredException>(() => tq.Login.VerifyAsync("bo@acme.com"));
        Assert.Equal("policy", passkey.Reason);
        await _api.OptsAsync(new { passkeyOnly = false });

        var escalated = await Assert.ThrowsAsync<TouchQuePasskeyRequiredException>(() => tq.Login.VerifyAsync(new LoginRequestOptions
        {
            ExternalUsername = "bo@acme.com", OnChallenge = c => _api.EscalateAsync(c.RequestId),
        }));
        Assert.Equal("step_up", escalated.Reason);
        await Assert.ThrowsAsync<TouchQueTimeoutException>(() => tq.Login.VerifyAsync(new LoginRequestOptions { ExternalUsername = "bo@acme.com", Timeout = TimeSpan.FromMilliseconds(500) }));
    }

    [Fact]
    public async Task VerifySendsExpiresInAndClientSignals()
    {
        await _api.LinkAsync("eve@acme.com");
        var tq = _api.Client();
        JsonNode? sentBody = null;
        await tq.Login.VerifyAsync(new LoginRequestOptions
        {
            ExternalUsername = "eve@acme.com", ExpiresIn = 120, ClientSignals = "cs.v1.page", Timeout = TimeSpan.FromSeconds(10),
            OnChallenge = async c =>
            {
                sentBody = (await _api.LastCallAsync())["body"]?.DeepClone();
                await _api.ApproveAsync(c.RequestId);
            },
        });
        Assert.Equal(120, (int)sentBody!["expiresIn"]!);
        Assert.Equal("cs.v1.page", (string?)sentBody["clientSignals"]);
    }

    [Fact]
    public async Task UnlinkedUserIsAClearApiError()
    {
        var tq = _api.Client();
        var e = await Assert.ThrowsAsync<TouchQueApiException>(() => tq.Login.RequestAsync("nobody@acme.com"));
        Assert.Equal((404, "device_not_linked"), (e.Status, e.Code));
    }

    [Fact]
    public async Task WaitingStepCarriesTheTelemetryToken()
    {
        await _api.LinkAsync("tel@acme.com");
        var tq = _api.Client();
        Assert.Null((await tq.StartAsync("LOGIN", new StartOptions { User = "tel@acme.com" })).TelemetryToken);
        await _api.OptsAsync(new { telemetry = true });
        Assert.Equal("tt_test", (await tq.StartAsync("LOGIN", new StartOptions { User = "tel@acme.com" })).TelemetryToken);
    }

    [Fact]
    public async Task StartCheckCompleteFullFlow()
    {
        await _api.LinkAsync("jane@acme.com");
        var tq = _api.Client();
        var step = await tq.StartAsync("SEND_MONEY", new StartOptions { User = "jane@acme.com", Details = new LoginDetail[] { (" Amount ", "250 EUR") }, ReferenceId = "tx-9" });
        Assert.Equal(("waiting", "47"), (step.State, step.Number));
        Assert.Equal(new LoginDetail("Amount", "250 EUR"), Assert.Single(step.Details!));
        Assert.Equal("waiting", (await tq.CheckAsync(step.RequestId!)).State);
        await _api.ApproveAsync();
        Assert.Equal("approved", (await tq.CheckAsync(step.RequestId!)).State);
        var expect = new CompleteExpectations { User = "Jane@acme.com", Action = "SEND_MONEY", Details = new LoginDetail[] { ("Amount", "250 EUR") }, ReferenceId = "tx-9" };
        var approval = await tq.CompleteAsync(step.RequestId!, expect);
        Assert.Equal(("push", false), (approval.Assurance!.Method, approval.Assurance.PhishingResistant));
        var again = await Assert.ThrowsAsync<TouchQueApiException>(() => tq.CompleteAsync(step.RequestId!, expect));
        Assert.Equal("already_used", again.Code);
    }

    [Fact]
    public async Task CompleteRefusesADifferentAmountAndUnknownActionsAreConfigErrors()
    {
        await _api.LinkAsync("jane2@acme.com");
        var tq = _api.Client();
        var step = await tq.StartAsync("SEND_MONEY", new StartOptions { User = "jane2@acme.com", Details = new LoginDetail[] { ("Amount", "250 EUR") } });
        await _api.ApproveAsync(step.RequestId);
        await Assert.ThrowsAsync<TouchQueApprovalMismatchException>(() => tq.CompleteAsync(step.RequestId!, new CompleteExpectations
        {
            User = "jane2@acme.com", Action = "SEND_MONEY", Details = new LoginDetail[] { ("Amount", "9999 EUR") },
        }));
        var e = await Assert.ThrowsAsync<TouchQueConfigException>(() => tq.StartAsync("NOT_DEFINED", new StartOptions { User = "jane2@acme.com" }));
        Assert.Contains("NOT_DEFINED", e.Message);
    }

    [Fact]
    public async Task AnEmptyReferenceIdIsNoReference()
    {
        await _api.LinkAsync("jane3@acme.com");
        var tq = _api.Client();
        var step = await tq.StartAsync("SEND_MONEY", new StartOptions { User = "jane3@acme.com", ReferenceId = "" });
        await _api.ApproveAsync(step.RequestId);
        Assert.Equal("SEND_MONEY", (await tq.CompleteAsync(step.RequestId!, new CompleteExpectations { User = "jane3@acme.com", Action = "SEND_MONEY", ReferenceId = "" })).Action);

        var first = await Guard.RunAsync(tq, G("jane3@acme.com", action: "SEND_MONEY") with { ReferenceId = "" });
        await _api.ApproveAsync();
        var done = await Guard.RunAsync(tq, G("jane3@acme.com", Token(first), action: "SEND_MONEY") with { ReferenceId = "" });
        Assert.Equal(200, done.Status);
    }

    [Fact]
    public async Task GuardAnswersAMismatchedApprovalWith503()
    {
        var http = new HttpClient(new StubHandler((req, _) => req.RequestUri!.AbsolutePath switch
        {
            "/login/request" => StubHandler.Json(200, new { requestId = "r1", expiresAt = "soon" }),
            "/login/status/r1" => StubHandler.Json(200, new { status = "CONFIRMED" }),
            _ => StubHandler.Json(200, new { consumed = true, requestId = "r1", externalUsername = "jane@acme.com", type = "PAY", referenceId = "another-tx" }),
        }));
        var tq = new TouchQueClient(new TouchQueOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, http);
        var first = await Guard.RunAsync(tq, G("jane@acme.com", action: "PAY") with { ReferenceId = "tx-1" });
        var done = await Guard.RunAsync(tq, G("jane@acme.com", Token(first), action: "PAY") with { ReferenceId = "tx-1" });
        Assert.Equal((503, null), (done.Status, done.Approved));
        Assert.Equal("unavailable", (string)Step(done)["reason"]!);
    }

    private sealed class ListLogger : Microsoft.Extensions.Logging.ILogger
    {
        public List<(Microsoft.Extensions.Logging.LogLevel Level, string Message)> Lines { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Lines.Add((logLevel, formatter(state, exception)));
    }

    [Fact]
    public async Task GuardAndOnChallengeLogOnlyThroughTheLogger()
    {
        await _api.LinkAsync("jane4@acme.com");
        await _api.OptsAsync(new { numberMatch = true });
        var console = new StringWriter();
        var original = Console.Error;
        Console.SetError(console);
        try
        {
            Assert.Equal(500, (await Guard.RunAsync(_api.Client(), G("jane4@acme.com", action: "NOT_DEFINED"))).Status);
            Assert.Equal("", console.ToString()); // silent by default

            var logger = new ListLogger();
            var tq = new TouchQueClient(new TouchQueOptions { ApiKey = "tq_test_key", ApiSecret = "test_secret", BaseUrl = _api.BaseUrl, Logger = logger });
            Assert.Equal(500, (await Guard.RunAsync(tq, G("jane4@acme.com", action: "NOT_DEFINED"))).Status);
            await tq.Login.VerifyAsync(new LoginRequestOptions
            {
                ExternalUsername = "jane4@acme.com", Timeout = TimeSpan.FromSeconds(10),
                OnChallenge = async c => { await _api.ApproveAsync(c.RequestId); throw new InvalidOperationException("screen gone"); },
            });
            Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Error, logger.Lines[0].Level);
            Assert.Contains("NOT_DEFINED", logger.Lines[0].Message);
            Assert.Equal((Microsoft.Extensions.Logging.LogLevel.Warning, "[TouchQue] OnChallenge failed: InvalidOperationException: screen gone"), logger.Lines[1]);
            Assert.Equal("", console.ToString());
        }
        finally
        {
            Console.SetError(original);
        }
    }

    [Fact]
    public async Task ActionTypesDefine()
    {
        var tq = _api.Client();
        var t = await tq.ActionTypes.DefineAsync("EXPORT", "Export data", null, true, new SecondThought { Questions = new[] { "safe_account" }, Locale = "en" });
        Assert.True(t.Critical);
        JsonAssert.Equal(new { type = "EXPORT", name = "Export data", critical = true, secondThought = new { questions = new[] { "safe_account" }, locale = "en" } }, (await _api.LastCallAsync())["body"]);
        Assert.Contains(await tq.ActionTypes.ListAsync(), x => x.Type == "EXPORT");
    }

    [Fact]
    public async Task GuardFullFlow()
    {
        await _api.LinkAsync("guard@acme.com");
        await _api.OptsAsync(new { numberMatch = true });
        var tq = _api.Client();
        var first = await Guard.RunAsync(tq, G("guard@acme.com"));
        Assert.Equal(202, first.Status);
        Assert.Equal(("waiting", "47"), ((string)Step(first)["state"]!, (string?)Step(first)["number"]));
        var still = await Guard.RunAsync(tq, G("guard@acme.com", Token(first)));
        Assert.Equal(202, still.Status);
        Assert.True(Guard.IsStatusPoll(tq, G("guard@acme.com", Token(first))));
        await _api.ApproveAsync();
        var done = await Guard.RunAsync(tq, G("guard@acme.com", Token(first)));
        Assert.Equal(200, done.Status);
        Assert.Equal("push", done.Approved!.Assurance!.Method);
        var replay = await Guard.RunAsync(tq, G("guard@acme.com", Token(first)));
        Assert.Null(replay.Approved);
        Assert.Contains(replay.Status, new[] { 403, 408, 409 });
        // A token is bound to its user and action.
        var other = await Guard.RunAsync(tq, G("guard@acme.com", Token(first), action: "SEND_MONEY"));
        Assert.Equal("waiting", (string)Step(other)["state"]!);
        Assert.Equal(401, (await Guard.RunAsync(tq, new GuardInput { User = null, Action = "LOGIN" })).Status);
    }

    [Fact]
    public async Task GuardEnrollThenOfflineCode()
    {
        var tq = _api.Client();
        var first = await Guard.RunAsync(tq, G("new-offline@acme.com"));
        Assert.Equal("enroll", (string)Step(first)["state"]!);
        Assert.StartsWith("data:image/png;base64,", (string)Step(first)["enroll"]!["qrCodeDataUrl"]!);
        await _api.LinkAsync("new-offline@acme.com");
        var waiting = await Guard.RunAsync(tq, G("new-offline@acme.com", Token(first)));
        Assert.Equal("waiting", (string)Step(waiting)["state"]!);
        var off = await Guard.RunAsync(tq, G("new-offline@acme.com", Token(waiting), offline: true));
        Assert.Equal("offline", (string)Step(off)["state"]!);
        Assert.Equal("data:image/png;base64,OFFLINE", (string)Step(off)["offline"]!["qrDataUrl"]!);
        var wrong = await Guard.RunAsync(tq, G("new-offline@acme.com", Token(off), code: "ZZZZ999"));
        Assert.Equal(4, (int)Step(wrong)["offline"]!["attemptsLeft"]!);
        var ok = await Guard.RunAsync(tq, G("new-offline@acme.com", Token(wrong), code: "ABCD123"));
        Assert.Equal(200, ok.Status);
        Assert.Equal(("offline_code", "OFFLINE_CODE"), (ok.Approved!.Assurance!.Method, ok.Approved.ConfirmedVia));
    }

    [Fact]
    public async Task GuardPhoneRejectKillsTheOfflineQr()
    {
        await _api.LinkAsync("reject-offline@acme.com");
        var tq = _api.Client();
        var start = await Guard.RunAsync(tq, G("reject-offline@acme.com"));
        var off = await Guard.RunAsync(tq, G("reject-offline@acme.com", Token(start), offline: true));
        Assert.Equal("offline", (string)Step(off)["state"]!);
        var qr = (await _api.CallsAsync()).Last(c => (string)c!["path"]! == "/offline/challenge");
        Assert.Equal((string)Step(start)["requestId"]!, (string)qr!["body"]!["requestId"]!);
        var poll = await Guard.RunAsync(tq, G("reject-offline@acme.com", Token(off)));
        Assert.Equal((202, "offline"), (poll.Status, (string)Step(poll)["state"]!));
        Assert.Equal((string)Step(off)["offline"]!["challengeId"]!, (string)Step(poll)["offline"]!["challengeId"]!);
        await _api.RejectAsync();
        var rejected = await Guard.RunAsync(tq, G("reject-offline@acme.com", Token(poll)));
        Assert.Equal((403, "rejected"), (rejected.Status, (string)Step(rejected)["state"]!));
        var late = await Guard.RunAsync(tq, G("reject-offline@acme.com", Token(off), code: "ABCD123"));
        Assert.Equal(("rejected", "request_rejected"), ((string)Step(late)["state"]!, (string)Step(late)["reason"]!));
        var totp = await Guard.RunAsync(tq, G("reject-offline@acme.com", Token(off), code: "123456", codeType: "totp"));
        Assert.Equal("rejected", (string)Step(totp)["state"]!);
        var again = await Guard.RunAsync(tq, G("reject-offline@acme.com", Token(start), offline: true));
        Assert.Equal("rejected", (string)Step(again)["state"]!);
    }

    [Fact]
    public async Task GuardOfflineQrCarriesTheNumber()
    {
        await _api.LinkAsync("nm-offline@acme.com");
        await _api.OptsAsync(new { numberMatch = true });
        var tq = _api.Client();
        var start = await Guard.RunAsync(tq, G("nm-offline@acme.com"));
        var off = await Guard.RunAsync(tq, G("nm-offline@acme.com", Token(start), offline: true));
        Assert.Equal("47", (string)Step(off)["offline"]!["challengeCode"]!);
    }

    [Fact]
    public async Task GuardFrozenRateLimitedBlocked()
    {
        await _api.LinkAsync("blocked@acme.com");
        var tq = _api.Client();
        await _api.OptsAsync(new { frozen = true });
        var frozen = await Guard.RunAsync(tq, G("blocked@acme.com"));
        Assert.Equal((423, 900), (frozen.Status, (int)Step(frozen)["retryAfter"]!));
        Assert.Equal(900, frozen.RetryAfter);
        await _api.OptsAsync(new { frozen = false, rateLimited = true });
        Assert.Equal(429, (await Guard.RunAsync(tq, G("blocked@acme.com"))).Status);
        await _api.OptsAsync(new { rateLimited = false, blocked = "geo_policy" });
        var blocked = await Guard.RunAsync(tq, G("blocked@acme.com"));
        Assert.Equal(403, blocked.Status);
        JsonAssert.Equal(new { state = "blocked", reason = "geo_policy", caseCode = "REF-USE" }, Step(blocked));
    }

    [Fact]
    public async Task FirstWaitingStepCarriesTheMirrorCanaryPollsDoNot()
    {
        await _api.LinkAsync("canary@acme.com");
        await _api.OptsAsync(new { canary = true });
        var tq = _api.Client();
        var first = await Guard.RunAsync(tq, G("canary@acme.com"));
        Assert.EndsWith(".gif", (string)Step(first)["canary"]!["url"]!);
        var poll = await Guard.RunAsync(tq, G("canary@acme.com", Token(first)));
        Assert.Equal("waiting", (string)Step(poll)["state"]!);
        Assert.Null(Step(poll)["canary"]);
        Assert.Equal("K7P-2QX", (string?)Step(poll)["caseCode"]);
    }

    [Fact]
    public async Task PushTappedDuringACallBecomesPasskeyRequiredAlsoFromTheOfflineQr()
    {
        await _api.LinkAsync("oncall@acme.com");
        var tq = _api.Client();
        var first = await Guard.RunAsync(tq, G("oncall@acme.com"));
        var rid = (string)Step(first)["requestId"]!;
        var off = await Guard.RunAsync(tq, G("oncall@acme.com", Token(first), offline: true));
        await _api.EscalateAsync(rid);
        var poll = await Guard.RunAsync(tq, G("oncall@acme.com", Token(off)));
        Assert.Equal((202, "passkey_required", rid), (poll.Status, (string)Step(poll)["state"]!, (string)Step(poll)["requestId"]!));
        var typed = await Guard.RunAsync(tq, G("oncall@acme.com", Token(off), code: "ABCD123"));
        Assert.Equal("passkey_required", (string)Step(typed)["state"]!);
    }

    [Fact]
    public async Task ProvisionalApprovalAndTheCriticalActionLock()
    {
        await _api.LinkAsync("prov@acme.com");
        var tq = _api.Client();
        var step = await tq.StartAsync("LOGIN", new StartOptions { User = "prov@acme.com" });
        await _api.ApproveAsync(step.RequestId, provisional: true);
        var approval = await tq.CompleteAsync(step.RequestId!, new CompleteExpectations { User = "prov@acme.com", Action = "LOGIN" });
        Assert.Equal((true, false), (approval.Provisional, approval.Revoked));
        var locked = await tq.StartAsync("SEND_MONEY", new StartOptions { User = "prov@acme.com" });
        Assert.Equal(("blocked", "provisional", "REF-USE"), (locked.State, locked.Reason, locked.CaseCode));
        await _api.ReconfirmAsync(step.RequestId);
        Assert.Equal("waiting", (await tq.StartAsync("SEND_MONEY", new StartOptions { User = "prov@acme.com" })).State);
    }

    [Fact]
    public async Task AnApprovalTakenBackIsNeverUsed()
    {
        await _api.LinkAsync("revoke@acme.com");
        var tq = _api.Client();
        var first = await Guard.RunAsync(tq, G("revoke@acme.com"));
        var rid = (string)Step(first)["requestId"]!;
        await _api.ApproveAsync(rid);
        await _api.RevokeAsync(rid);
        var done = await Guard.RunAsync(tq, G("revoke@acme.com", Token(first)));
        Assert.Equal(408, done.Status);
        JsonAssert.Equal(new { state = "expired", reason = "revoked" }, Step(done));
    }

    [Fact]
    public async Task RecoveryCodeAndAuthUser()
    {
        var tq = _api.Client();
        var gen = await tq.Auth.GenerateSecretAsync("eve@acme.com");
        Assert.StartsWith("data:image/png;base64,", gen.QrCodeDataUrl);
        Assert.Equal(409, (await Assert.ThrowsAsync<TouchQueApiException>(() => tq.Auth.GenerateSecretAsync("eve@acme.com"))).Status);
        var pending = await tq.Auth.GetUserAsync("eve@acme.com");
        Assert.False(pending.Used);
        Assert.Null(pending.Device);
        await _api.LinkAsync("eve@acme.com");
        var linked = await tq.Auth.GetUserAsync("eve@acme.com");
        Assert.Equal((true, "healthy", "ios"), (linked.Used, linked.Device!.State, linked.Device.Platform));
        Assert.Equal(404, (await Assert.ThrowsAsync<TouchQueApiException>(() => tq.Auth.GetUserAsync("nobody@acme.com"))).Status);
        var sent = await tq.Login.RequestAsync("eve@acme.com");
        Assert.True((bool?)(await tq.Login.ApproveWithRecoveryCodeAsync(sent.RequestId, "r1"))["success"]);
    }

    [Fact]
    public async Task ContextAndSecurityChangesAndDestination()
    {
        var vectors = Paths.Fixture("actions-api-vectors.json")["context"]!;
        await _api.LinkAsync("ctx@example.com");
        var tq = _api.Client();
        await tq.Login.RequestAsync(new LoginRequestOptions
        {
            ExternalUsername = "ctx@example.com", Context = new Dictionary<string, object?> { ["roles"] = new[] { "admin" }, ["amount"] = 2500 },
        });
        JsonAssert.Equal(vectors["loginRequest"]!["body"], (await _api.LastCallAsync())["body"]);
        await tq.Risk.CheckAsync(new RiskCheckOptions { ExternalUsername = "ctx@example.com", Type = "LOGIN", Context = new Dictionary<string, object?> { ["roles"] = new[] { "admin" } } });
        JsonAssert.Equal(vectors["riskCheck"]!["body"], (await _api.LastCallAsync())["body"]);

        var res = await tq.Login.RequestAsync(new LoginRequestOptions
        {
            ExternalUsername = "ctx@example.com",
            SecurityChanges = new SecurityChanges { Mfa = new DateTimeOffset(2026, 10, 25, 9, 30, 0, TimeSpan.Zero) },
            Destination = new Destination { Kind = "iban", Value = "TR33 0006 1005 1978 6457 9413 26", Known = new[] { "TR330006100519786457841326" } },
        });
        var body = (await _api.LastCallAsync())["body"]!;
        Assert.Equal("2026-10-25T09:30:00.000Z", (string)body["securityChanges"]!["mfa"]!);
        Assert.False(res.Destination!.Known);
        Assert.Equal("same_start_and_end", Assert.Single(res.Destination.Lookalike).Reason);
    }
}
