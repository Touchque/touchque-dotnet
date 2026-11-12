using System.Globalization;
using System.Security.Claims;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Touchque.AspNetCore;
using Touchque.Relay;

namespace Touchque.Tests;

/// <summary>The README's snippets, compiled (never run): a README that does not build fails the build.</summary>
internal static class ReadmeExamples
{
    public sealed record Transfer(string To, string Amount);

    public static void Configure(WebApplicationBuilder builder, WebApplication app, TouchqueClient tq)
    {
        builder.Services.AddTouchque(o => o.ApiKey = "tq_…");
        builder.Services.Configure<TouchqueGuardOptions>("PAYOUT", o => o.Details = c => [("Amount", "1")]);
        builder.Services.AddTouchqueLogin(o =>
        {
            o.Domain = "acme.login.touchque.com";
            o.ClientId = "…";
            o.Scope = "openid profile email offline_access";
        });
        builder.Services.AddAuthentication().AddTouchqueBearer(o =>
        {
            o.Domain = "acme.login.touchque.com";
            o.Audience = "https://api.acme.com";
            o.RequiredScopes = ["read:orders"];
        });

        app.MapPost("/transfer", (Transfer t, HttpContext http) => Results.Ok(http.GetTouchqueApproval()))
            .RequireAuthorization()
            .RequireTouchque("SEND_MONEY", o => o.Details = c =>
                [("Amount", c.Argument<Transfer>()!.Amount), ("To", c.Argument<Transfer>()!.To)]);
        app.MapTouchqueRelay("/touchque", new RelayOptions<HttpContext>
        {
            GetUserId = http => http.User.TouchqueUser(),
            OnAuthenticated = (http, response, info) => Task.CompletedTask,
            SilentSignIn = new(),
        });
        app.MapTouchqueWebhook("/webhooks/touchque", (JsonObject e, HttpContext http) => Task.CompletedTask);
        app.MapTouchqueLogin();
        app.MapGet("/account", (ClaimsPrincipal u) => u.FindFirstValue("email")).RequireAuthorization();
    }

    public static async Task Flows(TouchqueClient tq, JsonObject payment)
    {
        var step = await tq.StartAsync("SEND_MONEY", new StartOptions { User = "jane@acme.com", Details = [("Amount", "250 EUR")] });
        await tq.CheckAsync(step.RequestId!);
        await tq.CompleteAsync(step.RequestId!, new CompleteExpectations { User = "jane@acme.com", Action = "SEND_MONEY", Details = [("Amount", "250 EUR")] });
        await tq.Login.VerifyAsync(new LoginRequestOptions
        {
            ExternalUsername = "jane@acme.com",
            OnChallenge = c => Task.CompletedTask,
        });
        await tq.ActionTypes.DefineAsync("SEND_MONEY", "Send money", critical: true);
        await tq.Actions.DeployAsync("night-alert", new DeployActionOptions
        {
            Trigger = "approval.decided",
            Template = ActionTemplateRef.Of("alert", new { channel = "slack", when = new { countries = new[] { "TR" } } }),
        });
        var keys = AgentKeys.Generate();
        await tq.Agents.CreateAsync(new CreateAgentOptions { Name = "Invoice bot", AllowedTypes = ["PAY_INVOICE"], PublicKey = keys.PublicJwk });
        using var bot = new TouchqueAgent();
        var approved = await bot.RequireApprovalAsync("ayse@acme.com", "PAY_INVOICE", new[] { payment }, onChallenge: s => Task.CompletedTask);
        await tq.Agents.RedeemApprovalAsync(approved.ApprovalToken!, new ApprovalExpectation { User = "ayse@acme.com", AuthorizationDetails = payment });
    }

    public static async Task CrossAppAccessExamples(string clientId, string secret, string idToken, string filesSecret, string authenticatedClientId, IFormCollection form, string cardJson)
    {
        var jag = await CrossAppAccess.RequestIdJagAsync(new() { Issuer = "https://sso.touchque.com", ClientId = clientId,
            ClientSecret = secret, IdToken = idToken, Audience = "https://auth.files.example" });
        var tokens = await CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = "https://auth.files.example/token", ClientId = "acme",
            ClientSecret = filesSecret, Assertion = jag.Assertion });

        // Your own authorization server (jwt-bearer grant):
        var verifier = new IdJagVerifier(new() { Issuer = "https://sso.touchque.com", Audience = "https://auth.files.example" });
        var claims = await verifier.VerifyAsync(form["assertion"]!, authenticatedClientId);

        await AgentCard.VerifyAsync(cardJson, new() { CardUrl = "https://agent.example/.well-known/agent-card.json" });
    }

    public static async Task SharedSignalsExample(WebApplication app, string pollUrl, string streamToken, IReadOnlyList<string> handled,
        Func<string?, Task> EndSessionsAsync, Func<SecurityEvent, Task> HandleAsync)
    {
        var verifier = new SecurityEventVerifier(new() { Issuer = "https://sso.touchque.com", Audience = "https://app.example.com" });

        // Push delivery (RFC 8935): the SET is the request body (application/secevent+jwt).
        app.MapPost("/ssf", async (HttpRequest req) =>
        {
            try
            {
                var ev = await verifier.VerifyAsync(await new StreamReader(req.Body).ReadToEndAsync());
                if (ev.Name == "session-revoked") await EndSessionsAsync((string?)ev.Subject["email"]);
                return Results.StatusCode(202);
            }
            catch (TouchqueSecurityEventException e)
            {
                return Results.Json(new { err = e.Error, description = e.Message }, statusCode: e.Error == "temporarily_unavailable" ? 503 : 400);
            }
        });

        // Poll delivery (RFC 8936): acknowledge the jtis you handled, read the SETs that wait.
        var (sets, moreAvailable) = await SecurityEvents.PollAsync(new() { Url = pollUrl, Token = streamToken, Ack = handled });
        foreach (var (jti, set) in sets) await HandleAsync(await verifier.VerifyAsync(set));
    }

    public static async Task<string> SafeGuardExample(TouchqueClient tq, string safe, string guard, string to, string data, string multiSendCallOnly, string approverKey, string ownerSignatures)
    {
        var tx = new SafeGuardTx
        {
            ChainId = "1", Safe = safe, Guard = guard,
            Tx = new SafeTxCall { To = to, Value = "0", Data = data, Operation = 0, Nonce = "42" },
            Config = new SafeGuardConfig { Threshold = 2, GovThreshold = 3, GovDelay = 172800, ExitDelay = 259200 },
            BatchTargets = [multiSendCallOnly],
            ApproverIndex = 0,
        };
        var sent = await tq.SafeGuard.RequestAsync(new SafeGuardRequestOptions { ExternalUsername = "treasurer@acme.com", Type = "safe_payment", SafeTx = tx });
        var done = await tq.SafeGuard.WaitForApprovalAsync(sent.RequestId);
        var approval = done.SafeTx!.Approval!;
        var purpose = done.SafeTx.Purpose;
        var check = SafeApproval.Verify(tx, approval, approverKey, new VerifySafeApprovalOptions { Purpose = purpose, ApproverIndex = 0 });
        if (!check.Valid) throw new InvalidOperationException($"approval refused: {check.Reason}");
        return purpose == "approve"
            ? SafeApproval.WithApprovals(ownerSignatures, [approval])
            : SafeApproval.ScheduleCall(safe, check.GovernanceHash, [approval]);
    }

    private sealed class Accounts
    {
        public Task<bool> CanSendAsync(string? user, string amount) => Task.FromResult(user is not null && amount.Length > 0);
    }

    private sealed class Payments
    {
        public Task<Transfer> SendAsync(Transfer t) => Task.FromResult(t);
    }

    /// <summary>"Refusals in your app's error shape" and "Guard inside your handler".</summary>
    public static void GuardExamples(WebApplicationBuilder builder, WebApplication app)
    {
        var accounts = new Accounts();
        var payments = new Payments();
        app.MapPost("/transfer", (Transfer t) => Results.Ok())
            .RequireTouchque("SEND_MONEY", o => o.ErrorBody = r => new { message = r.Message, code = r.Code });
        builder.Services.ConfigureAll<TouchqueGuardOptions>(o => o.ErrorBody = r => new { message = r.Message, code = r.Code });

        app.MapPost("/transfer", async (Transfer t, HttpContext http) =>
        {
            var user = http.User.TouchqueUser();
            // 1. Your own checks first (ownership, balance): a request you refuse anyway never reaches the phone.
            if (!await accounts.CanSendAsync(user, t.Amount)) return Results.Conflict(new { error = "insufficient_funds" });

            var h = http.Request.Headers;
            var input = new GuardInput
            {
                User = user, Action = "SEND_MONEY", Details = [("Amount", t.Amount), ("To", t.To)],
                Ip = http.TouchqueClientIp(), UserAgent = h.UserAgent,
                Token = h[Guard.TokenHeader], Offline = h[Guard.OfflineHeader] == "1",
                Code = h[Guard.CodeHeader], CodeType = h[Guard.CodeTypeHeader],
            };
            GuardResult r;
            try
            {
                // The client AddTouchque registers, resolved per request: built on the first one, never at startup.
                r = await Guard.RunAsync(http.RequestServices.GetRequiredService<TouchqueClient>(), input, http.RequestAborted);
            }
            catch (TouchqueConfigException)
            {
                r = Guard.WithoutClient(input);   // no TQ_API_KEY / TQ_API_SECRET yet: 500 misconfigured (401 without a user)
            }
            // 2. A step (202) or a refusal: its status, headers (Cache-Control, Retry-After, X-Touchque-*) and JSON body.
            if (r.Approved is null) return r.ToResult();
            // 3. Approved: run the action once. The approval is used up.
            return Results.Ok(await payments.SendAsync(t));
        });

        // The bullets: the null client, an errorBody, WriteAsync, IsStatusPoll.
        app.MapPost("/env", async (HttpContext http) =>
        {
            var input = new GuardInput { User = http.User.TouchqueUser(), Action = "SEND_MONEY", Enroll = false };
            var r = await Guard.RunAsync(null, input, http.RequestAborted);
            if (Guard.IsStatusPoll(null, input) || r.Approved is not null) return Results.Ok();
            if (http.Request.Query.ContainsKey("write"))
            {
                await r.WriteAsync(http, refusal => new { message = refusal.Message, code = refusal.Code });
                return Results.Empty;
            }
            return r.ToResult(refusal => new { message = refusal.Message, code = refusal.Code });
        });
        _ = Guard.DefaultClient();   // the fail-fast check at startup
        Guard.SetDefaultClient(new TouchqueClient(new TouchqueOptions { Logger = null }));
        Guard.SetDefaultClient(null);
    }
}
