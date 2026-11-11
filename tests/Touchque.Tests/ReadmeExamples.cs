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
}
