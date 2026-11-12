using System.Text.Json.Nodes;
using Touchque.Internal;
using Xunit;

namespace Touchque.Tests;

/// <summary>What an adapter's ErrorBody sees of a refusal, and the answer without a client. No API needed.</summary>
public class GuardRefusalTests
{
    private static GuardResult Refused(int status, Step step) =>
        new() { Status = status, Step = step, Body = new JsonObject { ["touchque"] = Json.ToNode(step), ["token"] = "v1.x.y" } };

    private static (int, string, string) Of(GuardResult r)
    {
        var refusal = GuardRefusal.From(r)!;
        return (refusal.Status, refusal.Code, refusal.Message);
    }

    [Fact]
    public void CodeAndMessageComeFromTheErrorElseTheReasonElseTheState()
    {
        Assert.Equal((403, "rejected", "The approval was rejected."), Of(Refused(403, new Step { State = "rejected", RequestId = "r1" })));
        Assert.Equal((403, "request_rejected", "The approval was rejected."), Of(Refused(403, new Step { State = "rejected", Reason = "request_rejected" })));
        Assert.Equal((408, "already_used", "The approval expired. Try again."), Of(Refused(408, new Step { State = "expired", Reason = "already_used" })));
        Assert.Equal((423, "frozen", "Too many rejected approvals. Try again later."), Of(Refused(423, new Step { State = "frozen", RetryAfter = 900 })));
        Assert.Equal((429, "rate_limited", "Too many attempts. Try again later."), Of(Refused(429, new Step { State = "rate_limited", RetryAfter = 60 })));
        Assert.Equal((403, "geo_policy", "The approval was refused."), Of(Refused(403, new Step { State = "blocked", Reason = "geo_policy" })));
        var unauthenticated = Guard.WithoutClient(new GuardInput { User = null, Action = "LOGIN" });
        Assert.Equal((401, "unauthenticated", "Sign in first."), Of(unauthenticated));
        JsonAssert.Equal(new { state = "blocked", reason = "unauthenticated" }, GuardRefusal.From(unauthenticated)!.Touchque);
    }

    [Fact]
    public void StepsAndApprovalsAreNotRefusals()
    {
        Assert.Null(GuardRefusal.From(Refused(202, new Step { State = "waiting", RequestId = "r1" })));
        Assert.Null(GuardRefusal.From(new GuardResult { Status = 200, Approved = new Approval { RequestId = "r1", User = "a", Action = "LOGIN" } }));
    }

    [Fact]
    public void WithoutAClientTheGuardAnswers401Or500Misconfigured()
    {
        var anonymous = Guard.WithoutClient(new GuardInput { User = null, Action = "SEND_MONEY" });
        Assert.Equal(401, anonymous.Status);
        JsonAssert.Equal(new { touchque = new { state = "blocked", reason = "unauthenticated" }, error = new { code = "unauthenticated", message = "Sign in first." } }, anonymous.Body);
        var signedIn = Guard.WithoutClient(new GuardInput { User = "jane@acme.com", Action = "SEND_MONEY" });
        Assert.Equal(500, signedIn.Status);
        JsonAssert.Equal(new
        {
            touchque = new { state = "blocked", reason = "misconfigured" },
            error = new { code = "misconfigured", message = "Two-factor approval is not configured correctly." },
        }, signedIn.Body);
        Assert.Equal((500, "misconfigured", "Two-factor approval is not configured correctly."), Of(signedIn));
    }
}
