using System.Text.Json;
using System.Text.Json.Nodes;
using Touchque.AspNetCore;
using Touchque.Internal;
using Xunit;

namespace Touchque.Tests;

/// <summary>
/// The answer every adapter sends for a guard result that is not an approval (Guard.Answer: RequireTouchque,
/// [RequireTouchque], GuardResult.ToResult and the relay), and its ErrorBody rules. No API needed.
/// </summary>
public class GuardAnswerTests
{
    private static GuardResult Result(int status, Step step) =>
        new() { Status = status, Step = step, Body = new JsonObject { ["touchque"] = Json.ToNode(step), ["token"] = "v1.x.y" } };

    private static readonly GuardResult Waiting = Result(202, new Step { State = "waiting", RequestId = "r1", Number = "47" });
    private static readonly GuardResult Blocked = Result(403, new Step { State = "blocked", Reason = "geo_policy" });
    private static readonly GuardResult Limited = Result(429, new Step { State = "rate_limited", RetryAfter = 60 });
    private static readonly GuardResult Frozen = Result(423, new Step { State = "frozen", RetryAfter = 900 });
    private static readonly GuardResult Misconfigured = Guard.WithoutClient(new GuardInput { User = "jane@acme.com", Action = "LOGIN" });

    private static string[] Headers(GuardAnswer a) => a.Headers.Select(h => $"{h.Key}: {h.Value}").ToArray();

    [Fact]
    public void WithoutAnErrorBodyTheAnswerIsTheGuardsBodyWithItsHeaders()
    {
        var cases = new (GuardResult Result, string[] Headers)[]
        {
            (Waiting, new[] { "Cache-Control: no-store" }),
            (Blocked, new[] { "Cache-Control: no-store", "X-Touchque-State: blocked", "X-Touchque-Reason: geo_policy" }),
            (Limited, new[] { "Cache-Control: no-store", "Retry-After: 60", "X-Touchque-State: rate_limited" }),
            (Frozen, new[] { "Cache-Control: no-store", "Retry-After: 900", "X-Touchque-State: frozen" }),
            (Misconfigured, new[] { "Cache-Control: no-store", "X-Touchque-State: blocked", "X-Touchque-Reason: misconfigured" }),
        };
        foreach (var (result, headers) in cases)
        {
            var answer = Guard.Answer(result);
            Assert.Equal(result.Status, answer.Status);
            Assert.Equal(headers, Headers(answer));
            JsonAssert.Equal(result.Body, answer.Body);
        }
        var approved = new GuardResult { Status = 200, Approved = new Approval { RequestId = "r1", User = "a", Action = "LOGIN" } };
        Assert.Throws<ArgumentException>(() => Guard.Answer(approved));
        Assert.Throws<ArgumentException>(() => approved.ToResult());
    }

    [Fact]
    public void AnErrorBodyShapesRefusalsOnlyAndTheStepWins()
    {
        var seen = new List<GuardRefusal>();
        object? Shape(GuardRefusal r)
        {
            seen.Add(r);
            return new Dictionary<string, object?> { ["message"] = r.Message, ["code"] = r.Code, ["Touchque"] = "not the step" };
        }
        // Never for a 202 step.
        JsonAssert.Equal(Waiting.Body, Guard.Answer(Waiting, Shape).Body);
        Assert.Empty(seen);
        // An object gets the step under "touchque" (no other spelling of the key, no token); the status and headers stay.
        var limited = Guard.Answer(Limited, Shape);
        Assert.Equal(429, limited.Status);
        Assert.Equal(new[] { "Cache-Control: no-store", "Retry-After: 60", "X-Touchque-State: rate_limited" }, Headers(limited));
        JsonAssert.Equal(new { message = "Too many attempts. Try again later.", code = "rate_limited", touchque = new { state = "rate_limited", retryAfter = 60 } },
            limited.Body);
        JsonAssert.Equal(new
        {
            message = "Two-factor approval is not configured correctly.", code = "misconfigured",
            touchque = new { state = "blocked", reason = "misconfigured" },
        }, Guard.Answer(Misconfigured, Shape).Body);
        // Anything that is not an object is sent as it is; the state is in the headers.
        var text = Guard.Answer(Blocked, r => "refused: " + r.Code);
        Assert.Equal("\"refused: geo_policy\"", text.Body!.ToJsonString());
        Assert.Contains("X-Touchque-Reason: geo_policy", Headers(text));
        Assert.Null(Guard.Answer(Blocked, _ => null).Body);
        Assert.Equal("[1,2]", Guard.Answer(Blocked, _ => new[] { 1, 2 }).Body!.ToJsonString());
        // The callback gets a copy of the step.
        var mutated = Guard.Answer(Frozen, r =>
        {
            r.Touchque["state"] = "approved";
            return new { };
        });
        Assert.Equal(("frozen", "frozen"), ((string?)mutated.Body!["touchque"]!["state"], (string?)Frozen.Body!["touchque"]!["state"]));
        // A result that carries only its step (a BeforeStart hook's 429): the object still gets it.
        var hook = new GuardResult { Status = 429, Body = new JsonObject { ["error"] = "RATE_LIMITED" }, Step = new Step { State = "rate_limited", RetryAfter = 7 } };
        JsonAssert.Equal(new { code = "rate_limited", touchque = new { state = "rate_limited", retryAfter = 7 } }, Guard.Answer(hook, r => new { code = r.Code }).Body);
    }

    [Fact]
    public void TheAppsJsonOptionsWriteTheResult()
    {
        object? Shape(GuardRefusal r) => new { ErrorCode = r.Code };
        var snake = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
        JsonAssert.Equal(new { error_code = "geo_policy", touchque = new { state = "blocked", reason = "geo_policy" } }, Guard.Answer(Blocked, Shape, snake).Body);
        // Without the app's options: the web defaults (camelCase).
        JsonAssert.Equal(new { errorCode = "geo_policy", touchque = new { state = "blocked", reason = "geo_policy" } }, Guard.Answer(Blocked, Shape).Body);
    }

    [Fact]
    public void AFailingErrorBodySendsTheDefaultBodyAndLogsWhy()
    {
        var logger = new ContractTests.ListLogger();
        var log = new SdkLog(logger, false);
        var failing = new Func<GuardRefusal, object?>[]
        {
            _ => throw new InvalidOperationException("the error template is broken"),
            _ => typeof(string),   // the serializer cannot write it
        };
        foreach (var errorBody in failing)
        {
            var answer = Guard.Answer(Frozen, errorBody, null, log);
            Assert.Equal(423, answer.Status);
            Assert.Equal(new[] { "Cache-Control: no-store", "Retry-After: 900", "X-Touchque-State: frozen" }, Headers(answer));
            JsonAssert.Equal(Frozen.Body, answer.Body);
        }
        Assert.Equal(2, logger.Lines.Count);
        Assert.Equal((Microsoft.Extensions.Logging.LogLevel.Error, "[Touchque] errorBody failed: the error template is broken"), logger.Lines[0]);
        Assert.StartsWith("[Touchque] errorBody failed: ", logger.Lines[1].Message, StringComparison.Ordinal);
    }
}
