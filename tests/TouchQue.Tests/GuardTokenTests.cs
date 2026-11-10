using System.Text.Json.Nodes;
using Xunit;

namespace TouchQue.Tests;

/// <summary>GuardToken.Sign / Verify: typed claims over the guard's own token.</summary>
public class GuardTokenTests
{
    // Made by the Node SDK: signGuardToken('test_secret', { u, a, d: 'ab12', r: null, st: 'waiting', rid: 'req_1', n: '42', cc: 'K7P-2QX', exp: 4102444800000 }).
    private const string NodeToken =
        "v1.eyJ1IjoiamFuZUBhY21lLmNvbSIsImEiOiJTRU5EX01PTkVZIiwiZCI6ImFiMTIiLCJyIjpudWxsLCJzdCI6IndhaXRpbmciLCJyaWQiOiJyZXFfMSIsIm4iOiI0MiIsImNjIjoiSzdQLTJRWCIsImV4cCI6NDEwMjQ0NDgwMDAwMH0.2OOcXzpDijerGY5xy66he_sNaGbHtDnyNB0GE4w6-EI";

    private static readonly GuardTokenClaims NodeClaims = new()
    {
        User = "jane@acme.com", Action = "SEND_MONEY", DetailsDigest = "ab12", State = "waiting",
        RequestId = "req_1", Number = "42", CaseCode = "K7P-2QX", ExpiresAt = 4102444800000,
    };

    private static long InAMinute => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 60_000;

    [Fact]
    public void SignsLikeTheNodeSdkAndReadsItsTokens()
    {
        Assert.Equal(NodeToken, GuardToken.Sign("test_secret", NodeClaims));
        Assert.Equal(NodeClaims, GuardToken.Verify("test_secret", NodeToken));
    }

    [Fact]
    public void RoundTripsEveryClaim()
    {
        var claims = new GuardTokenClaims
        {
            User = "jane@acme.com", Action = "PAYOUT", DetailsDigest = Details.Digest([("Amount", "250 EUR")]), ReferenceId = "inv-7",
            State = "offline", RequestId = "req_2", Number = "17", OfflineChallengeId = "oc_1", CaseCode = "REF-USE", ExpiresAt = InAMinute,
        };
        Assert.Equal(claims, GuardToken.Verify("s", GuardToken.Sign("s", claims)));
        // r is always written, as null when there is no reference; the optional claims are left out.
        var bare = Steps.VerifyGuardToken("s", GuardToken.Sign("s", new GuardTokenClaims { User = "a", Action = "LOGIN", State = "waiting", ExpiresAt = InAMinute }))!;
        Assert.True(bare.ContainsKey("r") && bare["r"] is null);
        Assert.False(bare.ContainsKey("rid") || bare.ContainsKey("n") || bare.ContainsKey("oc") || bare.ContainsKey("cc"));
    }

    [Fact]
    public void RefusesForeignChangedExpiredAndIncompleteTokens()
    {
        var token = GuardToken.Sign("s", NodeClaims with { ExpiresAt = InAMinute });
        Assert.NotNull(GuardToken.Verify("s", token));
        Assert.Null(GuardToken.Verify("other", token));
        Assert.Null(GuardToken.Verify("", token));
        Assert.Null(GuardToken.Verify("s", token[..^2] + "xx"));
        Assert.Null(GuardToken.Verify("s", null));
        Assert.Null(GuardToken.Verify("s", "v1." + new string('a', 5000) + ".x"));
        Assert.Null(GuardToken.Verify("s", GuardToken.Sign("s", NodeClaims with { ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 1 })));
        // Signed with the secret, but not a guard token: no state.
        var noState = Steps.SignGuardToken("s", new JsonObject { ["u"] = "a", ["a"] = "LOGIN", ["d"] = "", ["r"] = null, ["exp"] = InAMinute });
        Assert.Null(GuardToken.Verify("s", noState));
        Assert.Throws<TouchQueConfigException>(() => GuardToken.Sign("", NodeClaims));
    }

    [Fact]
    public void TheGuardTakesTheTokenForItsOwn()
    {
        var tq = new TouchQueClient(new TouchQueOptions { ApiKey = "tq_k", ApiSecret = "test_secret", BaseUrl = "http://127.0.0.1:9" });
        IReadOnlyList<LoginDetail> details = [("Amount", "250 EUR")];
        var claims = new GuardTokenClaims
        {
            User = "jane@acme.com", Action = "SEND_MONEY", DetailsDigest = Details.Digest(details), State = "waiting", RequestId = "req_1", ExpiresAt = InAMinute,
        };
        var input = new GuardInput { User = "jane@acme.com", Action = "SEND_MONEY", Details = details, Token = GuardToken.Sign("test_secret", claims) };
        Assert.True(Guard.IsStatusPoll(tq, input));
        Assert.False(Guard.IsStatusPoll(tq, input with { User = "eve@acme.com" }));
        Assert.False(Guard.IsStatusPoll(tq, input with { Details = [("Amount", "9999 EUR")] }));
        Assert.False(Guard.IsStatusPoll(tq, input with { Token = GuardToken.Sign("another_secret", claims) }));
        Assert.False(Guard.IsStatusPoll(tq, input with { Token = GuardToken.Sign("test_secret", claims with { State = "approved" }) }));
    }
}
