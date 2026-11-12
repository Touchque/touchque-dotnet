using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>
/// What a guard token carries, under the same short names in every Touchque server SDK
/// (u, a, d, r, st, rid, n, oc, cc, ee, exp): it binds a step to one user, action and transaction.
/// </summary>
public sealed record GuardTokenClaims
{
    /// <summary>u: the user in YOUR system.</summary>
    public required string User { get; init; }
    /// <summary>a: the action.</summary>
    public required string Action { get; init; }
    /// <summary>d: <see cref="Details.Digest"/> of the details ("" for none).</summary>
    public string DetailsDigest { get; init; } = "";
    /// <summary>r: the reference id; written as null when there is none.</summary>
    public string? ReferenceId { get; init; }
    /// <summary>st: the step's state (waiting, passkey_required, offline …).</summary>
    public required string State { get; init; }
    /// <summary>rid: the request id while it waits.</summary>
    public string? RequestId { get; init; }
    /// <summary>n: the matching number.</summary>
    public string? Number { get; init; }
    /// <summary>oc: the offline challenge id.</summary>
    public string? OfflineChallengeId { get; init; }
    /// <summary>cc: the "Why?" case code, shown while it waits.</summary>
    public string? CaseCode { get; init; }
    /// <summary>ee: when the first-time linking QR of an <c>enroll</c> step expires, in Unix milliseconds; its polls keep that QR until then.</summary>
    public long? EnrollExpiresAt { get; init; }
    /// <summary>exp: Unix milliseconds (not seconds).</summary>
    public required long ExpiresAt { get; init; }
}

/// <summary>
/// The guard token <see cref="Guard.RunAsync"/> hands the browser, for a flow of your own.
/// The browser echoes it back while it waits; it is signed with a key derived from your
/// API secret, so it cannot be replayed for another user, amount or route.
/// </summary>
public static class GuardToken
{
    /// <summary>Signs the claims (<c>v1.&lt;body&gt;.&lt;mac&gt;</c>).</summary>
    public static string Sign(string apiSecret, GuardTokenClaims claims)
    {
        if (string.IsNullOrEmpty(apiSecret)) throw new TouchqueConfigException("GuardToken.Sign() needs the API secret");
        ArgumentNullException.ThrowIfNull(claims);
        var o = new JsonObject
        {
            ["u"] = claims.User, ["a"] = claims.Action, ["d"] = claims.DetailsDigest, ["r"] = claims.ReferenceId, ["st"] = claims.State,
        };
        if (claims.RequestId is not null) o["rid"] = claims.RequestId;
        if (claims.Number is not null) o["n"] = claims.Number;
        if (claims.OfflineChallengeId is not null) o["oc"] = claims.OfflineChallengeId;
        if (claims.CaseCode is not null) o["cc"] = claims.CaseCode;
        if (claims.EnrollExpiresAt is not null) o["ee"] = claims.EnrollExpiresAt;
        o["exp"] = claims.ExpiresAt;
        return Steps.SignGuardToken(apiSecret, o);
    }

    /// <summary>
    /// The token's claims, or null when it is missing, changed, signed with another secret,
    /// expired, or does not carry the guard's claims.
    /// </summary>
    public static GuardTokenClaims? Verify(string apiSecret, string? token)
    {
        if (string.IsNullOrEmpty(apiSecret)) return null;
        var c = Steps.VerifyGuardToken(apiSecret, token);
        if (c is null) return null;
        var (u, a, d, st, exp) = (Json.Str(c, "u"), Json.Str(c, "a"), Json.Str(c, "d"), Json.Str(c, "st"), Json.Long(c, "exp"));
        if (u is null || a is null || d is null || st is null || exp is null) return null;
        return new GuardTokenClaims
        {
            User = u, Action = a, DetailsDigest = d, ReferenceId = Json.Str(c, "r"), State = st,
            RequestId = Json.Str(c, "rid"), Number = Json.Str(c, "n"), OfflineChallengeId = Json.Str(c, "oc"), CaseCode = Json.Str(c, "cc"),
            EnrollExpiresAt = Json.Long(c, "ee"), ExpiresAt = exp.Value,
        };
    }
}
