using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Touchque.Internal;

namespace Touchque;

/// <summary>What you are about to execute: each field is checked when set.</summary>
public sealed record ApprovalExpectation
{
    /// <summary>The person (the token's <c>sub</c>).</summary>
    public string? User { get; init; }

    /// <summary>The action type.</summary>
    public string? Type { get; init; }

    /// <summary>
    /// RFC 9396 authorization details: one object (matches a token with exactly one
    /// entry) or a list (matches entry by entry). Any object (anonymous, dictionary,
    /// JsonNode). Amounts compare as decimals, IBANs without spaces in any case,
    /// currencies in any case; extra fields of the token are ignored.
    /// </summary>
    public object? AuthorizationDetails { get; init; }
}

/// <summary>
/// What a partner's server checks before executing what an AI agent asked for: the
/// approval token's claims match the transaction (person, action type,
/// authorization details) and, offline, its ES256 signature against Touchque's
/// keys (<c>GET /agents/jwks.json</c>). <see cref="AgentsResource.RedeemApprovalAsync"/>
/// makes a token single-use.
/// </summary>
public static partial class ApprovalToken
{
    [GeneratedRegex(@"^\d+(\.\d+)?$")]
    private static partial Regex DecimalRe();

    [GeneratedRegex(@"\s+")]
    private static partial Regex SpacesRe();

    /// <summary>Header and claims WITHOUT checking the signature.</summary>
    public static (JsonObject Header, JsonObject Claims) Decode(string token)
    {
        var parts = JwsVerify.Split(token) ?? throw new TouchqueApprovalMismatchException("not an approval token");
        return (parts.Header, parts.Claims);
    }

    /// <summary>Does <paramref name="details"/> (a token's authorization_details) say what <paramref name="expected"/> says?</summary>
    public static bool Matches(JsonNode? details, object expected)
    {
        if (details is not JsonArray list) return false;
        var exp = expected as JsonNode ?? Json.ToNode(expected);
        if (exp is JsonArray expList)
        {
            if (list.Count != expList.Count) return false;
            for (var i = 0; i < expList.Count; i++)
            {
                if (!Partial(list[i], expList[i])) return false;
            }
            return true;
        }
        return list.Count == 1 && Partial(list[0], exp);
    }

    /// <summary>Throws <see cref="TouchqueApprovalMismatchException"/> unless the claims say what you expect.</summary>
    public static void AssertMatches(JsonObject claims, ApprovalExpectation? expect)
    {
        if (expect is null) return;
        if (expect.User is not null && Json.Str(claims, "sub") != expect.User)
        {
            throw new TouchqueApprovalMismatchException("the approval is for another person");
        }
        if (expect.Type is not null && Json.Str(claims, "type") != expect.Type)
        {
            throw new TouchqueApprovalMismatchException($"the approval is for another action type ({Json.Str(claims, "type")})");
        }
        if (expect.AuthorizationDetails is not null && !Matches(claims["authorization_details"], expect.AuthorizationDetails))
        {
            throw new TouchqueApprovalMismatchException("the approved details differ from what you are about to execute");
        }
    }

    /// <summary>
    /// Verifies an approval token offline: typ <c>touchque-approval+jwt</c>, ES256 by a
    /// key of <paramref name="jwks"/>, not expired (30 s leeway), <c>aud</c> equal to
    /// <paramref name="audience"/>, then <paramref name="expect"/>. <paramref name="audience"/>
    /// is required: <c>/agents/jwks.json</c> is one key set for every Touchque workspace, so
    /// without it a token Touchque signed for another workspace would pass. Pass your own
    /// (<c>tq.Agents.ApprovalAudienceAsync()</c>, <c>touchque:workspace:&lt;id&gt;</c>), or use
    /// <c>tq.Agents.VerifyApprovalTokenAsync</c>, which fills it in. Does NOT make it single-use.
    /// </summary>
    public static JsonObject VerifyWith(string token, JsonObject jwks, string? audience = null, ApprovalExpectation? expect = null, DateTimeOffset? now = null)
    {
        if (string.IsNullOrEmpty(audience)) throw new TouchqueApprovalMismatchException("audience is required: your workspace's touchque:workspace:<id> (tq.Agents.ApprovalAudienceAsync())");
        var parts = JwsVerify.Split(token) ?? throw new TouchqueApprovalMismatchException("not an approval token");
        var (header, claims, input, sig) = parts;
        if (Json.Str(header, "typ") != "touchque-approval+jwt" || Json.Str(header, "alg") != "ES256")
        {
            throw new TouchqueApprovalMismatchException("not an approval token (typ/alg)");
        }
        var kid = Json.Str(header, "kid");
        JsonObject? jwk = null;
        if (jwks["keys"] is JsonArray keys)
        {
            foreach (var k in keys.OfType<JsonObject>())
            {
                if (Json.Str(k, "kid") == kid && Json.Str(k, "kty") == "EC" && Json.Str(k, "crv") == "P-256") jwk = k;
            }
        }
        if (jwk is null) throw new TouchqueApprovalMismatchException("signed by an unknown key");
        if (!JwsVerify.Verify("ES256", jwk, input, sig)) throw new TouchqueApprovalMismatchException("the signature does not verify");
        var at = (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        var exp = Json.Long(claims, "exp");
        if (exp is null || exp.Value + 30 < at) throw new TouchqueApprovalMismatchException("the approval token expired");
        var aud = Json.Str(claims, "aud");
        if (string.IsNullOrEmpty(aud)) throw new TouchqueApprovalMismatchException("the approval token names no workspace");
        if (aud != audience) throw new TouchqueApprovalMismatchException("the approval token is for another workspace");
        AssertMatches(claims, expect);
        return claims;
    }

    private static string? DecimalText(JsonNode? value)
    {
        var text = value switch
        {
            JsonValue v when v.TryGetValue<string>(out var s) => s,
            JsonValue v => v.ToJsonString(),
            _ => null,
        };
        if (text is null) return null;
        text = text.Trim();
        if (!DecimalRe().IsMatch(text)) return null;
        var parts = text.Split('.', 2);
        var whole = parts[0].TrimStart('0');
        if (whole.Length == 0) whole = "0";
        var frac = parts.Length > 1 ? parts[1].TrimEnd('0') : "";
        return frac.Length == 0 ? whole : whole + "." + frac;
    }

    private static bool Same(string key, JsonNode? actual, JsonNode? expected)
    {
        if (expected is JsonObject or JsonArray) return Partial(actual, expected);
        if (key == "amount")
        {
            var a = DecimalText(actual);
            return a is not null && a == DecimalText(expected);
        }
        if (key is "iban" or "currency")
        {
            if (actual is not JsonValue av || !av.TryGetValue<string>(out var a)) return false;
            static string Norm(string v) => SpacesRe().Replace(v, "").ToUpperInvariant();
            var e = expected is JsonValue ev && ev.TryGetValue<string>(out var es) ? es : expected?.ToJsonString() ?? "";
            return Norm(a) == Norm(e);
        }
        return ScalarEquals(actual, expected);
    }

    private static bool Partial(JsonNode? actual, JsonNode? expected)
    {
        if (expected is JsonArray expList)
        {
            if (actual is not JsonArray list || list.Count != expList.Count) return false;
            for (var i = 0; i < expList.Count; i++)
            {
                var e = expList[i];
                if (!(e is JsonObject or JsonArray ? Partial(list[i], e) : ScalarEquals(list[i], e))) return false;
            }
            return true;
        }
        if (expected is not JsonObject expObj) return ScalarEquals(actual, expected);
        if (actual is not JsonObject obj) return false;
        foreach (var (k, v) in expObj)
        {
            if (!obj.TryGetPropertyValue(k, out var a) || !Same(k, a, v)) return false;
        }
        return true;
    }

    private static bool ScalarEquals(JsonNode? a, JsonNode? b)
    {
        if (a is null || b is null) return a is null && b is null;
        if (a is not JsonValue av || b is not JsonValue bv) return false;
        if (av.TryGetValue<string>(out var sa)) return bv.TryGetValue<string>(out var sb) && sa == sb;
        if (av.TryGetValue<bool>(out var ba)) return bv.TryGetValue<bool>(out var bb) && ba == bb;
        if (decimal.TryParse(av.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var da) &&
            decimal.TryParse(bv.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var db))
        {
            return !bv.TryGetValue<string>(out _) && da == db;
        }
        return av.ToJsonString() == bv.ToJsonString();
    }
}
