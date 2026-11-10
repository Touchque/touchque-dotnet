using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>
/// What the user has to see while an approval runs, safe to send to the browser
/// as JSON (it never holds a secret). States: waiting, approved, rejected, expired,
/// enroll, passkey_required, offline, blocked, frozen, rate_limited.
/// </summary>
public sealed record Step
{
    public string State { get; init; } = "";
    public string? RequestId { get; init; }
    /// <summary>The number to show; the user picks it on the phone.</summary>
    public string? Number { get; init; }
    public string? ExpiresAt { get; init; }
    public IReadOnlyList<LoginDetail>? Details { get; init; }
    /// <summary>The "Why?" case code: show it ("Tell your support team: K7P-2QX").</summary>
    public string? CaseCode { get; init; }
    public IReadOnlyList<RiskReason>? Reasons { get; init; }
    /// <summary>Lets <c>@touchque/web</c> post behavioural signals for this one request.</summary>
    public string? TelemetryToken { get; init; }
    /// <summary>Mirror Alarm: the page showing this first step loads it.</summary>
    public Canary? Canary { get; init; }
    /// <summary>First-time linking: show <c>QrCodeDataUrl</c>.</summary>
    public StepEnroll? Enroll { get; init; }
    /// <summary>The offline QR (phone has no internet).</summary>
    public StepOffline? Offline { get; init; }
    public string? Reason { get; init; }
    public int? RetryAfter { get; init; }
    public Assurance? Assurance { get; init; }
}

public sealed record StepEnroll
{
    public string? QrCodeDataUrl { get; init; }
    public IReadOnlyList<string>? RecoveryCodes { get; init; }
    public string? ExpiresAt { get; init; }
}

public sealed record StepOffline
{
    public string ChallengeId { get; init; } = "";
    public string? QrDataUrl { get; init; }
    public string? ExpiresAt { get; init; }
    public bool? TotpAvailable { get; init; }
    public string? ChallengeCode { get; init; }
    public int? AttemptsLeft { get; init; }
}

/// <summary>An approval used once: run the protected action now.</summary>
public sealed record Approval
{
    public string RequestId { get; init; } = "";
    public string User { get; init; } = "";
    public string Action { get; init; } = "";
    public Assurance? Assurance { get; init; }
    /// <summary>DEVICE, WEBAUTHN, OFFLINE_CODE, OFFLINE_TOTP or SILENT.</summary>
    public string? ConfirmedVia { get; init; }
    /// <summary>The phone's signature over what it showed (<see cref="TouchQue.ApprovalProof"/>).</summary>
    public JsonObject? ApprovalProof { get; init; }
    /// <summary>
    /// Vishing Shield: approved during a call. Let the user in, but treat the session as
    /// limited: critical actions are refused until APPROVAL_RECONFIRMED, and APPROVAL_REVOKED means end it.
    /// </summary>
    public bool? Provisional { get; init; }
    public bool? Revoked { get; init; }
    public string? RevokeReason { get; init; }
    public string? ReconfirmedAt { get; init; }
    /// <summary>Silent sign-ins: why TouchQue let this known browser in (nothing went to the phone).</summary>
    public IReadOnlyList<RiskReason>? Reasons { get; init; }
}

/// <summary>What to start an approval for.</summary>
public sealed record StartOptions
{
    /// <summary>The user in YOUR system.</summary>
    public required string User { get; init; }
    public IReadOnlyList<LoginDetail>? Details { get; init; }
    public string? ReferenceId { get; init; }
    /// <summary>The end user's IP.</summary>
    public string? Ip { get; init; }
    public string? UserAgent { get; init; }
    /// <summary>Silent sign-ins: the <c>X-TouchQue-Browser</c> header, passed through untouched.</summary>
    public string? BrowserProof { get; init; }
    /// <summary>For your TouchQue Actions only (<c>event.context</c>).</summary>
    public IReadOnlyDictionary<string, object?>? Context { get; init; }
    /// <summary>False: never show the first-time linking QR (a typed username proves nothing).</summary>
    public bool Enroll { get; init; } = true;
}

/// <summary>What an approved request must be for (checked by <see cref="TouchQueClient.CompleteAsync"/>).</summary>
public sealed record CompleteExpectations
{
    public required string User { get; init; }
    public required string Action { get; init; }
    public IReadOnlyList<LoginDetail>? Details { get; init; }
    public string? ReferenceId { get; init; }
}

/// <summary>
/// The headless step-up flow shared by every integration: start → show the step in
/// YOUR UI → check → complete exactly once.
/// </summary>
internal static class Steps
{
    private static readonly Dictionary<string, string> StateMap = new()
    {
        ["PENDING"] = "waiting", ["CONFIRMED"] = "approved", ["REJECTED"] = "rejected", ["EXPIRED"] = "expired",
    };

    public static async Task<Step> StartAsync(TouchQueClient client, string action, StartOptions o, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(o.User)) throw new TouchQueConfigException("StartAsync() needs the user id");
        var norm = TouchQue.Details.Normalize(o.Details);
        var details = norm.Count > 0 ? norm : null;
        try
        {
            var res = await client.Login.RequestAsync(new LoginRequestOptions
            {
                ExternalUsername = o.User,
                Type = action,
                ReferenceId = o.ReferenceId,
                ClientIp = o.Ip,
                UserAgent = o.UserAgent,
                Details = details,
                BrowserProof = o.BrowserProof,
                Context = o.Context,
            }, ct).ConfigureAwait(false);
            var reasons = res.Reasons is { Count: > 0 } ? res.Reasons.Select(r => new RiskReason { Code = r.Code, Text = r.Text }).ToList() : null;
            var canary = string.IsNullOrEmpty(res.Canary?.Url) ? null : new Canary { Url = res.Canary!.Url };
            var caseCode = string.IsNullOrEmpty(res.CaseCode) ? null : res.CaseCode;
            if (res.RequiresPasskey)
            {
                return new Step { State = "passkey_required", RequestId = res.RequestId, ExpiresAt = res.ExpiresAt, Details = details, CaseCode = caseCode, Reasons = reasons, Canary = canary };
            }
            return new Step
            {
                State = "waiting",
                RequestId = res.RequestId,
                Number = string.IsNullOrEmpty(res.ChallengeCode) ? null : res.ChallengeCode,
                ExpiresAt = res.ExpiresAt,
                Details = details,
                CaseCode = caseCode,
                Reasons = reasons,
                // Only when the workspace collects behavioural signals.
                TelemetryToken = string.IsNullOrEmpty(res.TelemetryToken) ? null : res.TelemetryToken,
                // Mirror Alarm: only on this first step.
                Canary = canary,
            };
        }
        catch (TouchQueApiException e)
        {
            var code = e.Code ?? e.Error;
            var caseCode = e.CaseCode;
            if (e.Status == 404 && (code == "device_not_linked" || e.Message.Contains("linked device", StringComparison.OrdinalIgnoreCase)))
            {
                return o.Enroll ? await EnrollStepAsync(client, o.User, ct).ConfigureAwait(false) : new Step { State = "enroll" };
            }
            if (e.Status == 423) return new Step { State = "frozen", RetryAfter = e.RetryAfter, CaseCode = caseCode };
            if (e.Status == 429) return new Step { State = "rate_limited", RetryAfter = e.RetryAfter, CaseCode = caseCode };
            if (e.Status == 400 && (code == "unknown_action" || e.Message.Contains("invalid action type", StringComparison.OrdinalIgnoreCase)))
            {
                throw new TouchQueConfigException($"Unknown action \"{action}\". Create it once with client.ActionTypes.DefineAsync(\"{action}\") or in the dashboard (Action Types).");
            }
            if (e.Status == 403)
            {
                var reason = (code == "blocked" ? e.Reason : null)
                    ?? (code == "passkey_not_registered" || e.Error == "phishing_resistant_required" ? "passkey_not_registered" : null)
                    ?? (code == "action_disabled" ? "action_disabled" : null)
                    ?? code ?? "blocked";
                return new Step { State = "blocked", Reason = reason, CaseCode = caseCode };
            }
            throw;
        }
    }

    /// <summary>First-time linking. Never unlinks a phone: a secret is only re-issued when the account is confirmed NOT linked.</summary>
    private static async Task<Step> EnrollStepAsync(TouchQueClient client, string user, CancellationToken ct)
    {
        try
        {
            var gen = await client.Auth.GenerateSecretAsync(user, ct).ConfigureAwait(false);
            return new Step { State = "enroll", Enroll = new StepEnroll { QrCodeDataUrl = gen.QrCodeDataUrl, RecoveryCodes = gen.RecoveryCodes, ExpiresAt = gen.ExpiresAt } };
        }
        catch (TouchQueApiException e) when (e.Status == 409)
        {
            TouchQueUser? current = null;
            try
            {
                current = await client.Auth.GetUserAsync(user, ct).ConfigureAwait(false);
            }
            catch (TouchQueApiException)
            {
                // unknown user: reset below
            }
            if (current is not null && (current.Used || !string.IsNullOrEmpty(current.DeviceId)))
            {
                return new Step { State = "enroll", Reason = "already_linked" };
            }
            var reset = await client.Auth.ResetSecretAsync(user, ct).ConfigureAwait(false);
            return new Step { State = "enroll", Enroll = new StepEnroll { QrCodeDataUrl = reset.QrCodeDataUrl, RecoveryCodes = reset.RecoveryCodes, ExpiresAt = reset.ExpiresAt } };
        }
    }

    public static async Task<Step> CheckAsync(TouchQueClient client, string requestId, CancellationToken ct)
    {
        var s = await client.Login.StatusAsync(requestId, ct).ConfigureAwait(false);
        var state = s.Status == "PENDING" && s.RequiresPasskey ? "passkey_required" : StateMap.GetValueOrDefault(s.Status, "waiting");
        return new Step { State = state, RequestId = requestId, Assurance = state == "approved" ? s.Assurance : null };
    }

    public static async Task<Approval> CompleteAsync(TouchQueClient client, string requestId, CompleteExpectations expect, CancellationToken ct)
    {
        var res = await client.Login.ConsumeAsync(requestId, ct).ConfigureAwait(false);
        var sameUser = string.Equals(res.ExternalUsername, expect.User, StringComparison.OrdinalIgnoreCase);
        var sameDetails = TouchQue.Details.Digest(expect.Details) == TouchQue.Details.Digest(res.Details);
        // An empty reference is no reference: StartAsync does not send one, so Touchque keeps null.
        var sameRef = (string.IsNullOrEmpty(res.ReferenceId) ? null : res.ReferenceId) == (string.IsNullOrEmpty(expect.ReferenceId) ? null : expect.ReferenceId);
        if (!sameUser || res.Type != expect.Action || !sameDetails || !sameRef)
        {
            throw new TouchQueApprovalMismatchException("this approval is for a different user, action or transaction.");
        }
        return new Approval
        {
            RequestId = requestId,
            User = res.ExternalUsername,
            Action = res.Type,
            Assurance = res.Assurance,
            ConfirmedVia = res.ConfirmedVia,
            ApprovalProof = res.ApprovalProof,
            Provisional = res.Provisional,
            Revoked = res.Provisional is null ? null : res.Revoked,
            RevokeReason = res.RevokeReason,
            ReconfirmedAt = res.ReconfirmedAt,
        };
    }

    // ── Guard token ─────────────────────────────────────────────────────────
    // The browser echoes it back while it waits. Signed with a key derived from the
    // API secret, it binds the approval to one user, action and transaction.

    private static byte[] TokenKey(string apiSecret)
    {
        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(apiSecret));
        return h.ComputeHash(Encoding.UTF8.GetBytes("touchque-guard-token-v1"));
    }

    public static string SignGuardToken(string apiSecret, JsonObject claims)
    {
        var body = Base64Url.Encode(claims.ToJsonString(Json.Options));
        using var h = new HMACSHA256(TokenKey(apiSecret));
        return "v1." + body + "." + Base64Url.Encode(h.ComputeHash(Encoding.ASCII.GetBytes(body)));
    }

    public static JsonObject? VerifyGuardToken(string apiSecret, string? token)
    {
        if (string.IsNullOrEmpty(token) || token.Length > 4096) return null;
        var parts = token.Split('.');
        if (parts.Length != 3 || parts[0] != "v1") return null;
        using var h = new HMACSHA256(TokenKey(apiSecret));
        var expected = Base64Url.Encode(h.ComputeHash(Encoding.ASCII.GetBytes(parts[1])));
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(parts[2]))) return null;
        if (!Base64Url.TryDecode(parts[1], out var bytes)) return null;
        var claims = Json.Parse(Encoding.UTF8.GetString(bytes)) as JsonObject;
        var exp = Json.Long(claims, "exp");
        if (claims is null || exp is null || exp.Value < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) return null;
        return claims;
    }
}

/// <summary>Step serialization for the browser: the API's camelCase, nulls left out.</summary>
internal static class StepJson
{
    public static JsonNode? ToJson(Step step) => Json.ToNode(step);
}
