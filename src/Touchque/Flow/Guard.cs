using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>Silent sign-ins for a guard or relay: off by default.</summary>
public sealed record SilentSignInOptions
{
    /// <summary>Your own limit on how long ago the last phone approval in that browser may be (0 = always ask).</summary>
    public int? MaxAgeSeconds { get; init; }
}

/// <summary>One request through the guard.</summary>
public sealed record GuardInput
{
    /// <summary>The signed-in user (null answers 401).</summary>
    public string? User { get; init; }
    public required string Action { get; init; }
    public IReadOnlyList<LoginDetail>? Details { get; init; }
    public string? ReferenceId { get; init; }
    /// <summary>The end user's IP.</summary>
    public string? Ip { get; init; }
    public string? UserAgent { get; init; }
    /// <summary><c>X-Touchque-Token</c>: the token from the last answer.</summary>
    public string? Token { get; init; }
    /// <summary><c>X-Touchque-Offline: 1</c>: switch to offline approval.</summary>
    public bool Offline { get; init; }
    /// <summary><c>X-Touchque-Code</c>: the code from the phone.</summary>
    public string? Code { get; init; }
    /// <summary><c>X-Touchque-Code-Type</c>: totp for the rolling time-based code.</summary>
    public string? CodeType { get; init; }
    /// <summary>False: never show the first-time linking QR.</summary>
    public bool Enroll { get; init; } = true;
    /// <summary><c>X-Touchque-Browser</c>: the browser's device-bound key proof.</summary>
    public string? BrowserProof { get; init; }
    /// <summary>Null: silent sign-ins off.</summary>
    public SilentSignInOptions? SilentSignIn { get; init; }
    /// <summary>For your Touchque Actions only (<c>event.context</c>).</summary>
    public IReadOnlyDictionary<string, object?>? Context { get; init; }
}

/// <summary>
/// The guard's answer: either <see cref="Approved"/> (run your protected action once)
/// or <see cref="Status"/> and <see cref="Body"/> to send back as JSON.
/// </summary>
public sealed record GuardResult
{
    public int Status { get; init; }
    public Approval? Approved { get; init; }
    /// <summary><c>{"touchque": step, "token": "..."}</c> or an error.</summary>
    public JsonObject? Body { get; init; }
    public Step? Step { get; init; }

    /// <summary>Seconds for a Retry-After header (frozen, rate limited).</summary>
    public int? RetryAfter => Step?.RetryAfter is > 0 ? Step.RetryAfter : null;
}

/// <summary>
/// Framework-agnostic step-up guard (ASP.NET Core's <c>RequireTouchque</c> is a thin
/// wrapper over it). Contract, the same in every Touchque server SDK:
/// <list type="bullet">
/// <item>1st request → 202 <c>{"touchque": step, "token": ...}</c>: show the step in your UI;</item>
/// <item>repeat with the token (header <c>X-Touchque-Token</c>) → 202 while waiting, then the protected action runs once;</item>
/// <item>refused → 403 / 408 / 423 / 429 <c>{"touchque": {"state": ...}}</c>.</item>
/// </list>
/// </summary>
public static class Guard
{
    public const string TokenHeader = "X-Touchque-Token";
    public const string OfflineHeader = "X-Touchque-Offline";
    public const string CodeHeader = "X-Touchque-Code";
    public const string CodeTypeHeader = "X-Touchque-Code-Type";
    public const string BrowserHeader = "X-Touchque-Browser";

    private const long TokenTtlMs = 10 * 60 * 1000;
    /// <summary>A real proof is a few hundred characters; anything far larger is not one.</summary>
    private const int MaxBrowserProof = 4096;

    private static readonly Dictionary<string, int> StatusOf = new()
    {
        ["waiting"] = 202, ["enroll"] = 202, ["passkey_required"] = 202, ["offline"] = 202,
        ["approved"] = 200, ["rejected"] = 403, ["blocked"] = 403, ["expired"] = 408, ["frozen"] = 423, ["rate_limited"] = 429,
    };

    private static readonly HashSet<string> Waiting = new() { "waiting", "passkey_required", "offline" };

    /// <summary>
    /// True when this request only polls an approval already on its way: a valid token
    /// bound to this user/action/details, still waiting, and no offline switch or typed
    /// code. It can only read the status, so relays do not count it against the
    /// per-user push limit.
    /// </summary>
    public static bool IsStatusPoll(TouchqueClient client, GuardInput input)
    {
        if (string.IsNullOrEmpty(input.User) || string.IsNullOrEmpty(input.Token) || input.Offline || !string.IsNullOrEmpty(input.Code)) return false;
        var claims = Steps.VerifyGuardToken(client.ApiSecret, input.Token);
        if (claims is null || string.IsNullOrEmpty(Json.Str(claims, "rid"))) return false;
        return Bound(claims, input) && Waiting.Contains(Json.Str(claims, "st") ?? "");
    }

    private static bool Bound(JsonObject claims, GuardInput input) =>
        Json.Str(claims, "u") == input.User && Json.Str(claims, "a") == input.Action
        && Json.Str(claims, "d") == Details.Digest(input.Details) && Json.Str(claims, "r") == input.ReferenceId;

    /// <summary>
    /// Runs one step of the guard. Silent sign-ins: with <see cref="GuardInput.SilentSignIn"/>
    /// set, a new attempt that carries a browser proof first asks Touchque
    /// (<c>Risk.CheckAsync</c>); when it answers exactly <c>prompt: false</c> the guard
    /// approves at once with no push (<c>assurance.method</c> silent, <c>ConfirmedVia</c>
    /// SILENT, <c>RequestId</c> silent). Otherwise, and on any error, the usual push starts.
    /// </summary>
    public static async Task<GuardResult> RunAsync(TouchqueClient client, GuardInput input, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(input.User))
        {
            return Error(401, new Step { State = "blocked", Reason = "unauthenticated" }, "unauthenticated", "Sign in first.");
        }
        var user = input.User;
        var action = input.Action;
        var norm = Details.Normalize(input.Details);
        var details = norm.Count > 0 ? norm : null;
        var secret = client.ApiSecret;

        GuardResult Issue(Step step, JsonObject? extra = null)
        {
            if (details is not null && step.Details is null && step.State != "blocked") step = step with { Details = details };
            var claims = new JsonObject
            {
                ["u"] = user, ["a"] = action, ["d"] = Details.Digest(input.Details), ["r"] = input.ReferenceId,
                ["st"] = step.State, ["rid"] = step.RequestId, ["n"] = step.Number, ["oc"] = step.Offline?.ChallengeId,
                ["exp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + TokenTtlMs,
            };
            if (step.CaseCode is not null) claims["cc"] = step.CaseCode;
            if (extra is not null)
            {
                foreach (var (k, v) in extra) claims[k] = v?.DeepClone();
            }
            var body = new JsonObject { ["touchque"] = Json.ToNode(step), ["token"] = Steps.SignGuardToken(secret, claims) };
            return new GuardResult { Status = StatusOf[step.State], Body = body, Step = step };
        }

        try
        {
            var claims = Steps.VerifyGuardToken(secret, input.Token);
            var bound = claims is not null && Bound(claims, input) ? claims : null;
            var rid = bound is null ? null : Json.Str(bound, "rid");
            var n = bound is null ? null : Json.Str(bound, "n");
            var oc = bound is null ? null : Json.Str(bound, "oc");
            var st = bound is null ? null : Json.Str(bound, "st");
            var keep = new JsonObject { ["oc"] = oc, ["rid"] = rid, ["n"] = n };

            // Offline: the user typed the code from the phone.
            if (bound is not null && !string.IsNullOrEmpty(input.Code) && (st == "offline" || input.CodeType == "totp"))
            {
                var isTotp = input.CodeType == "totp";
                var res = isTotp
                    ? await client.Offline.VerifyTotpAsync(user, input.Code, action, input.Ip, rid, ct).ConfigureAwait(false)
                    : await client.Offline.VerifyAsync(oc ?? "", input.Code, ct).ConfigureAwait(false);
                var forThis = (string.IsNullOrEmpty(res.ExternalUsername) || string.Equals(res.ExternalUsername, user, StringComparison.OrdinalIgnoreCase))
                    && (string.IsNullOrEmpty(res.Type) || res.Type == action);
                if (res.Approved && forThis)
                {
                    return new GuardResult
                    {
                        Status = 200,
                        Approved = new Approval
                        {
                            RequestId = oc ?? "offline-totp", User = user, Action = action,
                            Assurance = new Assurance { PhishingResistant = false, Method = isTotp ? "offline_totp" : "offline_code" },
                            ConfirmedVia = isTotp ? "OFFLINE_TOTP" : "OFFLINE_CODE",
                        },
                    };
                }
                if (res.Reason == "invalid_code" && !isTotp)
                {
                    return Issue(new Step { State = "offline", Offline = new StepOffline { ChallengeId = oc ?? "", AttemptsLeft = res.AttemptsLeft } }, keep);
                }
                if (res.Reason == "invalid_code") return Issue(new Step { State = "offline", Reason = "invalid_code" }, keep);
                // The phone rejected the push this QR belongs to: the whole sign-in is over.
                if (res.Reason == "request_rejected") return Issue(new Step { State = "rejected", RequestId = rid, Reason = "request_rejected" });
                // The push now waits for a passkey (Vishing Shield): no code may finish it.
                if (res.Reason == "passkey_required" && !string.IsNullOrEmpty(rid))
                {
                    return Issue(new Step { State = "passkey_required", RequestId = rid, Number = n }, new JsonObject { ["n"] = n });
                }
                return Issue(new Step { State = res.Reason == "expired" ? "expired" : "blocked", Reason = res.Reason ?? "offline_failed" });
            }

            if (input.Offline)
            {
                try
                {
                    // Tie the QR to the push it follows: a phone-side rejection kills it, and number matching carries over.
                    var ch = await client.Offline.ChallengeAsync(new OfflineChallengeOptions
                    {
                        ExternalUsername = user, Type = action, Details = details, ClientIp = input.Ip, UserAgent = input.UserAgent, RequestId = rid,
                    }, ct).ConfigureAwait(false);
                    var offline = new StepOffline
                    {
                        ChallengeId = ch.ChallengeId, QrDataUrl = ch.QrDataUrl, ExpiresAt = ch.ExpiresAt, TotpAvailable = ch.TotpAvailable,
                        ChallengeCode = string.IsNullOrEmpty(ch.ChallengeCode) ? null : ch.ChallengeCode,
                    };
                    return Issue(new Step { State = "offline", Offline = offline }, new JsonObject { ["rid"] = rid, ["n"] = offline.ChallengeCode ?? n });
                }
                catch (TouchqueApiException e)
                {
                    var code = e.Code ?? e.Error;
                    if (e.Status == 409 && code == "request_rejected") return Issue(new Step { State = "rejected", RequestId = rid, Reason = "request_rejected" });
                    // The push it would follow now waits for a passkey (Vishing Shield): no QR, run the passkey.
                    if (!string.IsNullOrEmpty(rid) && code == "passkey_required")
                    {
                        return Issue(new Step { State = "passkey_required", RequestId = rid, Number = n }, new JsonObject { ["n"] = n });
                    }
                    if (e.Status < 500) return Issue(new Step { State = "blocked", Reason = e.Code ?? e.Error ?? "offline_unavailable" });
                    throw;
                }
            }

            // Waiting on a push / passkey, or showing the offline QR next to a push still open: poll, run once approved.
            if (bound is not null && !string.IsNullOrEmpty(rid) && Waiting.Contains(st ?? ""))
            {
                var now = await Steps.CheckAsync(client, rid, ct).ConfigureAwait(false);
                if (now.State == "approved")
                {
                    try
                    {
                        var approval = await Steps.CompleteAsync(client, rid, new CompleteExpectations
                        {
                            User = user, Action = action, Details = input.Details, ReferenceId = input.ReferenceId,
                        }, ct).ConfigureAwait(false);
                        return new GuardResult { Status = 200, Approved = approval };
                    }
                    catch (TouchqueApiException e) when (e.Status == 409)
                    {
                        return Issue(new Step { State = "expired", Reason = e.Code ?? "already_used" });
                    }
                }
                // The push behind the QR moved to a passkey after a tap during a call: the QR's code would be refused now.
                if (st == "offline" && now.State == "passkey_required")
                {
                    return Issue(new Step { State = "passkey_required", RequestId = rid, Number = n }, new JsonObject { ["n"] = n });
                }
                if (st == "offline" && now.State is "waiting" or "expired")
                {
                    // Nothing changed for the user: keep showing the QR they have.
                    return Issue(new Step { State = "offline", Offline = new StepOffline { ChallengeId = oc ?? "" } }, keep);
                }
                if (now.State is "waiting" or "passkey_required")
                {
                    // "Why?": the case code stays on screen while it waits.
                    return Issue(new Step { State = now.State, RequestId = rid, Number = n, CaseCode = Json.Str(bound, "cc") }, new JsonObject { ["n"] = n });
                }
                return Issue(new Step { State = now.State, RequestId = rid });
            }

            // Anything else (no or foreign token, enrollment finished, new attempt): start.
            var proof = !string.IsNullOrEmpty(input.BrowserProof) && input.BrowserProof.Length <= MaxBrowserProof ? input.BrowserProof : null;
            if (proof is not null && input.SilentSignIn is not null)
            {
                var silent = await SilentApprovalAsync(client, input, proof, ct).ConfigureAwait(false);
                if (silent is not null) return new GuardResult { Status = 200, Approved = silent };
            }
            var step = await Steps.StartAsync(client, action, new StartOptions
            {
                User = user, Details = details, ReferenceId = input.ReferenceId, Ip = input.Ip, UserAgent = input.UserAgent,
                Enroll = input.Enroll, BrowserProof = proof, Context = input.Context,
            }, ct).ConfigureAwait(false);
            return Issue(step);
        }
        catch (TouchqueConfigException e)
        {
            client.Log.Error("[Touchque] " + e.Message);
            return Error(500, new Step { State = "blocked", Reason = "misconfigured" }, "misconfigured", "Two-factor approval is not configured correctly.");
        }
        // A mismatch here means Touchque holds another transaction than this request: fail closed, never a 500.
        catch (Exception e) when (e is TouchqueNetworkException or TouchqueApiException or TouchqueApprovalMismatchException)
        {
            client.Log.Error("[Touchque] approval failed: " + SdkLog.Describe(e));
            return Error(503, new Step { State = "blocked", Reason = "unavailable" }, "unavailable", "Two-factor approval is temporarily unavailable.");
        }
    }

    private static GuardResult Error(int status, Step step, string code, string message) => new()
    {
        Status = status,
        Step = step,
        Body = new JsonObject { ["touchque"] = Json.ToNode(step), ["error"] = new JsonObject { ["code"] = code, ["message"] = message } },
    };

    /// <summary>
    /// Asks Touchque whether this known browser may sign in without the phone. Fails
    /// closed: only an answer of exactly <c>prompt: false</c> approves.
    /// </summary>
    private static async Task<Approval?> SilentApprovalAsync(TouchqueClient client, GuardInput input, string proof, CancellationToken ct)
    {
        try
        {
            var res = await client.Risk.CheckAsync(new RiskCheckOptions
            {
                ExternalUsername = input.User!, Type = input.Action, ClientIp = input.Ip, UserAgent = input.UserAgent, BrowserProof = proof,
                Context = input.Context is { Count: > 0 } ? input.Context : null, MaxAgeSeconds = input.SilentSignIn?.MaxAgeSeconds,
            }, ct).ConfigureAwait(false);
            if (res.Prompt) return null;
            return new Approval
            {
                RequestId = "silent", User = input.User!, Action = input.Action,
                Assurance = new Assurance { PhishingResistant = false, Method = "silent" },
                ConfirmedVia = "SILENT",
                // Nothing was sent to the phone; why Touchque let this known browser in.
                Reasons = res.Reasons,
            };
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            client.Log.Warn("[Touchque] silent sign-in check failed, asking the phone: " + SdkLog.Describe(e));
            return null;
        }
    }
}
