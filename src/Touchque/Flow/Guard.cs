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

    /// <summary>
    /// Called at most once, only for the token of a first-time QR (<c>enroll</c> with its expiry),
    /// right before the guard starts something instead of answering "keep the QR": a silent check
    /// or a push once the phone is linked, or a new QR once the old one expired, is about to, or is
    /// gone. A result is answered as it is and nothing starts. Relays charge the start here like a
    /// fresh attempt, so a status poll never starts anything on the poll budget.
    /// </summary>
    public Func<Task<GuardResult?>>? BeforeStart { get; init; }
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

    /// <summary>
    /// The headers of a refused answer (status 400 or more): <c>X-Touchque-State</c>, and
    /// <c>X-Touchque-Reason</c> when the step has a reason; none otherwise. <c>@touchque/web</c>
    /// reads the step from them when a body has no <c>touchque</c> (an ErrorBody's string, say).
    /// </summary>
    public IReadOnlyDictionary<string, string> RefusalHeaders
    {
        get
        {
            var headers = new Dictionary<string, string>();
            if (Status < 400 || string.IsNullOrEmpty(Step?.State)) return headers;
            headers[Guard.StateHeader] = Step.State;
            if (!string.IsNullOrEmpty(Step.Reason)) headers[Guard.ReasonHeader] = Step.Reason;
            return headers;
        }
    }
}

/// <summary>A refused answer (status 400 or more), as an adapter's <c>ErrorBody</c> callback sees it.</summary>
public sealed record GuardRefusal
{
    public int Status { get; init; }
    /// <summary><c>error.code</c> when the guard set one, else the step's reason, else its state.</summary>
    public string Code { get; init; } = "";
    /// <summary><c>error.message</c> when set, else a sentence for the state.</summary>
    public string Message { get; init; } = "";
    /// <summary>The step as it would be sent (<c>touchque</c>).</summary>
    public JsonObject Touchque { get; init; } = new();

    /// <summary>The refusal in a guard's answer, or null for a 202 step or an approval.</summary>
    public static GuardRefusal? From(GuardResult result)
    {
        if (result.Approved is not null || result.Status < 400 || result.Body is null) return null;
        var step = result.Body["touchque"] as JsonObject;
        var error = result.Body["error"];
        var state = Json.Str(step, "state");
        var code = Json.Str(error, "code");
        if (string.IsNullOrEmpty(code)) code = Json.Str(step, "reason");
        if (string.IsNullOrEmpty(code)) code = state;
        var message = Json.Str(error, "message");
        if (string.IsNullOrEmpty(message))
        {
            message = state switch
            {
                "rejected" => "The approval was rejected.",
                "expired" => "The approval expired. Try again.",
                "frozen" => "Too many rejected approvals. Try again later.",
                "rate_limited" => "Too many attempts. Try again later.",
                _ => "The approval was refused.",
            };
        }
        return new GuardRefusal { Status = result.Status, Code = code ?? "", Message = message, Touchque = (step?.DeepClone() as JsonObject) ?? new JsonObject() };
    }
}

/// <summary>
/// Framework-agnostic step-up guard (ASP.NET Core's <c>RequireTouchque</c> is a thin
/// wrapper over it). Contract, the same in every Touchque server SDK:
/// <list type="bullet">
/// <item>1st request → 202 <c>{"touchque": step, "token": ...}</c>: show the step in your UI;</item>
/// <item>repeat with the token (header <c>X-Touchque-Token</c>) → 202 while waiting, then the protected action runs once;</item>
/// <item>while the first-time linking QR is up → 202 <c>{"touchque": {"state": "enroll", "expiresAt": ...}}</c> without
/// <c>enroll</c>: keep showing that QR; a new one comes with <c>enroll.qrCodeDataUrl</c> once it expired;</item>
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
    /// <summary>On every refused answer (status 400 or more): the step's state.</summary>
    public const string StateHeader = "X-Touchque-State";
    /// <summary>On a refused answer whose step has a reason: that reason.</summary>
    public const string ReasonHeader = "X-Touchque-Reason";

    private const long TokenTtlMs = 10 * 60 * 1000;
    /// <summary>A first-time QR this close to its expiry is replaced instead of kept: the user could not scan it in time.</summary>
    private const long EnrollRenewMs = 15 * 1000;
    /// <summary>A real proof is a few hundred characters; anything far larger is not one.</summary>
    private const int MaxBrowserProof = 4096;

    private static readonly Dictionary<string, int> StatusOf = new()
    {
        ["waiting"] = 202, ["enroll"] = 202, ["passkey_required"] = 202, ["offline"] = 202,
        ["approved"] = 200, ["rejected"] = 403, ["blocked"] = 403, ["expired"] = 408, ["frozen"] = 423, ["rate_limited"] = 429,
    };

    private static readonly HashSet<string> Waiting = new() { "waiting", "passkey_required", "offline" };

    /// <summary>
    /// True when this request only reads a state: it polls an approval already on its way (a
    /// valid token bound to this user/action/details, still waiting) or a first-time linking
    /// QR still up (a bound <c>enroll</c> token whose QR expires in more than 15 s), with no
    /// offline switch or typed code. Relays do not count it against the per-user push limit. A
    /// start such a poll leads to (a push once the phone is linked, a new QR) goes through
    /// <see cref="GuardInput.BeforeStart"/>, where relays charge it like a fresh attempt: every
    /// start is counted.
    /// </summary>
    public static bool IsStatusPoll(TouchqueClient client, GuardInput input)
    {
        if (string.IsNullOrEmpty(input.User) || string.IsNullOrEmpty(input.Token) || input.Offline || !string.IsNullOrEmpty(input.Code)) return false;
        var claims = Steps.VerifyGuardToken(client.ApiSecret, input.Token);
        if (claims is null || !Bound(claims, input)) return false;
        var st = Json.Str(claims, "st");
        if (st == "enroll") return QrStillUp(Json.Long(claims, "ee"));
        return !string.IsNullOrEmpty(Json.Str(claims, "rid")) && Waiting.Contains(st ?? "");
    }

    /// <summary>A first-time QR that expires at <paramref name="ee"/> (ms since the epoch) can still be scanned: more than 15 s left.</summary>
    private static bool QrStillUp(long? ee) => ee is not null && DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() < ee - EnrollRenewMs;

    /// <summary>
    /// The guard's answer when no client can be built (TQ_API_KEY / TQ_API_SECRET missing): 401
    /// <c>unauthenticated</c> without a user, else 500 <c>misconfigured</c>. An adapter that
    /// builds its client on first use answers this instead of throwing.
    /// </summary>
    public static GuardResult WithoutClient(GuardInput input) => string.IsNullOrEmpty(input.User) ? Unauthenticated() : Misconfigured();

    private static bool Bound(JsonObject claims, GuardInput input) =>
        Json.Str(claims, "u") == input.User && Json.Str(claims, "a") == input.Action
        && Json.Str(claims, "d") == Details.Digest(input.Details) && Json.Str(claims, "r") == input.ReferenceId;

    /// <summary>
    /// Runs one step of the guard. Silent sign-ins: with <see cref="GuardInput.SilentSignIn"/>
    /// set, a new attempt that carries a browser proof first asks Touchque
    /// (<c>Risk.CheckAsync</c>); when it answers exactly <c>prompt: false</c> the guard
    /// approves at once with no push (<c>assurance.method</c> silent, <c>ConfirmedVia</c>
    /// SILENT, <c>RequestId</c> silent). Otherwise, and on any error, the usual push starts.
    /// First-time linking: a poll with the token of an <c>enroll</c> step only reads the link
    /// state (<c>Auth.GetUserAsync</c>). Not linked yet and the QR good for more than 15 s: 202
    /// <c>{"state": "enroll", "expiresAt": ...}</c> without <c>enroll</c>, so the page keeps its
    /// QR. Linked: the push starts. Expired or about to: a new QR.
    /// </summary>
    public static async Task<GuardResult> RunAsync(TouchqueClient client, GuardInput input, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(input.User)) return Unauthenticated();
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
            // A first-time QR: its polls keep it until it expires (ee, ms since the epoch).
            if (!string.IsNullOrEmpty(step.Enroll?.QrCodeDataUrl) && Steps.EpochMillis(step.Enroll.ExpiresAt) is { } qrExpiry) claims["ee"] = qrExpiry;
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

            // The first-time linking QR is up (its token carries the QR's expiry, ee): one QR per enrollment, not one per poll.
            if (st == "enroll" && Json.Long(bound, "ee") is { } ee)
            {
                TouchqueUser? current;
                try
                {
                    current = await client.Auth.GetUserAsync(user, ct).ConfigureAwait(false);
                }
                catch (TouchqueApiException e) when (e.Status == 404)
                {
                    current = null; // no such user: the QR is gone, a new one below
                }
                var linked = current is not null && (current.Used || !string.IsNullOrEmpty(current.DeviceId));
                if (current is not null && !linked && QrStillUp(ee))
                {
                    // Nothing changed for the user: the page keeps the QR and recovery codes it shows.
                    return Issue(new Step { State = "enroll", ExpiresAt = Steps.Iso(ee) }, new JsonObject { ["ee"] = ee });
                }
                // Linked: the push starts below. Not linked, and the QR expired or is about to: a new QR below.
                // Either way something starts: the caller may charge it, or answer instead.
                if (input.BeforeStart is not null && await input.BeforeStart().ConfigureAwait(false) is { } instead) return instead;
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
            return Misconfigured();
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

    private static GuardResult Unauthenticated() =>
        Error(401, new Step { State = "blocked", Reason = "unauthenticated" }, "unauthenticated", "Sign in first.");

    private static GuardResult Misconfigured() =>
        Error(500, new Step { State = "blocked", Reason = "misconfigured" }, "misconfigured", "Two-factor approval is not configured correctly.");

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
