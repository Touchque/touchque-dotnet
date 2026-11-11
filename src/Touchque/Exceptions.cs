using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>Base class of every exception the Touchque SDK throws.</summary>
public class TouchqueException : Exception
{
    public TouchqueException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// The API answered with an error (status 400 or more). <see cref="Status"/> is
/// the HTTP status, <see cref="Code"/> the machine-readable code
/// (<c>device_not_linked</c>, <c>unknown_action</c>, <c>already_used</c>…) and
/// <see cref="Body"/> the decoded JSON body.
/// </summary>
public class TouchqueApiException : TouchqueException
{
    public TouchqueApiException(int status, JsonObject? data, string? message = null)
        : base(message ?? Json.Str(data, "message") ?? Json.Str(data, "error") ?? $"Touchque API error: HTTP {status}")
    {
        Status = status;
        Body = data ?? new JsonObject();
    }

    /// <summary>HTTP status code (404, 409, 423, 429…).</summary>
    public int Status { get; }

    /// <summary>The decoded JSON body of the error.</summary>
    public JsonObject Body { get; }

    /// <summary>Machine-readable error code, e.g. <c>device_not_linked</c>.</summary>
    public string? Code => Json.Str(Body, "code");

    /// <summary>The API's <c>error</c> field.</summary>
    public string? Error => Json.Str(Body, "error");

    /// <summary>Why a request was refused (offline codes, blocked requests).</summary>
    public string? Reason => Json.Str(Body, "reason");

    /// <summary>Offline sign: wrong codes left before the challenge locks.</summary>
    public int? AttemptsLeft => Json.Int(Body, "attemptsLeft");

    /// <summary>Seconds to wait before retrying (429 / 423), from the body or the Retry-After header.</summary>
    public int? RetryAfter => Json.Int(Body, "retryAfter");

    /// <summary>
    /// "Why?" case code of a refusal (<c>K7P-2QX</c>): show it to the user ("Tell
    /// your support team: K7P-2QX"); your team opens the decision by it in the
    /// dashboard. Null for other errors.
    /// </summary>
    public string? CaseCode => Json.Str(Body, "caseCode");

    /// <summary>Where to send the person instead (help desk: <c>never_locked_out</c>).</summary>
    public string? Route => Json.Str(Body, "route");

    /// <summary>
    /// The exception for an error answer: a <see cref="TouchqueFeatureException"/>
    /// subclass for the three feature codes, else a <see cref="TouchqueApiException"/>.
    /// </summary>
    public static TouchqueApiException For(int status, JsonObject? data, string? message = null) => Json.Str(data, "error") switch
    {
        "feature_not_in_plan" => new TouchqueFeatureNotInPlanException(status, data, message),
        "feature_read_only" => new TouchqueFeatureReadOnlyException(status, data, message),
        "feature_off" => new TouchqueFeatureOffException(status, data, message),
        _ => new TouchqueApiException(status, data, message),
    };
}

/// <summary>Why a feature cannot be used here (<see cref="TouchqueFeatureException.FeatureReason"/>).</summary>
public enum FeatureRefusal
{
    /// <summary><c>feature_not_in_plan</c>: not in the organization's plan; an owner or admin adds it in the Touchque dashboard.</summary>
    NotInPlan,
    /// <summary><c>feature_read_only</c>: being turned off; reads still work for 14 days, changes are refused.</summary>
    ReadOnly,
    /// <summary><c>feature_off</c>: switched off on this Touchque deployment.</summary>
    Off,
}

/// <summary>
/// The organization behind your workspace cannot use this feature here (HTTP
/// 403). <see cref="Feature"/> is the catalog id (<c>device_risk</c>,
/// <c>ai_agents</c>, <c>mobile_sdk</c>, <c>ciam</c>…). A
/// <see cref="TouchqueApiException"/>, so existing <c>catch</c> blocks still see
/// it; catch one of the three subclasses to tell them apart.
/// </summary>
public abstract class TouchqueFeatureException : TouchqueApiException
{
    protected TouchqueFeatureException(int status, JsonObject? data, string? message, FeatureRefusal reason)
        : base(status, data, message) => FeatureReason = reason;

    /// <summary>The catalog id of the feature, or null.</summary>
    public string? Feature => Json.Str(Body, "feature");

    /// <summary>Not in the plan, being turned off (read-only), or switched off on this deployment.</summary>
    public FeatureRefusal FeatureReason { get; }
}

/// <summary><c>feature_not_in_plan</c>: the feature is not in the organization's plan.</summary>
public class TouchqueFeatureNotInPlanException : TouchqueFeatureException
{
    public TouchqueFeatureNotInPlanException(int status, JsonObject? data, string? message = null) : base(status, data, message, FeatureRefusal.NotInPlan) { }
}

/// <summary><c>feature_read_only</c>: the feature is being turned off; reads work, changes are refused.</summary>
public class TouchqueFeatureReadOnlyException : TouchqueFeatureException
{
    public TouchqueFeatureReadOnlyException(int status, JsonObject? data, string? message = null) : base(status, data, message, FeatureRefusal.ReadOnly) { }
}

/// <summary><c>feature_off</c>: the feature is switched off on this Touchque deployment.</summary>
public class TouchqueFeatureOffException : TouchqueFeatureException
{
    public TouchqueFeatureOffException(int status, JsonObject? data, string? message = null) : base(status, data, message, FeatureRefusal.Off) { }
}

/// <summary>
/// The request never reached Touchque (DNS, connection refused, timeout). Unlike
/// <see cref="TouchqueApiException"/>, generally safe to retry.
/// </summary>
public class TouchqueNetworkException : TouchqueException
{
    public TouchqueNetworkException(string message, Exception? inner = null) : base($"Touchque: network request failed: {message}", inner) { }
}

/// <summary>The user did not answer in time, or the request expired.</summary>
public class TouchqueTimeoutException : TouchqueException
{
    public TouchqueTimeoutException(string message, string? requestId = null) : base(message) => RequestId = requestId;

    public string? RequestId { get; }
}

/// <summary>The user rejected the request on their phone.</summary>
public class TouchqueRejectedException : TouchqueException
{
    public TouchqueRejectedException(string requestId) : base($"Touchque: request '{requestId}' was rejected by the user.") => RequestId = requestId;

    public string RequestId { get; }
}

/// <summary>A webhook is not from Touchque, was changed, or is too old.</summary>
public class TouchqueWebhookSignatureException : TouchqueException
{
    public TouchqueWebhookSignatureException(string message) : base($"Touchque: webhook rejected: {message}") { }
}

/// <summary>
/// A correctly signed webhook with this <c>jti</c> was already accepted. Usually
/// a Touchque retry of a delivery you processed: answer 200 so it stops, but do
/// not run your side effects again. Extends the signature exception, so existing
/// catch blocks still reject it.
/// </summary>
public class TouchqueWebhookReplayException : TouchqueWebhookSignatureException
{
    public TouchqueWebhookReplayException(string jti) : base("this webhook (jti) was already accepted") => Jti = jti;

    public string Jti { get; }
}

/// <summary>Missing or invalid configuration, an undefined action type, or a wrong argument.</summary>
public class TouchqueConfigException : TouchqueException
{
    public TouchqueConfigException(string message) : base($"Touchque config error: {message}") { }
}

/// <summary>
/// This request must be approved with a passkey. <see cref="Reason"/> is
/// <c>policy</c> when a phishing-resistant policy requires it (no push was sent),
/// or <c>step_up</c> when the user tapped Approve on the phone during a call
/// (Vishing Shield) and the request, still open, now waits for a passkey in the browser.
/// </summary>
public class TouchquePasskeyRequiredException : TouchqueException
{
    public TouchquePasskeyRequiredException(string requestId, string reason = "policy")
        : base(reason == "step_up"
            ? $"Touchque: request '{requestId}' must now be approved with a passkey: the user approved on the phone during a call."
            : $"Touchque: request '{requestId}' must be approved with a passkey (phishing-resistant policy); no push was sent.")
    {
        RequestId = requestId;
        Reason = reason;
    }

    public string RequestId { get; }

    /// <summary><c>policy</c> or <c>step_up</c>.</summary>
    public string Reason { get; }
}

/// <summary>
/// An AI agent's approval ended without a usable approval: <see cref="Status"/>
/// is rejected, blocked, revoked, expired, stale (approved too long ago) or
/// redeemed (already used).
/// </summary>
public class TouchqueApprovalException : TouchqueException
{
    public TouchqueApprovalException(string approvalId, string status, string? reason = null)
        : base($"Touchque: approval '{approvalId}' is {status}" + (reason is null ? "." : $" ({reason})."))
    {
        ApprovalId = approvalId;
        Status = status;
        Reason = reason;
    }

    public string ApprovalId { get; }
    public string Status { get; }
    public string? Reason { get; }
}

/// <summary>
/// An approval token (or a consumed approval) does not say what you are about to
/// execute (another person, action type, amount, recipient…), or it is not a
/// valid token from Touchque. Do not execute.
/// </summary>
public class TouchqueApprovalMismatchException : TouchqueException
{
    public TouchqueApprovalMismatchException(string message) : base($"Touchque: {message}") { }
}

/// <summary>
/// <see cref="McpAuth"/> refused a request: answer with <see cref="Status"/> (401,
/// 403) and the <c>WWW-Authenticate</c> header in <see cref="WwwAuthenticate"/>.
/// <see cref="Error"/> is missing_token, invalid_token, invalid_dpop_proof or insufficient_scope.
/// </summary>
public class TouchqueMcpAuthException : TouchqueException
{
    public TouchqueMcpAuthException(int status, string error, string message, string wwwAuthenticate) : base(message)
    {
        Status = status;
        Error = error;
        WwwAuthenticate = wwwAuthenticate;
    }

    public int Status { get; }
    public string Error { get; }
    public string WwwAuthenticate { get; }
}
