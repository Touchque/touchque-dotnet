using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>
/// Storage for webhook <c>jti</c>s already accepted. <see cref="CheckAndSetAsync"/> must
/// atomically record the jti for the TTL and return true when it was NOT seen
/// before. Use <see cref="MemoryReplayCache"/> for one process, or implement it over
/// Redis (<c>SET key 1 NX EX ttl</c>) or your database when you run several instances.
/// </summary>
public interface IWebhookReplayCache
{
    ValueTask<bool> CheckAndSetAsync(string jti, TimeSpan ttl, CancellationToken ct = default);
}

/// <summary>An in-process <see cref="IWebhookReplayCache"/>: entries expire after their TTL; the map is capped.</summary>
public sealed class MemoryReplayCache : IWebhookReplayCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new();
    private readonly int _maxEntries;
    private readonly object _gate = new();

    public MemoryReplayCache(int maxEntries = 100_000) => _maxEntries = Math.Max(2, maxEntries);

    public ValueTask<bool> CheckAndSetAsync(string jti, TimeSpan ttl, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (_seen.TryGetValue(jti, out var exp) && exp > now) return ValueTask.FromResult(false);
            if (_seen.Count >= _maxEntries)
            {
                foreach (var (k, v) in _seen)
                {
                    if (v <= now) _seen.TryRemove(k, out _);
                }
                foreach (var k in _seen.Keys.Take(Math.Max(0, _seen.Count - _maxEntries * 9 / 10)).ToList()) _seen.TryRemove(k, out _);
            }
            _seen[jti] = now + ttl;
            return ValueTask.FromResult(true);
        }
    }
}

/// <summary>Webhook signature verification (signed with your API secret).</summary>
public sealed class WebhookResource
{
    /// <summary>Default replay window: a callback whose signed timestamp is further than this from now is rejected.</summary>
    public const int DefaultToleranceSeconds = 300;

    // reason values of a REJECTED login webhook. Treat a value you do not know as a rejection.
    public const string ReasonUserRejected = "user_rejected";
    /// <summary>The user said "this wasn't me": 2FA is frozen.</summary>
    public const string ReasonUserReportedFraud = "user_reported_fraud";
    /// <summary>The user said someone on the phone told them to approve: 2FA is frozen; treat it as a takeover in progress.</summary>
    public const string ReasonUserReportedCoached = "user_reported_coached";
    /// <summary>An AI agent's request: the user said no and blocked the agent from asking them again (no 2FA freeze).</summary>
    public const string ReasonUserBlockedAgent = "user_blocked_agent";
    public const string ReasonRiskReversed = "risk_reversed";
    public const string ReasonRiskStepUp = "risk_step_up";
    public const string ReasonApprovalSignatureInvalid = "approval_signature_invalid";
    public const string ReasonDeviceIntegrityFailed = "device_integrity_failed";
    /// <summary>Vishing Shield: approved during a call (or with the screen shared / remote-controlled), critical, no passkey.</summary>
    public const string ReasonVishingSuspected = "vishing_suspected";
    /// <summary>Mirror Alarm: the sign-in page was not on your site (a real-time phishing proxy).</summary>
    public const string ReasonPhishingOrigin = "phishing_origin";

    // event values of event webhooks. Ignore types you do not know.
    public const string EventDeviceLinked = "DEVICE_LINKED";
    public const string EventDeviceUnlinked = "DEVICE_UNLINKED";
    public const string EventPasskeyRegistered = "PASSKEY_REGISTERED";
    public const string EventPasskeyDeleted = "PASSKEY_DELETED";
    /// <summary>Device risk: an identification or a DeviceRisk.CheckAsync raised a signal that asks for more. Never a trait.</summary>
    public const string EventDeviceRiskSignal = "DEVICE_RISK_SIGNAL";
    /// <summary>Device risk: an alert rule of the workspace went off.</summary>
    public const string EventDeviceRiskAlert = "DEVICE_RISK_ALERT";
    /// <summary>After the call, the user confirmed a provisional approval was theirs: critical actions are allowed again.</summary>
    public const string EventApprovalReconfirmed = "APPROVAL_RECONFIRMED";
    /// <summary>The user took an approval back (reason COACHED or UNDO): end the session built on it.</summary>
    public const string EventApprovalRevoked = "APPROVAL_REVOKED";
    /// <summary>Mobile SDK: send this push with your own keys (<see cref="MobileResource.PushFromWebhook"/>).</summary>
    public const string EventMobilePush = "MOBILE_PUSH";
    /// <summary>Never Locked Out: a recovery started (<see cref="RecoveryResource.StartAsync"/>).</summary>
    public const string EventRecoveryStarted = "RECOVERY_STARTED";
    /// <summary>The new phone was bound to the recovery.</summary>
    public const string EventRecoveryDeviceBound = "RECOVERY_DEVICE_BOUND";
    /// <summary>Enough vouchers approved: the cooling-off runs until <c>coolOffUntil</c> and the recovery can still be vetoed.</summary>
    public const string EventRecoveryCooling = "RECOVERY_COOLING";
    /// <summary>The account moved to the new phone (<c>method</c> vouch or old_phone; DEVICE_LINKED follows). By vouch, critical actions are refused until <c>probationUntil</c>.</summary>
    public const string EventRecoveryCompleted = "RECOVERY_COMPLETED";
    /// <summary>The recovery was stopped (<c>reason</c>, <c>by</c>): by an admin, or a "no" from the old phone or a voucher, which also freezes 2FA.</summary>
    public const string EventRecoveryVetoed = "RECOVERY_VETOED";
    /// <summary>The recovery ended without a move: the new phone was never bound, or a new recovery replaced it.</summary>
    public const string EventRecoveryExpired = "RECOVERY_EXPIRED";
    /// <summary>The recovery ended without a move: not enough approvals, the new phone's key changed, or the account is gone.</summary>
    public const string EventRecoveryFailed = "RECOVERY_FAILED";
    /// <summary>Help desk: IT started working on a person's account (<see cref="AssistResource.OpenAsync"/>).</summary>
    public const string EventAssistOpened = "ASSIST_OPENED";
    /// <summary>The assist session ended (<c>reason</c>).</summary>
    public const string EventAssistEnded = "ASSIST_ENDED";
    /// <summary>The person typed the agent's code on their phone: the check passed (<c>requestId</c>, <c>action</c>, <c>caseCode</c>).</summary>
    public const string EventAssistCheckPassed = "ASSIST_CHECK_PASSED";
    /// <summary>A check failed (<c>outcome</c> wrong_number, not_me, coached or declined): page someone.</summary>
    public const string EventAssistCheckFailed = "ASSIST_CHECK_FAILED";
    /// <summary>The help desk lifted the person's approval freeze after a passed check.</summary>
    public const string EventAssistUnfrozen = "ASSIST_UNFROZEN";
    /// <summary>The person checked on their phone that the agent working on their account is real.</summary>
    public const string EventAssistClaimConfirmed = "ASSIST_CLAIM_CONFIRMED";
    /// <summary>Nobody from IT was working on the account when the person asked: someone is pretending to be IT. No <c>assistId</c>; page someone.</summary>
    public const string EventAssistClaimUnverified = "ASSIST_CLAIM_UNVERIFIED";
    /// <summary>An AI agent was registered.</summary>
    public const string EventAgentCreated = "AGENT_CREATED";
    /// <summary>An AI agent was suspended (through the API or the dashboard): its tokens stopped working.</summary>
    public const string EventAgentSuspended = "AGENT_SUSPENDED";
    /// <summary>An AI agent may act again.</summary>
    public const string EventAgentResumed = "AGENT_RESUMED";
    /// <summary>An AI agent was revoked for good.</summary>
    public const string EventAgentRevoked = "AGENT_REVOKED";
    /// <summary>A key was added to an AI agent.</summary>
    public const string EventAgentKeyAdded = "AGENT_KEY_ADDED";
    /// <summary>A key was removed from an AI agent; tokens bound to it stopped working.</summary>
    public const string EventAgentKeyRemoved = "AGENT_KEY_REMOVED";
    /// <summary>The kill switch stopped every AI agent of the workspace.</summary>
    public const string EventAgentsPaused = "AGENTS_PAUSED";
    /// <summary>The kill switch was turned off.</summary>
    public const string EventAgentsResumed = "AGENTS_RESUMED";
    /// <summary>An AI agent's policy changed.</summary>
    public const string EventAgentPolicyChanged = "AGENT_POLICY_CHANGED";
    /// <summary>The workspace's agent policy (every agent's floor) changed.</summary>
    public const string EventAgentWorkspacePolicyChanged = "AGENT_WORKSPACE_POLICY_CHANGED";
    /// <summary>An approval token was used.</summary>
    public const string EventAgentApprovalRedeemed = "AGENT_APPROVAL_REDEEMED";
    /// <summary>A person stopped an AI agent from asking them ("this wasn't me", coached, or three rejections).</summary>
    public const string EventAgentBlockedByPerson = "AGENT_BLOCKED_BY_PERSON";
    /// <summary>An admin let an AI agent ask a person again.</summary>
    public const string EventAgentUnblockedForPerson = "AGENT_UNBLOCKED_FOR_PERSON";
    /// <summary>An AI agent sent the same request to the same person three times in 10 minutes.</summary>
    public const string EventAgentLoopDetected = "AGENT_LOOP_DETECTED";
    /// <summary>An AI agent asked a person for a mandate.</summary>
    public const string EventAgentMandateRequested = "AGENT_MANDATE_REQUESTED";
    /// <summary>A mandate was ended.</summary>
    public const string EventAgentMandateRevoked = "AGENT_MANDATE_REVOKED";
    /// <summary>An AI agent's text carried an instruction to the model or a link that carries data; the request was refused.</summary>
    public const string EventAgentInjectionSuspected = "AGENT_INJECTION_SUSPECTED";
    /// <summary>An approval came back sooner than a person can answer; it is never usable.</summary>
    public const string EventAgentInhumanApproval = "AGENT_INHUMAN_APPROVAL";
    /// <summary>A new or renamed AI agent's name read like another agent's; it was refused.</summary>
    public const string EventAgentLookalikeName = "AGENT_LOOKALIKE_NAME";

    private readonly string _secret;

    internal WebhookResource(string apiSecret) => _secret = apiSecret;

    /// <summary>
    /// Verifies an incoming webhook and returns its payload.
    /// </summary>
    /// <param name="rawBody">The raw request body, exactly as received.</param>
    /// <param name="signature">The <c>x-signature</c> header; null uses the <c>signature</c> field inside the body.</param>
    /// <param name="toleranceSeconds">Reject a callback whose signed timestamp is missing, invalid or further than this from now; 0 disables the check.</param>
    /// <param name="replayCache">When set, a second delivery of the same jti throws <see cref="TouchQueWebhookReplayException"/>.</param>
    /// <exception cref="TouchQueWebhookSignatureException">Not from TouchQue, changed, or too old.</exception>
    public async Task<JsonObject> VerifyAsync(string rawBody, string? signature = null, int toleranceSeconds = DefaultToleranceSeconds, IWebhookReplayCache? replayCache = null, CancellationToken ct = default)
    {
        var payload = Verify(rawBody, signature, toleranceSeconds);
        if (replayCache is not null)
        {
            var jti = Json.Str(payload, "jti");
            if (string.IsNullOrEmpty(jti)) throw new TouchQueWebhookSignatureException("jti is missing");
            // Remember it for twice the window so it outlives any timestamp that could still pass the freshness check.
            var ttl = TimeSpan.FromSeconds(Math.Max(toleranceSeconds * 2, 600));
            if (!await replayCache.CheckAndSetAsync(jti, ttl, ct).ConfigureAwait(false)) throw new TouchQueWebhookReplayException(jti);
        }
        return payload;
    }

    /// <summary>Verifies the signature and the freshness of a webhook (no replay cache) and returns its payload.</summary>
    public JsonObject Verify(string rawBody, string? signature = null, int toleranceSeconds = DefaultToleranceSeconds)
    {
        JsonObject payload;
        try
        {
            payload = JsonNode.Parse(rawBody) as JsonObject ?? throw new TouchQueWebhookSignatureException("invalid JSON payload");
        }
        catch (JsonException)
        {
            throw new TouchQueWebhookSignatureException("invalid JSON payload");
        }
        var provided = string.IsNullOrEmpty(signature) ? Json.Str(payload, "signature") : signature;
        if (string.IsNullOrEmpty(provided)) throw new TouchQueWebhookSignatureException("no signature provided");

        string canonical;
        try
        {
            canonical = Canonicalize(rawBody);
        }
        catch (JsonException)
        {
            throw new TouchQueWebhookSignatureException("could not canonicalize the payload");
        }
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_secret));
        var expected = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        // Never put the expected signature in the exception: it would be a signing oracle.
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(provided)))
        {
            throw new TouchQueWebhookSignatureException("invalid signature");
        }
        // TouchQue always signs a timestamp: a missing or unparseable one fails closed.
        if (toleranceSeconds > 0)
        {
            var ts = Json.Str(payload, "timestamp");
            if (ts is null || !DateTimeOffset.TryParse(ts, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at))
            {
                throw new TouchQueWebhookSignatureException("timestamp is missing or invalid");
            }
            if (Math.Abs((DateTimeOffset.UtcNow - at).TotalSeconds) > toleranceSeconds)
            {
                throw new TouchQueWebhookSignatureException("timestamp is outside the allowed window");
            }
        }
        return payload;
    }

    /// <summary>
    /// The server's stableStringify: drop <c>signature</c>, sort the TOP-LEVEL keys only (by
    /// UTF-16 code units, like JavaScript), and keep each value's bytes (nested key order,
    /// number spelling); insignificant whitespace is removed.
    /// </summary>
    internal static string Canonicalize(string rawBody)
    {
        using var doc = JsonDocument.Parse(rawBody);
        if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException("not an object");
        var members = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var p in doc.RootElement.EnumerateObject())
        {
            if (p.Name == "signature") continue;
            members[p.Name] = Json.Compact(p.Value.GetRawText());
        }
        var sb = new StringBuilder("{");
        var first = true;
        foreach (var key in members.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            if (!first) sb.Append(',');
            first = false;
            sb.Append(Json.JsString(key)).Append(':').Append(members[key]);
        }
        return sb.Append('}').ToString();
    }
}
