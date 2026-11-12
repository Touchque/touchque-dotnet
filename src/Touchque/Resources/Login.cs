using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>Push approvals on the user's phone: request, status, wait, use once, report fraud.</summary>
public sealed class LoginResource
{
    /// <summary>Reasons accepted by <see cref="ReportFraudAsync"/>.</summary>
    public static readonly IReadOnlyList<string> FraudReasons = new[] { "chargeback", "account_takeover", "social_engineering", "other" };

    private readonly TouchqueHttp _http;

    internal LoginResource(TouchqueHttp http) => _http = http;

    /// <summary>A push to the user's phone (returns at once; see <see cref="VerifyAsync(LoginRequestOptions, CancellationToken)"/> to wait).</summary>
    public Task<LoginRequestResult> RequestAsync(string externalUsername, string type = "LOGIN", CancellationToken ct = default) =>
        RequestAsync(new LoginRequestOptions { ExternalUsername = externalUsername, Type = type }, ct);

    /// <summary>
    /// A push to the user's phone with every option: transaction details, the end
    /// user's IP and browser, number matching, the browser proof of silent sign-ins,
    /// context for your Actions, security changes, a destination.
    /// With behavioral biometrics on, the answer has <see cref="LoginRequestResult.TelemetryToken"/>
    /// for the <c>@touchque/web</c> widget.
    /// </summary>
    public Task<LoginRequestResult> RequestAsync(LoginRequestOptions options, CancellationToken ct = default) =>
        _http.PostAsync<LoginRequestResult>("/login/request", options.ToJson(), ct);

    /// <summary>Where a request is now: PENDING, CONFIRMED, REJECTED or EXPIRED.</summary>
    public Task<LoginStatus> StatusAsync(string requestId, CancellationToken ct = default) =>
        _http.GetAsync<LoginStatus>("/login/status/" + TouchqueHttp.Seg(requestId), null, ct);

    /// <summary>Asks the phone and waits for the answer.</summary>
    public Task<VerifyResult> VerifyAsync(string externalUsername, string type = "LOGIN", CancellationToken ct = default) =>
        VerifyAsync(new LoginRequestOptions { ExternalUsername = externalUsername, Type = type }, ct);

    /// <summary>
    /// Asks the phone and polls until the user approves or rejects. With number
    /// matching (your option, a workspace policy, a critical action or the risk
    /// engine) the user picks a number on the phone: <see cref="LoginRequestOptions.OnChallenge"/>
    /// runs right after the request exists and before any waiting. Show
    /// <c>ChallengeCode</c> to the user now; the phone asks for it.
    /// </summary>
    /// <exception cref="TouchquePasskeyRequiredException">Only a passkey can approve (policy), or the user tapped Approve during a call (step_up).</exception>
    /// <exception cref="TouchqueRejectedException">The user rejected it.</exception>
    /// <exception cref="TouchqueTimeoutException">It expired or <see cref="LoginRequestOptions.Timeout"/> passed.</exception>
    public async Task<VerifyResult> VerifyAsync(LoginRequestOptions options, CancellationToken ct = default)
    {
        var sent = await RequestAsync(options, ct).ConfigureAwait(false);
        if (sent.RequiresPasskey)
        {
            throw new TouchquePasskeyRequiredException(sent.RequestId);
        }
        if (options.OnChallenge is { } onChallenge)
        {
            try
            {
                await onChallenge(new VerifyChallenge
                {
                    RequestId = sent.RequestId,
                    ChallengeCode = string.IsNullOrEmpty(sent.ChallengeCode) ? null : sent.ChallengeCode,
                    ExpiresAt = sent.ExpiresAt,
                    Reasons = sent.Reasons,
                    CaseCode = sent.CaseCode,
                }).ConfigureAwait(false);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // The caller's callback must not stop the wait.
                _http.Log.Warn("[Touchque] OnChallenge failed: " + SdkLog.Describe(e));
            }
        }
        return await WaitAsync(sent.RequestId, sent.ChallengeCode, options.Timeout ?? TimeSpan.FromSeconds(30), options.PollInterval ?? TimeSpan.FromMilliseconds(400), ct).ConfigureAwait(false);
    }

    /// <summary>Waits for a request you already sent (e.g. with <see cref="RequestAsync(LoginRequestOptions, CancellationToken)"/>).</summary>
    public Task<VerifyResult> WaitForApprovalAsync(string requestId, TimeSpan? timeout = null, TimeSpan? pollInterval = null, CancellationToken ct = default) =>
        WaitAsync(requestId, null, timeout ?? TimeSpan.FromSeconds(30), pollInterval ?? TimeSpan.FromMilliseconds(400), ct);

    private async Task<VerifyResult> WaitAsync(string requestId, string? challengeCode, TimeSpan timeout, TimeSpan interval, CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (true)
        {
            var s = await StatusAsync(requestId, ct).ConfigureAwait(false);
            switch (s.Status)
            {
                case "CONFIRMED":
                    return new VerifyResult
                    {
                        Approved = true,
                        Status = s.Status,
                        RequestId = requestId,
                        ChallengeCode = string.IsNullOrEmpty(challengeCode) ? null : challengeCode,
                        Assurance = s.Assurance,
                        ConfirmedVia = s.ConfirmedVia,
                        // Vishing Shield: approved during a call; critical actions wait for the phone to re-confirm.
                        Provisional = s.Provisional,
                    };
                case "REJECTED":
                    throw new TouchqueRejectedException(requestId);
                case "EXPIRED":
                    throw new TouchqueTimeoutException($"Touchque: request '{requestId}' expired before it was approved.", requestId);
            }
            // Vishing Shield: tapped during a call, the request now waits for a passkey in the browser.
            if (s.Status == "PENDING" && s.RequiresPasskey)
            {
                throw new TouchquePasskeyRequiredException(requestId, "step_up");
            }
            if (DateTimeOffset.UtcNow + interval > deadline)
            {
                throw new TouchqueTimeoutException(
                    $"Touchque: request '{requestId}' was not approved within {timeout.TotalSeconds:0}s. The user did not respond in time.", requestId);
            }
            await Task.Delay(interval, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Approves a pending request with one of the user's recovery codes (no phone).</summary>
    public Task<JsonObject> ApproveWithRecoveryCodeAsync(string requestId, string code, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>("/login/recovery", new JsonObject { ["requestId"] = requestId, ["code"] = code }, ct);

    /// <summary>
    /// Uses an approved request exactly once. The first call on a CONFIRMED request
    /// wins atomically; every later call (a replayed token, a retried form post)
    /// throws <see cref="TouchqueApiException"/> with code <c>already_used</c> (409).
    /// </summary>
    public Task<ConsumeResult> ConsumeAsync(string requestId, CancellationToken ct = default) =>
        _http.PostAsync<ConsumeResult>("/login/" + TouchqueHttp.Seg(requestId) + "/consume", new JsonObject(), ct);

    /// <summary>
    /// Reports a request you later learned was fraud (a chargeback, a confirmed
    /// account takeover, a scam the user was talked into). The risk engine learns
    /// from it and the report is kept in your audit log; the request's status does
    /// not change. A repeat answers <c>AlreadyReported = true</c>.
    /// </summary>
    /// <param name="reason">One of <see cref="FraudReasons"/> (default <c>other</c>).</param>
    /// <param name="note">Free text for your audit log, at most 500 characters.</param>
    public Task<FraudReport> ReportFraudAsync(string requestId, string? reason = null, string? note = null, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(requestId)) throw new TouchqueConfigException("ReportFraudAsync() needs the request id");
        var body = new JsonObject().Put("reason", reason).Put("note", note);
        return _http.PostAsync<FraudReport>("/login/" + TouchqueHttp.Seg(requestId) + "/report-fraud", body, ct);
    }
}

/// <summary>Every field of <c>POST /login/request</c>.</summary>
public sealed record LoginRequestOptions
{
    /// <summary>The user in YOUR system (email, id).</summary>
    public required string ExternalUsername { get; init; }

    /// <summary>The action type (default <c>LOGIN</c>).</summary>
    public string Type { get; init; } = "LOGIN";

    public string? ReferenceId { get; init; }

    /// <summary>The END USER's IP (shown as "City, Country" on the phone; Tor, travel and attack-tool checks).</summary>
    public string? ClientIp { get; init; }

    /// <summary>The end user's User-Agent (shown as browser and device).</summary>
    public string? UserAgent { get; init; }

    public bool RequireBiometric { get; init; }

    public bool RequireNumberMatch { get; init; }

    /// <summary>Digits of the matching number when one is shown: 2 or 3. The longer of this and the workspace policy wins.</summary>
    public int? ChallengeDigits { get; init; }

    /// <summary>How long the push waits for the person, in seconds: 30 (default) to 300.</summary>
    public int? ExpiresIn { get; init; }

    /// <summary>The end user's page check from <c>@touchque/web</c>, passed through untouched: a browser driven by software asks with number matching.</summary>
    public string? ClientSignals { get; init; }

    /// <summary>
    /// The page's device report from <c>@touchque/web</c> (<c>deviceRisk.collect({ purpose })</c>), passed through untouched.
    /// Used only when your workspace turned Device risk on: its signals only ever ask for more, and a device your
    /// admin marked "step up always" asks at once.
    /// </summary>
    public string? DeviceRisk { get; init; }
    /// <summary>The page's identification (<c>deviceRisk.identify()</c>), preferred over DeviceRisk; for this account only.</summary>
    public string? DeviceRiskRequestId { get; init; }

    /// <summary>
    /// A browser pairing by QR code (<see cref="TouchqueClient.QrPairings"/>), scanned and confirmed on the phone:
    /// only the phone that scanned it is asked, once, with number matching, for the user it scanned for.
    /// </summary>
    public string? QrPairing { get; init; }

    /// <summary>
    /// Ask the person to type back on the phone a sign-in code another service sent them; the phone
    /// encrypts it to <c>Reply.Key</c> and <see cref="LoginStatus.Reply"/> holds only the ciphertext
    /// (<see cref="CodeReply.Open"/>). Such a request lives 5 minutes. Not with <see cref="QrPairing"/>.
    /// </summary>
    public LoginReplyRequest? Reply { get; init; }

    /// <summary>Transaction context for the approval screen (at most 8 lines).</summary>
    public IReadOnlyList<LoginDetail>? Details { get; init; }

    /// <summary>
    /// Silent sign-ins: the browser's device-bound key proof exactly as the browser
    /// sent it (<c>X-Touchque-Browser</c>). Once the user approves this request,
    /// Touchque knows the browser.
    /// </summary>
    public string? BrowserProof { get; init; }

    /// <summary>For your Touchque Actions only (<c>event.context</c>); never shown on the phone. Any JSON object up to 4 KB.</summary>
    public IReadOnlyDictionary<string, object?>? Context { get; init; }

    /// <summary>When the user's sign-in security last changed in your system.</summary>
    public SecurityChanges? SecurityChanges { get; init; }

    /// <summary>Where the action sends money or value (shown in full on the phone; do not repeat it in Details).</summary>
    public Destination? Destination { get; init; }

    /// <summary><c>tr</c> (default) or <c>en</c>: the language of the rows Touchque adds.</summary>
    public string? Locale { get; init; }

    /// <summary>VerifyAsync only: how long to wait (default 30 seconds; with a longer <see cref="ExpiresIn"/>, set it to match).</summary>
    public TimeSpan? Timeout { get; init; }

    /// <summary>VerifyAsync only: how often to ask (default 400 ms).</summary>
    public TimeSpan? PollInterval { get; init; }

    /// <summary>
    /// VerifyAsync only: called once, right after the request is created and before
    /// any waiting. Not called when only a passkey can approve. An exception it
    /// throws is logged and ignored.
    /// </summary>
    public Func<VerifyChallenge, Task>? OnChallenge { get; init; }

    internal JsonObject ToJson()
    {
        if (string.IsNullOrEmpty(ExternalUsername)) throw new TouchqueConfigException("A login request needs the user (ExternalUsername)");
        var body = new JsonObject { ["externalUsername"] = ExternalUsername, ["type"] = string.IsNullOrEmpty(Type) ? "LOGIN" : Type };
        body.Put("referenceId", ReferenceId).Put("clientIp", ClientIp).Put("userAgent", UserAgent);
        if (RequireBiometric) body["requireBiometric"] = true;
        if (RequireNumberMatch) body["requireNumberMatch"] = true;
        if (ChallengeDigits is 2 or 3) body["challengeDigits"] = ChallengeDigits.Value;
        body.Put("expiresIn", ExpiresIn).Put("clientSignals", ClientSignals).Put("deviceRisk", string.IsNullOrEmpty(DeviceRisk) ? null : DeviceRisk).Put("deviceRiskRequestId", string.IsNullOrEmpty(DeviceRiskRequestId) ? null : DeviceRiskRequestId).Put("qrPairing", string.IsNullOrEmpty(QrPairing) ? null : QrPairing);
        if (Details is { Count: > 0 }) body["details"] = DetailsJson(Details);
        body.Put("browserProof", BrowserProof);
        if (Context is { Count: > 0 }) body["context"] = Json.ToNode(Context);
        body.PutNode("securityChanges", SecurityChanges?.ToJson());
        if (Destination is not null) body["destination"] = Json.ToNode(Destination);
        body.Put("locale", Locale);
        if (Reply is not null)
        {
            body["reply"] = new JsonObject { ["kind"] = Reply.Kind, ["key"] = Reply.Key }.Put("channel", Reply.Channel).Put("target", Reply.Target);
        }
        return body;
    }

    internal static JsonArray DetailsJson(IEnumerable<LoginDetail> details)
    {
        var arr = new JsonArray();
        foreach (var d in details) arr.Add(new JsonObject { ["label"] = d.Label, ["value"] = d.Value });
        return arr;
    }
}

/// <summary>What <see cref="LoginRequestOptions.OnChallenge"/> receives as soon as the request exists.</summary>
public sealed record VerifyChallenge
{
    public string RequestId { get; init; } = "";
    /// <summary>The number to show when number matching is on, otherwise null.</summary>
    public string? ChallengeCode { get; init; }
    public string? ExpiresAt { get; init; }
    /// <summary>Why number matching is needed (a fixed list, never a score).</summary>
    public IReadOnlyList<RiskReason>? Reasons { get; init; }
    /// <summary>The "Why?" case code of this decision.</summary>
    public string? CaseCode { get; init; }
}

public sealed record LoginRequestResult : TouchqueObject
{
    public string RequestId { get; init; } = "";
    /// <summary>The number to show the user with number matching (null otherwise).</summary>
    public string? ChallengeCode { get; init; }
    public string? Message { get; init; }
    public string? ExpiresAt { get; init; }
    /// <summary>
    /// The "Why?" case code of this decision (<c>K7P-2QX</c>). Show it to the user;
    /// your team opens the whole decision by this code in the dashboard.
    /// </summary>
    public string? CaseCode { get; init; }
    /// <summary>Why number matching or a passkey is needed; empty for a plain push.</summary>
    public IReadOnlyList<RiskReason>? Reasons { get; init; }
    /// <summary>A phishing-resistant policy demands a passkey: no push was sent.</summary>
    public bool RequiresPasskey { get; init; }
    /// <summary>For the behavioral widget of <c>@touchque/web</c>, when the workspace collects it.</summary>
    public string? TelemetryToken { get; init; }
    public Canary? Canary { get; init; }
    public DestinationCheck? Destination { get; init; }
}

public sealed record LoginStatus : TouchqueObject
{
    /// <summary>PENDING, CONFIRMED, REJECTED or EXPIRED.</summary>
    public string Status { get; init; } = "";
    public string? ExternalUsername { get; init; }
    public string? Type { get; init; }
    public string? ReferenceId { get; init; }
    public IReadOnlyList<LoginDetail>? Details { get; init; }
    public bool Consumed { get; init; }
    public bool RequiresPasskey { get; init; }
    public string? ConfirmedVia { get; init; }
    public Assurance? Assurance { get; init; }
    /// <summary>Rejected: <c>user_reported_coached</c> and others.</summary>
    public string? RejectReason { get; init; }
    /// <summary>Vishing Shield: approved during a call, waiting for the phone to re-confirm.</summary>
    public bool Provisional { get; init; }
    public string? ReconfirmedAt { get; init; }
    public bool Revoked { get; init; }
    public string? RevokeReason { get; init; }
    /// <summary>A request made with Reply, once the person typed it back: the ciphertext only (<see cref="CodeReply.Open"/>).</summary>
    public LoginReply? Reply { get; init; }
    /// <summary>When the request expires (ISO 8601; a Vishing Shield escalation to a passkey extends it), null when the API did not say or sent no string.</summary>
    [System.Text.Json.Serialization.JsonConverter(typeof(LenientStringConverter))]
    public string? ExpiresAt { get; init; }
}

public sealed record VerifyResult : TouchqueObject
{
    public bool Approved { get; init; }
    public string Status { get; init; } = "";
    public string RequestId { get; init; } = "";
    public string? ChallengeCode { get; init; }
    public Assurance? Assurance { get; init; }
    public string? ConfirmedVia { get; init; }
    /// <summary>Vishing Shield: approved during a call; critical actions wait for the phone to re-confirm.</summary>
    public bool Provisional { get; init; }
}

public sealed record ConsumeResult : TouchqueObject
{
    public bool Consumed { get; init; }
    public string RequestId { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    public string Type { get; init; } = "";
    public string? ReferenceId { get; init; }
    public IReadOnlyList<LoginDetail>? Details { get; init; }
    public string? ConfirmedVia { get; init; }
    public Assurance? Assurance { get; init; }
    /// <summary>The phone's signature over what it showed (<see cref="ApprovalProof"/>), or null.</summary>
    public JsonObject? ApprovalProof { get; init; }
    public bool? Provisional { get; init; }
    public string? ReconfirmedAt { get; init; }
    public bool Revoked { get; init; }
    public string? RevokeReason { get; init; }
}

public sealed record FraudReport : TouchqueObject
{
    public bool Reported { get; init; }
    public bool AlreadyReported { get; init; }
    public string RequestId { get; init; } = "";
}
