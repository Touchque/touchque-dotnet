using System.Text.Json.Nodes;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>
/// Device risk (a paid add-on, off until your workspace turns it on): a visitor ID for every browser on your
/// sign-up, password-reset, sign-in or approval page. The page identifies with <c>@touchque/web</c>
/// (<c>deviceRisk.identify({ siteKey, purpose })</c> gives <c>{ visitorId, requestId, confidence }</c>) and sends you
/// the requestId. Never trust the page's copy: read the identification here (<see cref="GetEventAsync"/>) or check
/// it for an account (<see cref="CheckAsync(DeviceRiskCheckOptions, CancellationToken)"/>). TouchQue keeps keyed hashes only, with a key of your workspace
/// alone, and its risk engine decides. Every signal only ever asks for more: <c>StepUp</c> means an extra check on
/// this page (an emailed code, a passkey, a number-matched approval), never a refusal. For sign-ins, pass the
/// requestId as <c>DeviceRiskRequestId</c> in <see cref="LoginRequestOptions"/> and <see cref="RiskCheckOptions"/>.
/// Collect it only on these pages and name it in your privacy notice.
/// With the script tag (device.js), the form arrives with <c>touchque_request_id</c>:
/// <c>await tq.DeviceRisk.CheckAsync(Request.Form["touchque_request_id"], new() { ExternalUsername = email })</c>.
/// Pass it as it came. Missing, empty, made up or expired, it is still a verdict (<c>Report</c> missing, unknown,
/// expired; the signal <c>device_identification_missing</c>), never an exception: a page without the tag, or with
/// it blocked, only gets the visitor a step-up.
/// </summary>
public sealed partial class DeviceRiskResource
{
    /// <summary>The pages a device report may come from.</summary>
    public static readonly IReadOnlyList<string> Events = ["sign_in", "sign_up", "password_reset", "approval"];

    /// <summary>What the page had sent: <c>ok</c>, <c>replayed</c>, or no usable identification.</summary>
    public static readonly IReadOnlyList<string> Reports = ["ok", "replayed", "missing", "unknown", "expired", "invalid"];

    private readonly TouchQueHttp _http;

    internal DeviceRiskResource(TouchQueHttp http) => _http = http;

    [System.Text.RegularExpressions.GeneratedRegex("^dre_[A-Za-z0-9_-]{22}$")]
    private static partial System.Text.RegularExpressions.Regex RequestIdPattern();

    /// <summary>
    /// Checks the page's identification for an account (the <c>touchque_request_id</c> form field, as it came):
    /// null, empty or made up is still a verdict, never an exception. See
    /// <see cref="CheckAsync(DeviceRiskCheckOptions, CancellationToken)"/>.
    /// </summary>
    public Task<DeviceRiskCheckResult> CheckAsync(string? requestId, DeviceRiskCheckOptions? options = null, CancellationToken ct = default)
        => CheckAsync((options ?? new DeviceRiskCheckOptions()) with { RequestId = requestId }, ct);

    /// <summary>
    /// Checks the page's identification for an account: binds it (one account per identification, 15 minutes) and
    /// asks the risk engine. Pass the form field as it came: null, empty or made up is still a verdict (<c>Report</c>
    /// missing, unknown), never an exception. 409 <c>device_risk_off</c> until your workspace turns Device risk on.
    /// </summary>
    public async Task<DeviceRiskCheckResult> CheckAsync(DeviceRiskCheckOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var ev = string.IsNullOrEmpty(options.Event) ? "sign_in" : options.Event;
        if (!Events.Contains(ev))
            throw new TouchQueConfigException($"DeviceRisk.CheckAsync(): Event must be one of {string.Join(", ", Events)}");
        var body = new JsonObject();
        if (!string.IsNullOrEmpty(options.RequestId))
            body["requestId"] = options.RequestId.Length > 64 ? options.RequestId[..64] : options.RequestId;
        else if (!string.IsNullOrEmpty(options.DeviceRisk))
            body["deviceRisk"] = options.DeviceRisk;
        body["event"] = ev;
        body.Put("externalUsername", string.IsNullOrEmpty(options.ExternalUsername) ? null : options.ExternalUsername)
            .Put("clientIp", string.IsNullOrEmpty(options.ClientIp) ? null : options.ClientIp);
        return ParseCheck(await _http.PostAsync("/device-risk/check", body, ct).ConfigureAwait(false));
    }

    /// <summary>
    /// Your workspace's identifications, newest first, one page at a time (<c>GET /device-risk/events</c>): a date
    /// range (<c>From</c>/<c>To</c>: YYYY-MM-DD or ISO times; 7 days by default, at most 90, within your retention)
    /// and any of the filters. <c>Ip</c> is an address or a CIDR range and is never returned. Pass
    /// <c>NextCursor</c> back as <c>Cursor</c> until it is null; do not page by moving the dates. A search that would
    /// read too much is a 422 <c>search_too_broad</c>: narrow the range or add a filter.
    /// </summary>
    public async Task<DeviceRiskSearchResult> SearchEventsAsync(DeviceRiskSearchOptions? options = null, CancellationToken ct = default)
    {
        var o = options ?? new DeviceRiskSearchOptions();
        if (o.Limit is { } l && (l < 1 || l > 100)) throw new TouchQueConfigException("DeviceRisk.SearchEventsAsync() Limit must be 1 to 100");
        var query = new Dictionary<string, string?>();
        void Put(string k, string? v) { if (!string.IsNullOrEmpty(v)) query[k] = v; }
        Put("from", o.From); Put("to", o.To); Put("signal", o.Signal); Put("kind", o.Kind); Put("origin", o.Origin);
        Put("ip", o.Ip); Put("account", o.Account); Put("visitorId", o.VisitorId); Put("requestId", o.RequestId); Put("cursor", o.Cursor);
        if (o.StepUp is { } up) query["stepUp"] = up ? "true" : "false";
        if (o.Limit is { } n) query["limit"] = n.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var res = await _http.GetAsync("/device-risk/events", query, ct).ConfigureAwait(false) as JsonObject ?? new JsonObject();
        var events = new List<JsonObject>();
        if (res["events"] is JsonArray list) foreach (var e in list) if (e is JsonObject obj) events.Add((JsonObject)obj.DeepClone());
        var next = res["nextCursor"] is JsonValue c && c.TryGetValue<string>(out var cs) && cs.Length > 0 ? cs : null;
        return new DeviceRiskSearchResult
        {
            Events = events,
            NextCursor = next,
            From = res["from"] is JsonValue f && f.TryGetValue<string>(out var fs) ? fs : "",
            To = res["to"] is JsonValue t && t.TryGetValue<string>(out var ts) ? ts : "",
        };
    }

    /// <summary>
    /// The trusted identification behind a requestId: the visitor (visitorId, confidence, matchedBy), what the page
    /// showed (facts) and the risk engine's verdict. Read-only.
    /// </summary>
    public async Task<JsonObject> GetEventAsync(string requestId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(requestId) || !RequestIdPattern().IsMatch(requestId))
            throw new TouchQueConfigException("DeviceRisk.GetEventAsync() needs a requestId (dre_…)");
        return await _http.GetAsync($"/device-risk/events/{System.Uri.EscapeDataString(requestId)}", null, ct).ConfigureAwait(false) as JsonObject ?? new JsonObject();
    }

    /// <summary>
    /// Reads a <c>POST /device-risk/check</c> answer, failing toward asking: <c>StepUp</c> is true unless it
    /// says exactly <c>stepUp: false</c>; junk signals are dropped.
    /// </summary>
    public static DeviceRiskCheckResult ParseCheck(JsonNode? raw)
    {
        var body = raw as JsonObject ?? new JsonObject();
        bool IsFalse(string key) => body.TryGetPropertyValue(key, out var v) && v is JsonValue jv && jv.TryGetValue<bool>(out var b) && !b;
        bool IsTrue(string key) => body.TryGetPropertyValue(key, out var v) && v is JsonValue jv && jv.TryGetValue<bool>(out var b) && b;
        var signals = new List<DeviceRiskSignal>();
        if (body["signals"] is JsonArray arr)
        {
            foreach (var s in arr)
            {
                var code = Json.Str(s, "code");
                if (code is null) continue;
                var strength = Json.Str(s, "strength");
                signals.Add(new DeviceRiskSignal
                {
                    Code = code,
                    Text = Json.Str(s, "text") ?? "",
                    Strength = strength is "passkey" or "none" ? strength : "number_match",
                    Enforced = s?["enforced"] is JsonValue ev && ev.TryGetValue<bool>(out var e) && e,
                    Evidence = s?["evidence"] as JsonObject,
                });
            }
        }
        var report = Json.Str(body, "report");
        var requires = Json.Str(body, "requires");
        return new DeviceRiskCheckResult
        {
            Report = report is not null && Reports.Contains(report) ? report : "invalid",
            RequestId = Json.Str(body, "requestId"),
            VisitorId = Json.Str(body, "visitorId"),
            Confidence = body["confidence"] is JsonValue cv && cv.TryGetValue<double>(out var c) ? c : null,
            Visitor = body["visitor"] as JsonObject,
            CaseCode = Json.Str(body, "caseCode"),
            Counts = body["counts"] as JsonObject,
            Network = body["network"] as JsonObject,
            Velocity = body["velocity"] as JsonObject,
            Bot = body["bot"] as JsonObject,
            Signals = signals,
            StepUp = !IsFalse("stepUp"),
            WouldStepUp = IsTrue("wouldStepUp"),
            Requires = requires is "number_match" or "passkey" ? requires : "none",
            Mode = Json.Str(body, "mode") == "enforce" ? "enforce" : "shadow",
            Engine = Json.Str(body, "engine"),
        };
    }
}

/// <summary>One page's identification, for an account.</summary>
public sealed record DeviceRiskCheckOptions
{
    /// <summary>
    /// The <c>touchque_request_id</c> form field (the script tag) or <c>deviceRisk.identify()</c>'s requestId, as it
    /// came: null or empty is answered <c>Report</c> missing.
    /// </summary>
    public string? RequestId { get; init; }
    /// <summary>Instead: the page's report (<c>deviceRisk.collect()</c>), relayed untouched.</summary>
    public string? DeviceRisk { get; init; }
    /// <summary><c>sign_in</c> (default), <c>sign_up</c>, <c>password_reset</c> or <c>approval</c>.</summary>
    public string? Event { get; init; }
    /// <summary>The account the page is for, when there is one. One account per identification.</summary>
    public string? ExternalUsername { get; init; }
    /// <summary>The end user's address; default: where the browser identified from.</summary>
    public string? ClientIp { get; init; }
}

/// <summary>A device signal. Each one only ever asks for more; none blocks.</summary>
public sealed record DeviceRiskSignal
{
    /// <summary>
    /// <c>device_tampered</c>, <c>device_virtual</c>, <c>device_geo_mismatch</c>, <c>device_many_accounts</c>,
    /// <c>device_signup_burst</c>, <c>device_id_resets</c>, <c>device_many_countries</c>, <c>device_wrong_site</c>,
    /// <c>device_report_replayed</c>, <c>device_private_window</c> (context only), <c>device_step_up_by_admin</c>,
    /// <c>device_identification_missing</c> (no identification, or one that does not verify).
    /// </summary>
    public string Code { get; init; } = "";
    /// <summary>English text.</summary>
    public string Text { get; init; } = "";
    /// <summary><c>number_match</c>, <c>passkey</c> or <c>none</c> (context only).</summary>
    public string Strength { get; init; } = "number_match";
    /// <summary>Scored now; false: reported only (shadow) until TouchQue enforces it.</summary>
    public bool Enforced { get; init; }
    /// <summary>Counts and finding names behind it (never a raw trait).</summary>
    public JsonObject? Evidence { get; init; }
}

/// <summary>The answer of <see cref="DeviceRiskResource.CheckAsync(DeviceRiskCheckOptions, CancellationToken)"/>.</summary>
public sealed record DeviceRiskCheckResult
{
    /// <summary>
    /// What the page had sent: <c>ok</c>; <c>replayed</c> (another account, or sent twice); or no usable
    /// identification, which raises <c>device_identification_missing</c>: <c>missing</c> (none or empty),
    /// <c>unknown</c> (made up, or another workspace's), <c>expired</c> (over 15 minutes old), <c>invalid</c>.
    /// </summary>
    public string Report { get; init; } = "invalid";
    /// <summary>This identification (<c>dre_…</c>).</summary>
    public string? RequestId { get; init; }
    /// <summary>This browser in your workspace only (<c>tqv_…</c>).</summary>
    public string? VisitorId { get; init; }
    /// <summary>How sure the visitorId is (0 to 1).</summary>
    public double? Confidence { get; init; }
    /// <summary>firstSeenAt, lastSeenAt, seenCount, matchedBy, sealed, status (your admin's mark), labels.</summary>
    public JsonObject? Visitor { get; init; }
    /// <summary>"Why?": the decision record, opened by this code in the dashboard.</summary>
    public string? CaseCode { get; init; }
    /// <summary>Accounts, sign-ups and countries per device, and stored-id resets.</summary>
    public JsonObject? Counts { get; init; }
    /// <summary>
    /// The address as the risk engine saw it (never coordinates): countryCode, region, city, accuracyKm,
    /// timeZone, asn, asnOrg, type (<c>isp</c>, <c>hosting</c>, <c>tor</c>, <c>unknown</c>), tor, hosting,
    /// hostingProvider, timezoneMismatch. Null without an address.
    /// </summary>
    public JsonObject? Network { get; init; }
    /// <summary>
    /// The visitor's counts: accounts24h, accounts30d, signUps24h, countries24h, idResets7d,
    /// identifications1h, identifications24h. Null without a usable identification.
    /// </summary>
    public JsonObject? Velocity { get; init; }
    /// <summary>
    /// One answer to "a bot?": result (<c>detected</c>, <c>suspected</c>, <c>not_detected</c>) and reasons.
    /// Null without a usable identification.
    /// </summary>
    public JsonObject? Bot { get; init; }
    /// <summary>The signals raised.</summary>
    public IReadOnlyList<DeviceRiskSignal> Signals { get; init; } = [];
    /// <summary>Ask for more on this page. Never a reason to refuse.</summary>
    public bool StepUp { get; init; } = true;
    /// <summary>A signal that asks was raised, enforced or not.</summary>
    public bool WouldStepUp { get; init; }
    /// <summary><c>none</c>, <c>number_match</c> or <c>passkey</c>.</summary>
    public string Requires { get; init; } = "none";
    /// <summary><c>enforce</c> when at least one raised signal is enforced, else <c>shadow</c>.</summary>
    public string Mode { get; init; } = "shadow";
    /// <summary>The engine's state for this check; <c>unavailable</c> when the risk engine could not be reached and the verdict is a safe default.</summary>
    public string? Engine { get; init; }
}

/// <summary><see cref="DeviceRiskResource.SearchEventsAsync"/>'s filters; each one only when set.</summary>
public sealed record DeviceRiskSearchOptions
{
    public string? From { get; init; }
    public string? To { get; init; }
    public string? Signal { get; init; }
    public bool? StepUp { get; init; }
    public string? Kind { get; init; }
    public string? Origin { get; init; }
    /// <summary>An address or a CIDR range; never returned.</summary>
    public string? Ip { get; init; }
    public string? Account { get; init; }
    public string? VisitorId { get; init; }
    public string? RequestId { get; init; }
    /// <summary>The previous page's <c>NextCursor</c>, as it came.</summary>
    public string? Cursor { get; init; }
    /// <summary>1 to 100 (default 25).</summary>
    public int? Limit { get; init; }
}

/// <summary>One page: pass <c>NextCursor</c> back as <c>Cursor</c> until it is null. No event carries an address.</summary>
public sealed record DeviceRiskSearchResult
{
    public IReadOnlyList<JsonObject> Events { get; init; } = new List<JsonObject>();
    public string? NextCursor { get; init; }
    public string From { get; init; } = "";
    public string To { get; init; } = "";
}
