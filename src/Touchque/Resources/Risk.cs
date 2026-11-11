using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>
/// Silent sign-ins: ask Touchque's risk engine whether a sign-in needs the phone at
/// all, and manage the browsers it knows for a user. A browser becomes known when
/// the user approves a request that carried the browser's device-bound key proof;
/// later <see cref="CheckAsync"/> with a fresh proof from the same browser answers
/// <c>Prompt = false</c> when nothing about the sign-in is new. Nothing goes to the phone.
/// </summary>
public sealed class RiskResource
{
    private static readonly HashSet<string> AssuranceLevels = new() { "high", "normal", "low" };
    private readonly TouchqueHttp _http;

    internal RiskResource(TouchqueHttp http) => _http = http;

    /// <summary>
    /// Should this sign-in ask the phone? Skip the push only when <c>Prompt</c> is
    /// false; on any error, ask as usual. A critical action always asks.
    /// </summary>
    public async Task<RiskCheckResult> CheckAsync(RiskCheckOptions options, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(options.ExternalUsername)) throw new TouchqueConfigException("Risk.CheckAsync() needs the user (ExternalUsername)");
        if (options.MaxAgeSeconds is < 0) throw new TouchqueConfigException("Risk.CheckAsync(): MaxAgeSeconds must be >= 0 (0 = always ask)");
        var body = new JsonObject { ["externalUsername"] = options.ExternalUsername };
        body.Put("type", options.Type).Put("clientIp", options.ClientIp).Put("userAgent", options.UserAgent)
            .Put("browserProof", options.BrowserProof).Put("clientSignals", options.ClientSignals).Put("deviceRisk", options.DeviceRisk).Put("deviceRiskRequestId", options.DeviceRiskRequestId).Put("maxAgeSeconds", options.MaxAgeSeconds);
        if (options.Context is { Count: > 0 }) body["context"] = Json.ToNode(options.Context);
        return ParseCheck(await _http.PostAsync("/risk/check", body, ct).ConfigureAwait(false));
    }

    /// <summary>
    /// Reads a <c>POST /risk/check</c> answer, failing closed: <c>Prompt</c> is false
    /// ONLY when the answer says exactly <c>prompt: false</c> (a boolean). Malformed
    /// reasons become empty, and an unknown or missing assurance is <c>normal</c>.
    /// </summary>
    public static RiskCheckResult ParseCheck(JsonNode? raw)
    {
        var body = raw as JsonObject ?? new JsonObject();
        var prompt = !(body.TryGetPropertyValue("prompt", out var p) && p is JsonValue pv && pv.TryGetValue<bool>(out var pb) && pb == false);
        var reasons = new List<RiskReason>();
        if (body["reasons"] is JsonArray arr)
        {
            foreach (var r in arr)
            {
                var code = Json.Str(r, "code");
                if (code is not null) reasons.Add(new RiskReason { Code = code, Text = Json.Str(r, "text") ?? "" });
            }
        }
        var assurance = Json.Str(body, "assurance");
        return new RiskCheckResult
        {
            Prompt = prompt,
            Reasons = reasons,
            Assurance = assurance is not null && AssuranceLevels.Contains(assurance) ? assurance : "normal",
            SilentMode = Json.Str(body, "silentMode") == "shadow" ? "shadow" : "enforce",
            CaseCode = Json.Str(body, "caseCode"),
        };
    }

    /// <summary>The browsers Touchque knows for a user (for an "approved browsers" list in your settings page).</summary>
    public async Task<IReadOnlyList<RiskBrowser>> BrowsersAsync(string externalUsername, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(externalUsername)) throw new TouchqueConfigException("Risk.BrowsersAsync() needs the user (externalUsername)");
        var res = await _http.GetAsync("/risk/browsers", new Dictionary<string, string?> { ["externalUsername"] = externalUsername }, ct).ConfigureAwait(false);
        return res?["browsers"] is JsonArray ? Json.To<List<RiskBrowser>>(res["browsers"]) : new List<RiskBrowser>();
    }

    /// <summary>
    /// Forgets one browser (<paramref name="thumbprint"/>) or all of a user's browsers:
    /// their next sign-in asks the phone again. Call it after a password reset or a
    /// sign-out everywhere. Returns how many were forgotten.
    /// </summary>
    public async Task<int> ForgetBrowsersAsync(string externalUsername, string? thumbprint = null, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(externalUsername)) throw new TouchqueConfigException("Risk.ForgetBrowsersAsync() needs the user (externalUsername)");
        var body = new JsonObject { ["externalUsername"] = externalUsername }.Put("thumbprint", thumbprint);
        var res = await _http.PostAsync("/risk/browsers/forget", body, ct).ConfigureAwait(false);
        return Json.Int(res, "forgotten") ?? 0;
    }
}

public sealed record RiskCheckOptions
{
    /// <summary>The user in YOUR system.</summary>
    public required string ExternalUsername { get; init; }
    /// <summary>The action the user is about to do (default LOGIN); a critical action always asks.</summary>
    public string? Type { get; init; }
    /// <summary>The end user's IP, compared with the networks of earlier approved sign-ins.</summary>
    public string? ClientIp { get; init; }
    public string? UserAgent { get; init; }
    /// <summary>The browser's device-bound key proof (<c>X-Touchque-Browser</c>), passed through untouched.</summary>
    public string? BrowserProof { get; init; }
    /// <summary>The end user's page check from <c>@touchque/web</c>: software driving the browser is never silent.</summary>
    public string? ClientSignals { get; init; }
    /// <summary>The page's device report from <c>@touchque/web</c> (<c>deviceRisk.collect</c>): a device signal is never silent.</summary>
    public string? DeviceRisk { get; init; }
    /// <summary>The page's identification (<c>deviceRisk.identify()</c>), preferred over DeviceRisk; for this account only.</summary>
    public string? DeviceRiskRequestId { get; init; }
    /// <summary>Your own limit on how long ago the last phone approval in this browser may be; 0 = always ask. Touchque never goes beyond 7 days.</summary>
    public int? MaxAgeSeconds { get; init; }
    /// <summary>For your Touchque Actions only (<c>event.context</c>).</summary>
    public IReadOnlyDictionary<string, object?>? Context { get; init; }
}

public sealed record RiskCheckResult : TouchqueObject
{
    /// <summary>False only when Touchque said exactly <c>prompt: false</c>.</summary>
    public bool Prompt { get; init; } = true;
    /// <summary>
    /// Silent: known_browser, recent_approval, same_phone, familiar_network, no_risk_signal.
    /// Asked: no_browser_key, new_browser, approval_too_old, critical_action, risk_signal, silent_mode_shadow…
    /// </summary>
    public IReadOnlyList<RiskReason> Reasons { get; init; } = Array.Empty<RiskReason>();
    /// <summary>high, normal or low.</summary>
    public string Assurance { get; init; } = "normal";
    /// <summary><c>shadow</c>: silent sign-ins are only measured, so Prompt is always true.</summary>
    public string SilentMode { get; init; } = "enforce";
    /// <summary>The check's "Why?" case code.</summary>
    public string? CaseCode { get; init; }
}

public sealed record RiskBrowser : TouchqueObject
{
    public string Thumbprint { get; init; } = "";
    public string? Label { get; init; }
    public string? CreatedAt { get; init; }
    public string? LastMfaAt { get; init; }
    public string? LastMfaMethod { get; init; }
    public string? LastSeenAt { get; init; }
    public string? LastSilentAt { get; init; }
}
