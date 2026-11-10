using System.Text.Json.Nodes;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>
/// WebAuthn / FIDO2 (passkeys), the backend half. The ceremony runs in the
/// browser (<c>@touchque/web</c>); your backend relays its JSON through these
/// methods (or <c>MapTouchQueRelay</c> in ASP.NET Core does it for you).
/// </summary>
public sealed class WebAuthnResource
{
    private readonly TouchQueHttp _http;

    internal WebAuthnResource(TouchQueHttp http) => _http = http;

    /// <summary>
    /// Step 1 of registration: options for <c>navigator.credentials.create()</c>.
    /// <paramref name="discoverable"/> registers a resident credential (the shape a
    /// passwordless sign-in uses). A user with a linked phone needs
    /// <paramref name="approvalRequestId"/>: a PASSKEY_ENROLL request they approved
    /// on the phone, at most 10 minutes old, used once (403 enrollment_approval_required otherwise).
    /// </summary>
    public Task<JsonObject> RegisterOptionsAsync(string externalUsername, bool discoverable = false, string? approvalRequestId = null, CancellationToken ct = default)
    {
        var body = new JsonObject { ["externalUsername"] = externalUsername };
        if (discoverable) body["discoverable"] = true;
        body.Put("approvalRequestId", approvalRequestId);
        return _http.PostAsync<JsonObject>("/webauthn/register/options", body, ct);
    }

    /// <summary>Step 2 of registration: verifies the browser's answer.</summary>
    public Task<WebAuthnRegisterResult> RegisterVerifyAsync(string externalUsername, JsonNode response, string? label = null, CancellationToken ct = default)
    {
        var body = new JsonObject { ["externalUsername"] = externalUsername, ["response"] = response.DeepClone() };
        if (label is not null) body["label"] = label;
        return _http.PostAsync<WebAuthnRegisterResult>("/webauthn/register/verify", body, ct);
    }

    /// <summary>Second factor, step 1: options for <c>navigator.credentials.get()</c>, scoped to a pending request.</summary>
    public Task<JsonObject> AuthenticateOptionsAsync(string requestId, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>("/webauthn/login/options", new JsonObject { ["requestId"] = requestId }, ct);

    /// <summary>Second factor, step 2: verifies the assertion and approves the request.</summary>
    public Task<WebAuthnAuthenticateResult> AuthenticateVerifyAsync(string requestId, JsonNode response, CancellationToken ct = default) =>
        _http.PostAsync<WebAuthnAuthenticateResult>("/webauthn/login/verify", new JsonObject { ["requestId"] = requestId, ["response"] = response.DeepClone() }, ct);

    /// <summary>
    /// Whether passkey sign-in (<c>passwordlessLoginEnabled</c>) is on for your workspace.
    /// Ask before your sign-in page shows its passkey button and passkey autofill: when it
    /// is off, <see cref="PrimaryOptionsAsync"/> answers 403 <c>passwordless_login_disabled</c>.
    /// </summary>
    public async Task<WebAuthnPrimaryAvailability> PrimaryAvailabilityAsync(CancellationToken ct = default)
    {
        var res = await _http.GetAsync("/webauthn/authenticate/primary/availability", null, ct).ConfigureAwait(false);
        var enabled = res?["enabled"] is JsonValue on && on.TryGetValue<bool>(out var b) && b;
        var uv = res?["userVerification"] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
        return new WebAuthnPrimaryAvailability { Enabled = enabled, UserVerification = enabled && (uv is "required" or "preferred") ? uv : null };
    }

    /// <summary>
    /// Passwordless sign-in, step 1 (needs <c>passwordlessLoginEnabled</c>). 404
    /// <c>no_passkey_registered</c>: fall back to the password. Without a user the
    /// options accept any passkey of your site (passkey autofill).
    /// </summary>
    public Task<WebAuthnPrimaryOptions> PrimaryOptionsAsync(string? externalUsername = null, CancellationToken ct = default) =>
        _http.PostAsync<WebAuthnPrimaryOptions>("/webauthn/authenticate/primary/options", new JsonObject().Put("externalUsername", externalUsername), ct);

    /// <summary>
    /// Passwordless sign-in, step 2. On success <c>RequestId</c> is a CONFIRMED
    /// request; with <c>RequiresStepUp</c> start the normal push flow instead.
    /// </summary>
    public Task<WebAuthnPrimaryResult> PrimaryVerifyAsync(string attemptId, JsonNode response, CancellationToken ct = default) =>
        _http.PostAsync<WebAuthnPrimaryResult>("/webauthn/authenticate/primary/verify", new JsonObject { ["attemptId"] = attemptId, ["response"] = response.DeepClone() }, ct);

    /// <summary>A user's passkeys (metadata only, no key material).</summary>
    public async Task<IReadOnlyList<WebAuthnCredential>> ListCredentialsAsync(string externalUsername, CancellationToken ct = default)
    {
        var res = await _http.GetAsync("/webauthn/credentials", new Dictionary<string, string?> { ["externalUsername"] = externalUsername }, ct).ConfigureAwait(false);
        return Json.To<List<WebAuthnCredential>>(res?["credentials"]) ?? new List<WebAuthnCredential>();
    }

    /// <summary>
    /// Removes a passkey. Pass <paramref name="externalUsername"/> to scope it to that
    /// user (recommended: without it any credential your API key can reach is deletable).
    /// </summary>
    public async Task<bool> DeleteCredentialAsync(string credentialRecordId, string? externalUsername = null, CancellationToken ct = default)
    {
        var path = "/webauthn/credentials/" + TouchQueHttp.Seg(credentialRecordId);
        if (externalUsername is not null) path += "?externalUsername=" + TouchQueHttp.Seg(externalUsername);
        var res = await _http.DeleteAsync(path, ct).ConfigureAwait(false);
        return Json.Bool(res, "deleted");
    }
}

public sealed record WebAuthnRegisterResult : TouchQueObject
{
    public bool Verified { get; init; }
    public string? CredentialId { get; init; }
}

public sealed record WebAuthnAuthenticateResult : TouchQueObject
{
    public bool Success { get; init; }
    public string? Message { get; init; }
    /// <summary>The user TouchQue approved (trust this, never a name the browser sent).</summary>
    public string? ExternalUsername { get; init; }
    public string? RequestId { get; init; }
}

/// <summary>Whether passkey sign-in is on; <c>UserVerification</c> is <c>required</c> or <c>preferred</c>, null when off.</summary>
public sealed record WebAuthnPrimaryAvailability : TouchQueObject
{
    public bool Enabled { get; init; }
    public string? UserVerification { get; init; }
}

public sealed record WebAuthnPrimaryOptions : TouchQueObject
{
    public string AttemptId { get; init; } = "";
    public JsonObject? Options { get; init; }
}

public sealed record WebAuthnPrimaryResult : TouchQueObject
{
    public bool Success { get; init; }
    public bool RequiresStepUp { get; init; }
    public string? ExternalUsername { get; init; }
    public double? RiskScore { get; init; }
    public string? RequestId { get; init; }
}

public sealed record WebAuthnCredential : TouchQueObject
{
    public string Id { get; init; } = "";
    public string? CredentialId { get; init; }
    public string? DeviceType { get; init; }
    public bool BackedUp { get; init; }
    public string? Label { get; init; }
    public string? CreatedAt { get; init; }
    public string? LastUsedAt { get; init; }
}
