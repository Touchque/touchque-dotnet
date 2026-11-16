using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Touchque.Internal;

namespace Touchque;

/// <summary>Setup secrets (the QR code the Touchque app scans) and a user's link status.</summary>
public sealed class AuthResource
{
    private readonly TouchqueHttp _http;

    internal AuthResource(TouchqueHttp http) => _http = http;

    /// <summary>
    /// A new setup secret for a user: show <see cref="GenerateSecretResult.QrCodeDataUrl"/> so
    /// the Touchque app links the phone. 409 when an unscanned or used secret exists
    /// (<see cref="ResetSecretAsync(string, string, string, CancellationToken)"/> issues a new one).
    /// </summary>
    /// <param name="clientIp">
    /// The END user's IP, from the request that asks for the QR, as for a login request (sent only
    /// when not null or empty). Touchque keeps it with the secret, never in the QR: before linking,
    /// the phone shows where the QR was asked for (<see cref="ValidateSecretResult.SetupContext"/>).
    /// </param>
    /// <param name="userAgent">The end user's User-Agent, from the same request (sent only when not null or empty).</param>
    public Task<GenerateSecretResult> GenerateSecretAsync(string externalUsername, string? clientIp = null, string? userAgent = null, CancellationToken ct = default) =>
        _http.PostAsync<GenerateSecretResult>("/auth/generate-secret", SecretBody(externalUsername, clientIp, userAgent), ct);

    /// <summary>A new setup secret for a user, without the end user's IP and User-Agent.</summary>
    public Task<GenerateSecretResult> GenerateSecretAsync(string externalUsername, CancellationToken ct) =>
        GenerateSecretAsync(externalUsername, null, null, ct);

    /// <summary>Regenerates a user's secret.</summary>
    /// <param name="clientIp">
    /// The END user's IP, from the request that asks for the new QR, sent like
    /// <see cref="GenerateSecretAsync(string, string, string, CancellationToken)"/>'s: only when not null or empty.
    /// </param>
    /// <param name="userAgent">The end user's User-Agent, from the same request (sent only when not null or empty).</param>
    public Task<ResetSecretResult> ResetSecretAsync(string externalUsername, string? clientIp = null, string? userAgent = null, CancellationToken ct = default) =>
        _http.PostAsync<ResetSecretResult>("/auth/secret/reset", SecretBody(externalUsername, clientIp, userAgent), ct);

    /// <summary>Regenerates a user's secret, without the end user's IP and User-Agent.</summary>
    public Task<ResetSecretResult> ResetSecretAsync(string externalUsername, CancellationToken ct) =>
        ResetSecretAsync(externalUsername, null, null, ct);

    /// <summary>
    /// Checks a setup secret code. A valid one carries <see cref="ValidateSecretResult.SetupContext"/>:
    /// where its QR was asked for.
    /// </summary>
    public Task<ValidateSecretResult> ValidateSecretAsync(string secret, CancellationToken ct = default) =>
        _http.PostAsync<ValidateSecretResult>("/auth/secret/validate", new JsonObject { ["secret"] = secret }, ct);

    /// <summary>The user, and the end user's IP and User-Agent with the same rule as a login request: each only when not null or empty.</summary>
    private static JsonObject SecretBody(string externalUsername, string? clientIp, string? userAgent) =>
        new JsonObject { ["externalUsername"] = externalUsername }.Put("clientIp", clientIp).Put("userAgent", userAgent);

    /// <summary>
    /// A user's link status without sending a push: <see cref="TouchqueUser.Used"/> flips true and
    /// <see cref="TouchqueUser.DeviceId"/> is set once the app scans the secret.
    /// <see cref="TouchqueUser.Device"/> is the linked phone's self-reported posture (device trust).
    /// Throws <see cref="TouchqueApiException"/> (404) for an unknown user.
    /// </summary>
    public Task<TouchqueUser> GetUserAsync(string externalUsername, CancellationToken ct = default) =>
        _http.GetAsync<TouchqueUser>("/users/" + TouchqueHttp.Seg(externalUsername), null, ct);
}

public sealed record GenerateSecretResult : TouchqueObject
{
    public string Secret { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    public string? ExpiresAt { get; init; }
    public long? TtlMs { get; init; }
    /// <summary>A ready-to-render <c>data:image/png;base64,…</c> QR code for the Touchque app.</summary>
    public string? QrCodeDataUrl { get; init; }
    public IReadOnlyList<string>? RecoveryCodes { get; init; }
}

public sealed record ResetSecretResult : TouchqueObject
{
    public string? Message { get; init; }
    public string? UserId { get; init; }
    public string Secret { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    public string? ExpiresAt { get; init; }
    public long? TtlMs { get; init; }
    public string? QrCodeDataUrl { get; init; }
    public IReadOnlyList<string>? RecoveryCodes { get; init; }
}

public sealed record ValidateSecretResult : TouchqueObject
{
    public bool Valid { get; init; }
    public string? ExternalUsername { get; init; }
    public string? IntegrationId { get; init; }
    public string? Message { get; init; }
    public string? Reason { get; init; }
    public string? UsedAt { get; init; }
    public string? ExpiredAt { get; init; }

    /// <summary>
    /// Where the QR of this secret was asked for, which the phone shows before it links: null for
    /// an older QR, an API before setup context, or a QR asked for without the end user's IP and
    /// User-Agent. Read leniently: an answer of another shape is null, never an error.
    /// </summary>
    [JsonConverter(typeof(LenientObjectConverter<SetupContext>))]
    public SetupContext? SetupContext { get; init; }
}

/// <summary>
/// 2FA setup context: where a first-time linking QR was asked for (the browser that asked for it,
/// as the API recorded it from that request), shown on the phone before it links. Someone tricked
/// into scanning an attacker's QR sees the attacker's place and device. Every field may be null;
/// one the API sends in another shape is null too.
/// </summary>
public sealed record SetupContext : TouchqueObject
{
    /// <summary>The IP address the QR was asked from, or null.</summary>
    [JsonConverter(typeof(LenientStringConverter))]
    public string? Ip { get; init; }

    /// <summary>Where that address is (GeoIP), or null when unknown.</summary>
    [JsonConverter(typeof(LenientObjectConverter<SetupLocation>))]
    public SetupLocation? Location { get; init; }

    /// <summary>The browser and system from its User-Agent, or null when unknown.</summary>
    [JsonConverter(typeof(LenientObjectConverter<SetupDevice>))]
    public SetupDevice? Device { get; init; }

    /// <summary>When the QR was asked for (ISO 8601), as the API sent it.</summary>
    [JsonConverter(typeof(LenientStringConverter))]
    public string? RequestedAt { get; init; }

    /// <summary>True when the QR was asked for far from the phone that checks it, false when not, null when Touchque cannot tell.</summary>
    [JsonConverter(typeof(LenientBoolConverter))]
    public bool? FarFromPhone { get; init; }
}

/// <summary>Where a setup request came from (GeoIP).</summary>
public sealed record SetupLocation : TouchqueObject
{
    [JsonConverter(typeof(LenientStringConverter))]
    public string? City { get; init; }

    [JsonConverter(typeof(LenientStringConverter))]
    public string? Country { get; init; }

    /// <summary>ISO 3166-1 alpha-2, e.g. <c>DE</c>.</summary>
    [JsonConverter(typeof(LenientStringConverter))]
    public string? CountryCode { get; init; }
}

/// <summary>The browser and system a setup request came from (its User-Agent).</summary>
public sealed record SetupDevice : TouchqueObject
{
    /// <summary>E.g. <c>Chrome</c>, <c>Safari</c>.</summary>
    [JsonConverter(typeof(LenientStringConverter))]
    public string? Browser { get; init; }

    /// <summary>E.g. <c>macOS</c>, <c>iOS</c>, <c>Windows</c>.</summary>
    [JsonConverter(typeof(LenientStringConverter))]
    public string? Os { get; init; }

    /// <summary>E.g. <c>iPhone</c>, when the User-Agent names one.</summary>
    [JsonConverter(typeof(LenientStringConverter))]
    public string? Model { get; init; }
}

/// <summary>A user as Touchque knows them.</summary>
public sealed record TouchqueUser : TouchqueObject
{
    public string ExternalUsername { get; init; } = "";
    public string? DeviceId { get; init; }
    public bool Used { get; init; }
    public bool Frozen { get; init; }
    public string? CreatedAt { get; init; }
    public string? ExpireAt { get; init; }
    /// <summary>The linked phone's posture, or null before a phone is linked.</summary>
    public DevicePosture? Device { get; init; }
}

/// <summary>The linked phone's posture for device trust. Self-reported by the app.</summary>
public sealed record DevicePosture : TouchqueObject
{
    /// <summary><c>ios</c>, <c>android</c> or null.</summary>
    public string? Platform { get; init; }
    public string? Model { get; init; }
    public string? OsVersion { get; init; }
    /// <summary>Android security patch level (YYYY-MM-DD).</summary>
    public string? SecurityPatch { get; init; }
    public string? AppVersion { get; init; }
    public bool? ScreenLock { get; init; }
    /// <summary><c>face</c>, <c>touch</c>, <c>fingerprint</c>, <c>iris</c>, <c>none</c> or null.</summary>
    public string? Biometrics { get; init; }
    public bool Jailbroken { get; init; }
    public bool Compromised { get; init; }
    public bool HardwareKey { get; init; }
    /// <summary><c>apple-appattest</c>, <c>android-key</c> or null.</summary>
    public string? Attestation { get; init; }
    /// <summary>The latest report was signed by the phone's hardware key.</summary>
    public bool Signed { get; init; }
    public string? ReportedAt { get; init; }
    public string? LastSeenAt { get; init; }
    public string? LinkedAt { get; init; }
    /// <summary><c>healthy</c>, <c>at_risk</c>, <c>compromised</c> or <c>unknown</c>.</summary>
    public string State { get; init; } = "unknown";
    /// <summary>jailbroken, tampered, integrity_failed, no_report, stale_report, no_screen_lock, keys_lost, no_hardware_key, debugger, developer_mode.</summary>
    public IReadOnlyList<string> Issues { get; init; } = Array.Empty<string>();
}
