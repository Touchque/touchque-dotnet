using System.Text.Json.Nodes;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>Setup secrets (the QR code the TouchQue app scans) and a user's link status.</summary>
public sealed class AuthResource
{
    private readonly TouchQueHttp _http;

    internal AuthResource(TouchQueHttp http) => _http = http;

    /// <summary>
    /// A new setup secret for a user: show <see cref="GenerateSecretResult.QrCodeDataUrl"/> so
    /// the TouchQue app links the phone. 409 when an unscanned or used secret exists
    /// (<see cref="ResetSecretAsync"/> issues a new one).
    /// </summary>
    public Task<GenerateSecretResult> GenerateSecretAsync(string externalUsername, CancellationToken ct = default) =>
        _http.PostAsync<GenerateSecretResult>("/auth/generate-secret", new JsonObject { ["externalUsername"] = externalUsername }, ct);

    /// <summary>Regenerates a user's secret.</summary>
    public Task<ResetSecretResult> ResetSecretAsync(string externalUsername, CancellationToken ct = default) =>
        _http.PostAsync<ResetSecretResult>("/auth/secret/reset", new JsonObject { ["externalUsername"] = externalUsername }, ct);

    /// <summary>Checks a setup secret code.</summary>
    public Task<ValidateSecretResult> ValidateSecretAsync(string secret, CancellationToken ct = default) =>
        _http.PostAsync<ValidateSecretResult>("/auth/secret/validate", new JsonObject { ["secret"] = secret }, ct);

    /// <summary>
    /// A user's link status without sending a push: <see cref="TouchQueUser.Used"/> flips true and
    /// <see cref="TouchQueUser.DeviceId"/> is set once the app scans the secret.
    /// <see cref="TouchQueUser.Device"/> is the linked phone's self-reported posture (device trust).
    /// Throws <see cref="TouchQueApiException"/> (404) for an unknown user.
    /// </summary>
    public Task<TouchQueUser> GetUserAsync(string externalUsername, CancellationToken ct = default) =>
        _http.GetAsync<TouchQueUser>("/users/" + TouchQueHttp.Seg(externalUsername), null, ct);
}

public sealed record GenerateSecretResult : TouchQueObject
{
    public string Secret { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    public string? ExpiresAt { get; init; }
    public long? TtlMs { get; init; }
    /// <summary>A ready-to-render <c>data:image/png;base64,…</c> QR code for the TouchQue app.</summary>
    public string? QrCodeDataUrl { get; init; }
    public IReadOnlyList<string>? RecoveryCodes { get; init; }
}

public sealed record ResetSecretResult : TouchQueObject
{
    public string? Message { get; init; }
    public string? UserId { get; init; }
    public string Secret { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    public string? ExpiresAt { get; init; }
    public string? QrCodeDataUrl { get; init; }
    public IReadOnlyList<string>? RecoveryCodes { get; init; }
}

public sealed record ValidateSecretResult : TouchQueObject
{
    public bool Valid { get; init; }
    public string? ExternalUsername { get; init; }
    public string? IntegrationId { get; init; }
    public string? Message { get; init; }
    public string? Reason { get; init; }
    public string? UsedAt { get; init; }
    public string? ExpiredAt { get; init; }
}

/// <summary>A user as TouchQue knows them.</summary>
public sealed record TouchQueUser : TouchQueObject
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
public sealed record DevicePosture : TouchQueObject
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
