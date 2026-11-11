using System.Globalization;
using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>
/// Touchque Mobile SDK, your backend's side: your own iOS/Android app is the
/// approver of your users (white-label); they never install the Touchque app.
/// <list type="number">
/// <item>A user signed in to your app turns approvals on: <see cref="CreateEnrollmentAsync"/> gives a one-time
/// token; your app hands it to the SDK (<c>Touchque.enroll</c>).</item>
/// <item>Ask for approvals as always (<c>Login.RequestAsync</c>, <c>StartAsync</c>, the guards): they reach your app
/// over the SDK's encrypted connection.</item>
/// <item>Without your APNs/FCM keys in <see cref="UpdateSettingsAsync"/>, Touchque sends you a signed MOBILE_PUSH
/// webhook per request: verify it, then <see cref="PushFromWebhook"/> gives the APNs payload / FCM data to
/// send with your own credentials.</item>
/// </list>
/// </summary>
public sealed class MobileResource
{
    private static readonly HashSet<string> SettingKeys = new() { "iosAppIds", "androidPackages", "androidCerts", "attestation", "enrollTtlSeconds", "apns", "fcm" };
    private readonly TouchqueHttp _http;

    internal MobileResource(TouchqueHttp http) => _http = http;

    /// <summary>
    /// A one-time enrollment token for a user you signed in. Whoever spends it becomes
    /// the user's approver, so authenticate the user first. Throws
    /// <see cref="TouchqueApiException"/> already_enrolled (pass <paramref name="replace"/>) or account_frozen.
    /// </summary>
    public Task<MobileEnrollment> CreateEnrollmentAsync(string externalUsername, bool replace = false, int? ttlSeconds = null, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(externalUsername)) throw new TouchqueConfigException("Mobile.CreateEnrollmentAsync() needs the user (externalUsername)");
        var body = new JsonObject { ["externalUsername"] = externalUsername };
        if (replace) body["replace"] = true;
        body.Put("ttlSeconds", ttlSeconds);
        return _http.PostAsync<MobileEnrollment>("/mobile/enrollments", body, ct);
    }

    /// <summary>The devices inside your app (default: active ones), newest first.</summary>
    /// <param name="status">active, revoked or all.</param>
    public Task<MobileDevices> ListDevicesAsync(string? externalUsername = null, string? status = null, int? limit = null, string? cursor = null, CancellationToken ct = default) =>
        _http.GetAsync<MobileDevices>("/mobile/devices", new Dictionary<string, string?>
        {
            ["externalUsername"] = string.IsNullOrEmpty(externalUsername) ? null : externalUsername,
            ["status"] = string.IsNullOrEmpty(status) ? null : status,
            ["limit"] = limit?.ToString(CultureInfo.InvariantCulture),
            ["cursor"] = string.IsNullOrEmpty(cursor) ? null : cursor,
        }, ct);

    public async Task<MobileDevice> GetDeviceAsync(string deviceId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(deviceId)) throw new TouchqueConfigException("Mobile.GetDeviceAsync() needs the device id");
        return Json.To<MobileDevice>((await _http.GetAsync("/mobile/devices/" + TouchqueHttp.Seg(deviceId), null, ct).ConfigureAwait(false))?["device"]);
    }

    /// <summary>Stops a device from approving (the user has no approver until you enrol again).</summary>
    public Task<JsonObject> RemoveDeviceAsync(string deviceId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(deviceId)) throw new TouchqueConfigException("Mobile.RemoveDeviceAsync() needs the device id");
        return _http.DeleteAsync<JsonObject>("/mobile/devices/" + TouchqueHttp.Seg(deviceId), ct);
    }

    /// <summary>
    /// A harmless push to the device, the way a request would reach it: via <c>touchque</c> (your key
    /// for its platform) or <c>webhook</c> (MOBILE_PUSH, kind test). <c>Ok</c>: APNs / FCM accepted it.
    /// </summary>
    public Task<MobileTestPush> TestPushAsync(string deviceId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(deviceId)) throw new TouchqueConfigException("Mobile.TestPushAsync() needs the device id");
        return _http.PostAsync<MobileTestPush>("/mobile/devices/" + TouchqueHttp.Seg(deviceId) + "/test-push", new JsonObject(), ct);
    }

    public async Task<MobileSettings> SettingsAsync(CancellationToken ct = default) =>
        Json.To<MobileSettings>((await _http.GetAsync("/mobile/settings", null, ct).ConfigureAwait(false))?["settings"]);

    /// <summary>
    /// Which apps may enrol, whether they must prove themselves, and your push keys. Only the
    /// keys given change: iosAppIds, androidPackages, androidCerts (package → SHA-256 of its
    /// signing certificates), attestation (off | optional | required), enrollTtlSeconds, apns
    /// (keyId, teamId, topic, key = the .p8 text, production: Touchque then sends the iOS push),
    /// fcm (serviceAccount = the JSON: the Android push); null removes a key. The keys are never shown back.
    /// </summary>
    public async Task<MobileSettings> UpdateSettingsAsync(object changes, CancellationToken ct = default)
    {
        var body = changes as JsonObject ?? System.Text.Json.JsonSerializer.SerializeToNode(changes, KeepNulls) as JsonObject
            ?? throw new TouchqueConfigException("Mobile.UpdateSettingsAsync() takes an object of settings");
        var unknown = body.Select(p => p.Key).Where(k => !SettingKeys.Contains(k)).ToList();
        if (unknown.Count > 0) throw new TouchqueConfigException("Mobile.UpdateSettingsAsync(): unknown setting " + string.Join(", ", unknown));
        return Json.To<MobileSettings>((await _http.PutAsync("/mobile/settings", body.DeepClone(), ct).ConfigureAwait(false))?["settings"]);
    }

    private static readonly System.Text.Json.JsonSerializerOptions KeepNulls =
        new(Json.Options) { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never };

    /// <summary>
    /// The push to send for a verified MOBILE_PUSH webhook, or null for any other event.
    /// No secret, no details, no number in it.
    /// </summary>
    public static MobilePush? PushFromWebhook(JsonObject? webhookEvent)
    {
        if (webhookEvent is null || Json.Str(webhookEvent, "event") != "MOBILE_PUSH") return null;
        var data = webhookEvent["data"] as JsonObject;
        var t = data?["touchque"];
        var touchque = t is JsonValue tv && tv.TryGetValue<string>(out var s) ? s : (t is null ? "{}" : t.ToJsonString());
        var aps = new JsonObject { ["sound"] = "default", ["interruption-level"] = "time-sensitive" };
        JsonObject? alert = null;
        if (webhookEvent["alert"] is JsonObject a)
        {
            alert = new JsonObject { ["title"] = Json.Str(a, "title") ?? "", ["body"] = Json.Str(a, "body") ?? "" };
            aps["alert"] = alert.DeepClone();
        }
        var kind = Json.Str(webhookEvent, "kind");
        return new MobilePush
        {
            DeviceId = Json.Str(webhookEvent, "deviceId"),
            ExternalUsername = Json.Str(webhookEvent, "externalUsername"),
            Platform = Json.Str(webhookEvent, "platform") == "android" ? "android" : "ios",
            PushToken = Json.Str(webhookEvent, "pushToken"),
            RequestId = Json.Str(webhookEvent, "requestId"),
            ExpiresAt = Json.Str(webhookEvent, "expiresAt"),
            // test: a test push sent from the dashboard
            Kind = kind is "notice" or "test" ? kind : "approval",
            Alert = alert,
            Apns = new JsonObject { ["aps"] = aps, ["touchque"] = touchque },
            FcmData = new Dictionary<string, string> { ["touchque"] = touchque },
        };
    }
}

/// <summary>A MOBILE_PUSH webhook, ready to send with your own APNs / FCM credentials.</summary>
public sealed record MobilePush
{
    public string? DeviceId { get; init; }
    public string? ExternalUsername { get; init; }
    /// <summary>ios or android.</summary>
    public string Platform { get; init; } = "ios";
    /// <summary>The token your app handed to the SDK; null: send by your own user → device mapping.</summary>
    public string? PushToken { get; init; }
    public string? RequestId { get; init; }
    public string? ExpiresAt { get; init; }
    /// <summary>approval, notice or test.</summary>
    public string Kind { get; init; } = "approval";
    /// <summary>Suggested text (English); translate or replace it.</summary>
    public JsonObject? Alert { get; init; }
    /// <summary>The APNs payload: the alert plus the custom key <c>touchque</c>.</summary>
    public JsonObject Apns { get; init; } = new();
    /// <summary>The FCM data map (a data message; your app builds the notification).</summary>
    public IReadOnlyDictionary<string, string> FcmData { get; init; } = new Dictionary<string, string>();

    /// <summary>True once the push is past its request's expiry (don't send it any more).</summary>
    public bool IsExpired(DateTimeOffset? now = null) =>
        ExpiresAt is not null && DateTimeOffset.TryParse(ExpiresAt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at) && at <= (now ?? DateTimeOffset.UtcNow);
}

public sealed record MobileEnrollment : TouchqueObject
{
    public string EnrollmentId { get; init; } = "";
    /// <summary>The one-time <c>tqe_</c> token your app spends with the Mobile SDK.</summary>
    public string EnrollmentToken { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    public string? ExpiresAt { get; init; }
    public bool Replace { get; init; }
    public string? ReplacesDeviceId { get; init; }
}

public sealed record MobileHardwareKey : TouchqueObject
{
    public bool Registered { get; init; }
    public string? Attestation { get; init; }
    public string? LostAt { get; init; }
}

public sealed record MobileDevice : TouchqueObject
{
    public string DeviceId { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    public string? Platform { get; init; }
    public string? AppId { get; init; }
    public string? SdkVersion { get; init; }
    public string? Attestation { get; init; }
    public string Status { get; init; } = "";
    public string? RevokedReason { get; init; }
    public string? RevokedAt { get; init; }
    public string? EnrolledAt { get; init; }
    public string? LastSeenAt { get; init; }
    public bool? Linked { get; init; }
    public MobileHardwareKey? HardwareKey { get; init; }
    public bool PushToken { get; init; }
    public JsonObject? Posture { get; init; }
}

public sealed record MobileDevices : TouchqueObject
{
    public IReadOnlyList<MobileDevice> Devices { get; init; } = Array.Empty<MobileDevice>();
    public string? NextCursor { get; init; }
}

public sealed record MobileApnsInfo : TouchqueObject
{
    public string? KeyId { get; init; }
    public string? TeamId { get; init; }
    public string? Topic { get; init; }
    public bool Production { get; init; }
}

public sealed record MobileFcmInfo : TouchqueObject
{
    public string? ProjectId { get; init; }
    public string? ClientEmail { get; init; }
}

public sealed record MobilePushSettings : TouchqueObject
{
    /// <summary>Who pushes to iOS: touchque or webhook.</summary>
    public string? Ios { get; init; }
    public string? Android { get; init; }
    public MobileApnsInfo? Apns { get; init; }
    public MobileFcmInfo? Fcm { get; init; }
}

public sealed record MobileSettings : TouchqueObject
{
    public IReadOnlyList<string>? IosAppIds { get; init; }
    public IReadOnlyList<string>? AndroidPackages { get; init; }
    public Dictionary<string, List<string>>? AndroidCerts { get; init; }
    /// <summary>off, optional or required.</summary>
    public string? Attestation { get; init; }
    public int? EnrollTtlSeconds { get; init; }
    public MobilePushSettings? Push { get; init; }
    public string? UpdatedAt { get; init; }
}

public sealed record MobileTestPush : TouchqueObject
{
    /// <summary>touchque or webhook.</summary>
    public string Via { get; init; } = "";
    public bool Ok { get; init; }
    public string? Reason { get; init; }
}
