using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>
/// Never Locked Out: move a user whose phone is lost, dead or replaced to a new
/// phone without a help desk.
/// <list type="number">
/// <item>Let users name colleagues who can vouch for them (<see cref="SetVouchersAsync"/>), behind an approval on their phone.</item>
/// <item>When the phone is gone, after the password (or your IdP): <see cref="StartAsync"/>. Show <c>BindUri</c> as a QR
/// for the Touchque app on the new phone, then poll <see cref="StatusAsync"/> and show each voucher's <c>Code</c>:
/// the user reads it to the colleague on a call, who types it on their own phone.</item>
/// <item>After a cooling-off nobody vetoed, the account is on the new phone (<c>COMPLETED</c>); critical actions wait 24 h.</item>
/// </list>
/// Admins can stop a running recovery with <see cref="VetoAsync"/>.
/// </summary>
public sealed class RecoveryResource
{
    /// <summary>Statuses of a recovery still waiting for the new phone, the vouchers or the cooling-off.</summary>
    public static readonly IReadOnlyList<string> OpenStatuses = new[] { "AWAITING_DEVICE", "VOUCHING", "COOLING" };

    private readonly TouchqueHttp _http;

    internal RecoveryResource(TouchqueHttp http) => _http = http;

    /// <summary>The colleagues a user named, and whether each can vouch today.</summary>
    public Task<RecoveryVouchers> VouchersAsync(string externalUsername, CancellationToken ct = default)
    {
        Require("VouchersAsync", "externalUsername", externalUsername);
        return _http.GetAsync<RecoveryVouchers>("/recovery/vouchers", new Dictionary<string, string?> { ["externalUsername"] = externalUsername }, ct);
    }

    /// <summary>
    /// Replaces the user's vouchers (at most 5 are kept). Ask for the user's phone
    /// first: whoever sets them chooses who may move the account.
    /// </summary>
    public Task<RecoveryVouchers> SetVouchersAsync(string externalUsername, IEnumerable<string> vouchers, CancellationToken ct = default)
    {
        Require("SetVouchersAsync", "externalUsername", externalUsername);
        var body = new JsonObject
        {
            ["externalUsername"] = externalUsername,
            ["vouchers"] = new JsonArray(vouchers.Select(v => (JsonNode)v).ToArray()),
        };
        return _http.PostAsync<RecoveryVouchers>("/recovery/vouchers", body, ct);
    }

    /// <summary>
    /// Starts moving the user to a new phone. Call it only after the first factor.
    /// Throws <see cref="TouchqueApiException"/> with code not_enough_vouchers,
    /// recovery_in_progress, blocked, frozen or rate_limited.
    /// </summary>
    public Task<RecoveryCase> StartAsync(StartRecoveryOptions options, CancellationToken ct = default)
    {
        Require("StartAsync", "the user (ExternalUsername)", options.ExternalUsername);
        if (options.Required is < 1 || options.CoolOffMinutes is < 1)
        {
            throw new TouchqueConfigException("Recovery.StartAsync(): Required and CoolOffMinutes must be positive integers");
        }
        var body = new JsonObject { ["externalUsername"] = options.ExternalUsername };
        body.Put("clientIp", options.ClientIp).Put("userAgent", options.UserAgent).Put("displayName", options.DisplayName);
        if (options.FallbackVouchers is { Count: > 0 }) body["fallbackVouchers"] = new JsonArray(options.FallbackVouchers.Select(v => (JsonNode)v).ToArray());
        body.Put("required", options.Required).Put("coolOffMinutes", options.CoolOffMinutes);
        if (options.Details is { Count: > 0 }) body["details"] = LoginRequestOptions.DetailsJson(options.Details);
        if (options.NoticeDetails is { Count: > 0 }) body["noticeDetails"] = LoginRequestOptions.DetailsJson(options.NoticeDetails);
        return _http.PostAsync<RecoveryCase>("/recovery/start", body, ct);
    }

    /// <summary>The recovery now, with its receipt chain. Poll it while the user waits.</summary>
    public Task<RecoveryCase> StatusAsync(string recoveryId, CancellationToken ct = default)
    {
        Require("StatusAsync", "recoveryId", recoveryId);
        return _http.GetAsync<RecoveryCase>("/recovery/" + TouchqueHttp.Seg(recoveryId), null, ct);
    }

    /// <summary>A user's recoveries, or (<paramref name="open"/>) every running one of your workspace.</summary>
    public async Task<IReadOnlyList<RecoveryCase>> ListAsync(string? externalUsername = null, bool open = false, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(externalUsername) && !open)
        {
            throw new TouchqueConfigException("Recovery.ListAsync() needs externalUsername or open: true");
        }
        var res = await _http.GetAsync("/recovery", new Dictionary<string, string?>
        {
            ["externalUsername"] = string.IsNullOrEmpty(externalUsername) ? null : externalUsername,
            ["open"] = open ? "true" : null,
        }, ct).ConfigureAwait(false);
        return res?["recoveries"] is JsonArray ? Json.To<List<RecoveryCase>>(res["recoveries"]) : new List<RecoveryCase>();
    }

    /// <summary>Stops a running recovery (e.g. an admin who does not believe it). Does not freeze the user.</summary>
    public Task<RecoveryCase> VetoAsync(string recoveryId, string? by = null, string? reason = null, CancellationToken ct = default)
    {
        Require("VetoAsync", "recoveryId", recoveryId);
        return _http.PostAsync<RecoveryCase>("/recovery/" + TouchqueHttp.Seg(recoveryId) + "/veto", new JsonObject().Put("by", by).Put("reason", reason), ct);
    }

    private static void Require(string method, string what, string? value)
    {
        if (string.IsNullOrEmpty(value)) throw new TouchqueConfigException($"Recovery.{method}() needs {what}");
    }
}

public sealed record StartRecoveryOptions
{
    public required string ExternalUsername { get; init; }
    public string? ClientIp { get; init; }
    public string? UserAgent { get; init; }
    public string? DisplayName { get; init; }
    /// <summary>Fill up a short named list, e.g. with the organization's admins.</summary>
    public IReadOnlyList<string>? FallbackVouchers { get; init; }
    /// <summary>Raise the floor of 2 vouchers.</summary>
    public int? Required { get; init; }
    /// <summary>Raise the floor of 15 minutes.</summary>
    public int? CoolOffMinutes { get; init; }
    /// <summary>What the vouchers' phones show.</summary>
    public IReadOnlyList<LoginDetail>? Details { get; init; }
    /// <summary>What the old phone shows (approve to move now, reject to stop).</summary>
    public IReadOnlyList<LoginDetail>? NoticeDetails { get; init; }
}

public sealed record RecoveryVoucherEligibility : TouchqueObject
{
    public string ExternalUsername { get; init; } = "";
    public bool Eligible { get; init; }
    /// <summary>Why not (e.g. no_phone).</summary>
    public string? Reason { get; init; }
}

public sealed record RecoveryVouchers : TouchqueObject
{
    public string ExternalUsername { get; init; } = "";
    public IReadOnlyList<RecoveryVoucherEligibility> Vouchers { get; init; } = Array.Empty<RecoveryVoucherEligibility>();
    public string? UpdatedAt { get; init; }
    public string? ProbationUntil { get; init; }
}

public sealed record RecoveryVoucherState : TouchqueObject
{
    public string ExternalUsername { get; init; } = "";
    /// <summary>nominated or fallback.</summary>
    public string? Source { get; init; }
    public string State { get; init; } = "";
    /// <summary>The code the user reads to this voucher.</summary>
    public string? Code { get; init; }
}

public sealed record RecoveryOldPhone : TouchqueObject
{
    public bool Notified { get; init; }
    public string? Code { get; init; }
}

public sealed record RecoveryReceipt : TouchqueObject
{
    public int Seq { get; init; }
    public string? At { get; init; }
    public string? Step { get; init; }
    public JsonObject? Actor { get; init; }
    public JsonObject? Data { get; init; }
    public string? Prev { get; init; }
    public string? Hash { get; init; }
}

public sealed record RecoveryCase : TouchqueObject
{
    public string RecoveryId { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    public string? Method { get; init; }
    /// <summary>AWAITING_DEVICE, VOUCHING, COOLING, COMPLETED, VETOED, EXPIRED…</summary>
    public string Status { get; init; } = "";
    public int Required { get; init; }
    public int Approvals { get; init; }
    public IReadOnlyList<RecoveryVoucherState> Vouchers { get; init; } = Array.Empty<RecoveryVoucherState>();
    public RecoveryOldPhone? OldPhone { get; init; }
    public int CoolOffMinutes { get; init; }
    public string? CoolOffUntil { get; init; }
    public bool Elevated { get; init; }
    public IReadOnlyList<string>? Reasons { get; init; }
    public string? Location { get; init; }
    public bool NewPhoneBound { get; init; }
    public string? ExpiresAt { get; init; }
    public string? CompletedAt { get; init; }
    public string? EndedReason { get; init; }
    public string? EndedBy { get; init; }
    public string? CreatedAt { get; init; }
    public IReadOnlyList<RecoveryReceipt>? Receipts { get; init; }
    /// <summary>Start only: the code the new phone's app types.</summary>
    public string? BindCode { get; init; }
    /// <summary>Start only: show it as a QR for the Touchque app on the new phone.</summary>
    public string? BindUri { get; init; }

    /// <summary>Still waiting for the new phone, the vouchers or the cooling-off.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsOpen => RecoveryResource.OpenStatuses.Contains(Status);
}
