using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>The guard's settings for this Safe, as you read them from chain. With <c>RecipientLock</c> on, a payment or allowance outside the address book is a governance change.</summary>
public sealed record SafeGuardConfig
{
    public int Threshold { get; init; }
    public int GovThreshold { get; init; }
    /// <summary>Seconds.</summary>
    public long GovDelay { get; init; }
    /// <summary>Seconds.</summary>
    public long ExitDelay { get; init; }
    public bool? RecipientLock { get; init; }
}

/// <summary>An entry of the guard's address book: the phone names the address with its label (at most 64 bytes, no control, bidi or invisible characters).</summary>
public sealed record SafeGuardRecipient(string Address, string? Label = null);

/// <summary>The raw Safe transaction and what the phone needs to decode it like the guard.</summary>
public sealed record SafeGuardTx : SafeTxTarget
{
    public SafeGuardConfig Config { get; init; } = new();
    /// <summary>MultiSendCallOnly contracts the guard opens call by call (at most 5).</summary>
    public IReadOnlyList<string>? BatchTargets { get; init; }
    public IReadOnlyList<SafeGuardRecipient>? Recipients { get; init; }
    /// <summary>This approver's index in the guard: the approval names it.</summary>
    public int ApproverIndex { get; init; }
    /// <summary>The language of the rows on the phone: <c>tr</c> (the default) or <c>en</c>.</summary>
    public string? Locale { get; init; }
}

/// <summary>Asks one approver's phone. <c>Type</c> is an action type from your dashboard; <c>ExpiresIn</c> is seconds, 30 to 300 (default 300).</summary>
public sealed record SafeGuardRequestOptions
{
    public string ExternalUsername { get; init; } = "";
    public string Type { get; init; } = "";
    public SafeGuardTx SafeTx { get; init; } = new();
    public string? ReferenceId { get; init; }
    public int? ExpiresIn { get; init; }
    public string? ClientIp { get; init; }
    public string? UserAgent { get; init; }
}

/// <summary>Touchque's own decoding, for your logs and screens (the phone decodes for itself). <c>Class</c>: tighten, ordinary, governance or exit.</summary>
public sealed record SafeGuardDecoded : TouchqueObject
{
    public string Class { get; init; } = "";
    public IReadOnlyList<string> Flags { get; init; } = [];
    public string SafeTxHash { get; init; } = "";
    public string? GovernanceHash { get; init; }
    public IReadOnlyList<SafeDisplayRow> Rows { get; init; } = [];
}

/// <summary>A request on its way to the phone.</summary>
public sealed record SafeGuardRequestResult : TouchqueObject
{
    public string RequestId { get; init; } = "";
    public string Message { get; init; } = "";
    public string ExpiresAt { get; init; } = "";
    public string? CaseCode { get; init; }
    public SafeGuardDecoded SafeTx { get; init; } = new();
}

/// <summary>
/// Where an approval stands. <c>Purpose</c> <c>approve</c>: append to the owners' signatures; <c>schedule</c>:
/// send <c>guard.schedule</c>. <c>Approval</c> (105 bytes, 0x hex) and <c>ExpiresAt</c> (Unix seconds) are set once approved.
/// </summary>
public sealed record SafeGuardApproval : TouchqueObject
{
    public string Class { get; init; } = "";
    public IReadOnlyList<string> Flags { get; init; } = [];
    public string SafeTxHash { get; init; } = "";
    public string? GovernanceHash { get; init; }
    public string Purpose { get; init; } = "";
    public int ApproverIndex { get; init; }
    public string? Approval { get; init; }
    public long? ExpiresAt { get; init; }
}

/// <summary>A request's status. <c>Provisional</c>: given during a call or after a risky Second Thought answer; the person confirms it again later.</summary>
public sealed record SafeGuardStatus : TouchqueObject
{
    public string RequestId { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    public string Status { get; init; } = "";
    public bool Provisional { get; init; }
    public SafeGuardApproval? SafeTx { get; init; }
}

/// <summary>
/// Safe Guard: a Safe transaction approved on the approver's phone for TouchqueSafeGuard (the guard on your
/// Safe). You send the raw transaction; the phone gets the raw fields only, decodes them itself, shows its own
/// rows and signs, with a key only its biometrics unlock, a 105-byte approval of the hash it computed. Touchque
/// never holds a key that can approve.
/// <list type="number">
/// <item><see cref="RequestAsync"/> asks the phone (same pipeline as <c>Login.RequestAsync</c>: risk engine, push
/// limit, Vishing Shield, case code, always biometrics).</item>
/// <item><see cref="WaitForApprovalAsync"/> (or poll <see cref="StatusAsync"/>) until the phone answered.</item>
/// <item>Check <c>SafeTx.Approval</c> yourself with <see cref="SafeApproval.Verify"/>: it needs your own
/// transaction and the approver's key from the guard, not this answer.</item>
/// <item>Purpose <c>approve</c>: <see cref="SafeApproval.WithApprovals"/> as the signatures of
/// <c>execTransaction</c>. <c>schedule</c>: send <see cref="SafeApproval.ScheduleCall"/> to the guard; the
/// change runs once its waiting time is over.</item>
/// </list>
/// </summary>
public sealed class SafeGuardResource
{
    private readonly TouchqueHttp _http;

    internal SafeGuardResource(TouchqueHttp http) => _http = http;

    /// <summary>Asks the approver's phone to approve a Safe transaction.</summary>
    public Task<SafeGuardRequestResult> RequestAsync(SafeGuardRequestOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.ExternalUsername)) throw new TouchqueConfigException("SafeGuard.RequestAsync() needs ExternalUsername.");
        if (string.IsNullOrEmpty(options.Type)) throw new TouchqueConfigException("SafeGuard.RequestAsync() needs Type: an action type from your dashboard.");
        var body = new JsonObject
        {
            ["externalUsername"] = options.ExternalUsername,
            ["type"] = options.Type,
            ["safeTx"] = Json.ToNode(options.SafeTx),
        };
        body.Put("referenceId", options.ReferenceId).Put("expiresIn", options.ExpiresIn).Put("clientIp", options.ClientIp).Put("userAgent", options.UserAgent);
        return _http.PostAsync<SafeGuardRequestResult>("/safe-guard/approvals", body, ct);
    }

    /// <summary>The request's status and, once approved, the approval.</summary>
    public Task<SafeGuardStatus> StatusAsync(string requestId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(requestId)) throw new TouchqueConfigException("SafeGuard.StatusAsync() needs a requestId.");
        return _http.GetAsync<SafeGuardStatus>("/safe-guard/approvals/" + TouchqueHttp.Seg(requestId), null, ct);
    }

    /// <summary>Polls until the phone approved and returns the status with the approval.</summary>
    /// <exception cref="TouchqueRejectedException">The person said no.</exception>
    /// <exception cref="TouchqueTimeoutException">It expired or <paramref name="timeout"/> (default 5 minutes, the request's own life) ran out.</exception>
    public async Task<SafeGuardStatus> WaitForApprovalAsync(string requestId, TimeSpan? timeout = null, TimeSpan? pollInterval = null, CancellationToken ct = default)
    {
        var limit = timeout ?? TimeSpan.FromMinutes(5);
        var deadline = DateTimeOffset.UtcNow + limit;
        while (true)
        {
            var s = await StatusAsync(requestId, ct).ConfigureAwait(false);
            switch (s.Status)
            {
                case "CONFIRMED":
                    return s;
                case "REJECTED":
                    throw new TouchqueRejectedException(requestId);
                case "EXPIRED":
                    throw new TouchqueTimeoutException($"Touchque: request '{requestId}' expired before it was approved.", requestId);
            }
            if (DateTimeOffset.UtcNow > deadline)
            {
                throw new TouchqueTimeoutException($"Touchque: Safe Guard approval timed out after {(int)limit.TotalMilliseconds}ms.", requestId);
            }
            await Task.Delay(pollInterval ?? TimeSpan.FromMilliseconds(1500), ct).ConfigureAwait(false);
        }
    }
}
