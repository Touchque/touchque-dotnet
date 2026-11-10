using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>
/// Pairing a browser by QR code: your page shows a QR code, the person scans it with the TouchQue app,
/// and the phone that scanned is the one asked to approve.
/// <list type="number">
/// <item>Your page gets the thumbprint of its browser key (<c>@touchque/web</c> <c>browserKey.thumbprint()</c>)
/// and sends it to your server.</item>
/// <item><see cref="CreateAsync"/> registers a pairing and returns <c>Uri</c> (<c>touchque://pair-browser?…</c>):
/// show it as a QR code. It can be scanned once, for <c>TtlSeconds</c> (default 120). The nonce in it never
/// leaves your server and the QR: TouchQue keeps only its hash.</item>
/// <item>Poll <see cref="GetAsync"/>: <c>scanned</c> once a phone holding one of your users' accounts read it
/// (<c>ExternalUsername</c>, <c>Proximity</c>), <c>confirmed</c> once the person went on, <c>reported</c> when
/// they said someone told them to scan it (their 2FA freezes).</item>
/// <item><c>Login.RequestAsync</c> with <c>QrPairing</c> asks that phone, once, with number matching; the
/// browser key's fingerprint is one of the rows the phone signs. When your own checks say no,
/// <see cref="RefuseAsync"/>, and the phone shows why.</item>
/// </list>
/// </summary>
public sealed partial class QrPairingsResource
{
    /// <summary>What <see cref="RefuseAsync"/> may tell the phone.</summary>
    public static readonly IReadOnlyList<string> RefusalReasons = ["policy", "device_not_approved", "too_many_browsers", "rate_limited", "no_account", "other"];

    private readonly TouchQueHttp _http;

    internal QrPairingsResource(TouchQueHttp http) => _http = http;

    [GeneratedRegex("^[A-Za-z0-9_-]{43}$")]
    private static partial Regex Base64Url43();

    /// <summary>What the QR code says: <c>touchque://pair-browser?v=1&amp;p=&lt;pairing&gt;&amp;n=&lt;nonce&gt;&amp;k=&lt;key thumbprint&gt;</c>.</summary>
    public static string Uri(string pairingId, string nonce, string keyThumbprint) =>
        $"touchque://pair-browser?v=1&p={System.Uri.EscapeDataString(pairingId)}&n={System.Uri.EscapeDataString(nonce)}&k={System.Uri.EscapeDataString(keyThumbprint)}";

    /// <summary>Registers a pairing for one browser and returns the QR code's text.</summary>
    public async Task<CreatedQrPairing> CreateAsync(CreateQrPairingOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.KeyThumbprint) || !Base64Url43().IsMatch(options.KeyThumbprint))
            throw new TouchQueConfigException("QrPairings.CreateAsync() needs KeyThumbprint: the RFC 7638 thumbprint of the browser key, base64url (43 characters).");
        if (options.TtlSeconds is { } ttl && (ttl < 30 || ttl > 300))
            throw new TouchQueConfigException("QrPairings.CreateAsync(): TtlSeconds must be 30 to 300.");
        var nonce = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        var body = new JsonObject
        {
            ["nonceHash"] = Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(nonce))),
            ["keyThumbprint"] = options.KeyThumbprint,
        };
        body.Put("clientIp", Empty(options.ClientIp)).Put("userAgent", Empty(options.UserAgent))
            .Put("browser", Empty(options.Browser)).Put("os", Empty(options.Os)).Put("ttlSeconds", options.TtlSeconds);
        var created = await _http.PostAsync<JsonObject>("/qr-pairings", body, ct).ConfigureAwait(false);
        var pairingId = Json.Str(created, "pairingId") ?? "";
        return new CreatedQrPairing(pairingId, Json.Str(created, "expiresAt") ?? "", nonce, Uri(pairingId, nonce, options.KeyThumbprint));
    }

    /// <summary>Where a pairing stands; once scanned, who scanned it and how near the phone was.</summary>
    public Task<QrPairing> GetAsync(string pairingId, CancellationToken ct = default) =>
        _http.GetAsync<QrPairing>("/qr-pairings/" + Id(pairingId, "GetAsync"), null, ct);

    /// <summary>
    /// Your own checks refused a scanned pairing (an unapproved computer, too many browsers…): the phone shows
    /// <c>Message</c>. Only a <c>scanned</c> or <c>confirmed</c> pairing can be refused (409 <c>not_open</c> otherwise).
    /// </summary>
    public Task<QrPairing> RefuseAsync(string pairingId, RefuseQrPairingOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var path = "/qr-pairings/" + Id(pairingId, "RefuseAsync") + "/outcome";
        if (!RefusalReasons.Contains(options.Reason))
            throw new TouchQueConfigException("QrPairings.RefuseAsync(): Reason must be one of " + string.Join(", ", RefusalReasons) + ".");
        if (string.IsNullOrWhiteSpace(options.Message))
            throw new TouchQueConfigException("QrPairings.RefuseAsync() needs Message: what the phone shows (up to 300 characters).");
        var body = new JsonObject { ["reason"] = options.Reason, ["message"] = options.Message };
        body.Put("caseCode", Empty(options.CaseCode)).Put("deviceCode", Empty(options.DeviceCode));
        return _http.PostAsync<QrPairing>(path, body, ct);
    }

    private static string? Empty(string? value) => string.IsNullOrEmpty(value) ? null : value;

    private static string Id(string pairingId, string method) =>
        string.IsNullOrEmpty(pairingId) ? throw new TouchQueConfigException($"QrPairings.{method}() needs the pairing id.") : TouchQueHttp.Seg(pairingId);
}

/// <summary>A pairing to register for one browser.</summary>
public sealed record CreateQrPairingOptions
{
    /// <summary>RFC 7638 thumbprint of the browser's key, base64url (<c>@touchque/web</c> <c>browserKey.thumbprint()</c>).</summary>
    public required string KeyThumbprint { get; init; }
    /// <summary>The end user's IP: the phone is told where the browser is and whether it is on the same network.</summary>
    public string? ClientIp { get; init; }
    public string? UserAgent { get; init; }
    /// <summary>A short name the phone shows, e.g. "Chrome 155".</summary>
    public string? Browser { get; init; }
    /// <summary>E.g. "macOS 15".</summary>
    public string? Os { get; init; }
    /// <summary>How long the QR code can be scanned: 30 to 300 seconds (default 120).</summary>
    public int? TtlSeconds { get; init; }
}

/// <summary>A registered pairing: show <c>Uri</c> as a QR code. <c>Nonce</c> is the one-time nonce in it (TouchQue keeps its SHA-256).</summary>
public sealed record CreatedQrPairing(string PairingId, string ExpiresAt, string Nonce, string Uri);

/// <summary>Where a pairing stands.</summary>
public sealed record QrPairing : TouchQueObject
{
    public string PairingId { get; init; } = "";
    /// <summary>waiting, scanned, confirmed, requested, approved, refused, reported or expired.</summary>
    public string State { get; init; } = "";
    public string KeyThumbprint { get; init; } = "";
    public string ExpiresAt { get; init; } = "";
    /// <summary>The login request made with this pairing, once asked.</summary>
    public string? RequestId { get; init; }
    /// <summary>Set once scanned: the user whose account is on the phone that scanned.</summary>
    public string? ExternalUsername { get; init; }
    public string? ScannedAt { get; init; }
    public string? ConfirmedAt { get; init; }
    public QrPairingPlace? Phone { get; init; }
    public QrPairingPlace? Browser { get; init; }
    public QrPairingProximity? Proximity { get; init; }
    /// <summary>Why it was refused (by you, or declined on the phone).</summary>
    public QrPairingOutcome? Outcome { get; init; }
    /// <summary>The person said someone told them to scan it: their 2FA is frozen.</summary>
    public string? ReportedAt { get; init; }
}

/// <summary>Where the phone or the browser is.</summary>
public sealed record QrPairingPlace(string? Country, string? Location);

/// <summary>How near the phone was to the browser; <c>Warnings</c>: <c>different_country</c>, <c>different_network</c>.</summary>
public sealed record QrPairingProximity(bool? SameNetwork, bool? SameCountry, IReadOnlyList<string> Warnings);

/// <summary>Why a pairing was refused.</summary>
public sealed record QrPairingOutcome(string Reason, string Message, string? CaseCode, string? DeviceCode, string At);

/// <summary>Your own refusal of a scanned pairing.</summary>
public sealed record RefuseQrPairingOptions
{
    /// <summary>One of <see cref="QrPairingsResource.RefusalReasons"/>.</summary>
    public required string Reason { get; init; }
    /// <summary>What the phone shows, up to 300 characters of plain text.</summary>
    public required string Message { get; init; }
    /// <summary>A "Why?" case code for your support team (<c>ABC-123</c>).</summary>
    public string? CaseCode { get; init; }
    /// <summary>Your code for the computer (<c>ABC-123</c>), shown on the phone.</summary>
    public string? DeviceCode { get; init; }
}
