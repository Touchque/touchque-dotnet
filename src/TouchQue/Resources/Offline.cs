using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>Offline Sign: QR challenge and typed-code approvals that work with the phone offline.</summary>
public sealed class OfflineResource
{
    private const string CodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private readonly TouchQueHttp _http;

    internal OfflineResource(TouchQueHttp http) => _http = http;

    /// <summary>
    /// Issues an offline QR challenge. With number matching the answer has
    /// <c>ChallengeCode</c>: print it under the QR; the phone offers it among two decoys.
    /// Details are REQUIRED for critical action types. Always pass
    /// <see cref="OfflineChallengeOptions.RequestId"/> when the QR follows a push: a
    /// phone-side rejection then kills the QR.
    /// </summary>
    public Task<OfflineChallenge> ChallengeAsync(OfflineChallengeOptions options, CancellationToken ct = default)
    {
        var body = new JsonObject { ["externalUsername"] = options.ExternalUsername, ["type"] = string.IsNullOrEmpty(options.Type) ? "LOGIN" : options.Type };
        if (options.Details is not null) body["details"] = LoginRequestOptions.DetailsJson(options.Details);
        body.Put("clientIp", options.ClientIp).Put("userAgent", options.UserAgent).Put("ttlSeconds", options.TtlSeconds);
        if (!options.IncludeQrImage) body["includeQrImage"] = false;
        body.Put("requestId", options.RequestId);
        if (options.RequireNumberMatch) body["requireNumberMatch"] = true;
        return _http.PostAsync<OfflineChallenge>("/offline/challenge", body, ct);
    }

    /// <summary>
    /// Verifies the 7-character code the phone shows. Never throws for a wrong,
    /// expired or used code: check <c>Approved</c>; <c>Reason</c> is invalid_code,
    /// locked, expired, used, unknown_challenge, request_rejected, too_many_failures or device_not_enrolled.
    /// </summary>
    public Task<OfflineVerifyResult> VerifyAsync(string challengeId, string code, CancellationToken ct = default) =>
        NotApprovedAsResult(() => _http.PostAsync<OfflineVerifyResult>("/offline/verify", new JsonObject { ["challengeId"] = challengeId, ["code"] = code }, ct));

    /// <summary>
    /// Verifies the rolling time-based code (no QR scan needed). Refused for critical
    /// action types. <paramref name="requestId"/>: the push this sign-in belongs to; a
    /// code is refused (request_rejected) once the phone rejected it.
    /// </summary>
    public Task<OfflineVerifyResult> VerifyTotpAsync(string externalUsername, string code, string type = "LOGIN", string? clientIp = null, string? requestId = null, CancellationToken ct = default)
    {
        var body = new JsonObject { ["externalUsername"] = externalUsername, ["code"] = code, ["type"] = type };
        body.Put("clientIp", clientIp).Put("requestId", requestId);
        return NotApprovedAsResult(() => _http.PostAsync<OfflineVerifyResult>("/offline/totp/verify", body, ct));
    }

    /// <summary>
    /// For checking typed time-based codes while your server cannot reach TouchQue (an
    /// outage): salted, slow digests of each user's next codes, never a key. Up to 1,000
    /// users and 24,000 user-steps a call; <paramref name="steps"/> 1-480 (default 480,
    /// four hours). Check a code with <see cref="MatchTotpVerifier"/>. Requires the
    /// workspace policies offlineTotpEnabled and outageVerifiersEnabled.
    /// </summary>
    public Task<OfflineTotpVerifiers> TotpVerifiersAsync(IEnumerable<string> externalUsernames, long? fromStep = null, int? steps = null, CancellationToken ct = default)
    {
        var body = new JsonObject { ["externalUsernames"] = new JsonArray(externalUsernames.Select(u => (JsonNode)u).ToArray()) };
        body.Put("fromStep", fromStep).Put("steps", steps);
        return _http.PostAsync<OfflineTotpVerifiers>("/offline/totp/verifiers", body, ct);
    }

    /// <summary>
    /// Checks a typed code against one user's digests without calling TouchQue: the
    /// step the code belongs to (the current one or one either side), or null.
    /// Accept each step once: remember the step you accepted and refuse codes for it or an older one.
    /// </summary>
    public static long? MatchTotpVerifier(OfflineTotpVerifiers verifiers, OfflineTotpVerifierUser user, string code, DateTimeOffset? at = null)
    {
        var given = code.ToUpperInvariant().Replace(" ", "").Replace("-", "").Replace("\t", "");
        if (given.Length != 7 || given.Any(c => CodeAlphabet.IndexOf(c) < 0) || verifiers.StepSeconds <= 0) return null;
        byte[] salt, digests;
        try
        {
            salt = Convert.FromBase64String(user.Salt);
            digests = Convert.FromBase64String(user.Digests);
        }
        catch (FormatException)
        {
            return null;
        }
        var length = verifiers.Kdf.Length;
        if (length <= 0) return null;
        var now = (at ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() / verifiers.StepSeconds;
        foreach (var step in new[] { now, now - 1, now + 1 })
        {
            if (step < user.FromStep || step > verifiers.NotAfterStep) continue;
            var i = (int)(step - user.FromStep) * 2 * length;
            if (i + 2 * length > digests.Length) continue;
            var s = salt.Concat(Encoding.UTF8.GetBytes(":" + step)).ToArray();
            var got = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(given), s, verifiers.Kdf.Iterations, HashAlgorithmName.SHA256, length);
            if (CryptographicOperations.FixedTimeEquals(digests.AsSpan(i, length), got) ||
                CryptographicOperations.FixedTimeEquals(digests.AsSpan(i + length, length), got))
            {
                return step;
            }
        }
        return null;
    }

    private static async Task<OfflineVerifyResult> NotApprovedAsResult(Func<Task<OfflineVerifyResult>> call)
    {
        try
        {
            return await call().ConfigureAwait(false);
        }
        catch (TouchQueApiException e) when (e.Status < 500)
        {
            return new OfflineVerifyResult { Approved = false, Reason = e.Reason ?? e.Code ?? e.Error, AttemptsLeft = e.AttemptsLeft };
        }
    }
}

public sealed record OfflineChallengeOptions
{
    public required string ExternalUsername { get; init; }
    public string Type { get; init; } = "LOGIN";
    public IReadOnlyList<LoginDetail>? Details { get; init; }
    public string? ClientIp { get; init; }
    public string? UserAgent { get; init; }
    /// <summary>30-300 (default 120).</summary>
    public int? TtlSeconds { get; init; }
    /// <summary>False: no <c>QrDataUrl</c> image, only the <c>Qr</c> text.</summary>
    public bool IncludeQrImage { get; init; } = true;
    /// <summary>The push this QR is a fallback for.</summary>
    public string? RequestId { get; init; }
    public bool RequireNumberMatch { get; init; }
}

public sealed record OfflineChallenge : TouchQueObject
{
    public string ChallengeId { get; init; } = "";
    public string? Qr { get; init; }
    public string? QrDataUrl { get; init; }
    public string? ExpiresAt { get; init; }
    public int? ExpiresInSeconds { get; init; }
    public bool TotpAvailable { get; init; }
    /// <summary>Number matching: print it under the QR.</summary>
    public string? ChallengeCode { get; init; }
}

public sealed record OfflineVerifyResult : TouchQueObject
{
    public bool Approved { get; init; }
    public string? Reason { get; init; }
    public int? AttemptsLeft { get; init; }
    public string? ChallengeId { get; init; }
    /// <summary>The user the code belongs to (trust this, never a name the browser sent).</summary>
    public string? ExternalUsername { get; init; }
    public string? Type { get; init; }
}

public sealed record OfflineTotpVerifierUser : TouchQueObject
{
    public string ExternalUsername { get; init; } = "";
    public long FromStep { get; init; }
    /// <summary>base64, 16 bytes.</summary>
    public string Salt { get; init; } = "";
    /// <summary>base64, two digests a step from FromStep.</summary>
    public string Digests { get; init; } = "";
}

public sealed record OfflineTotpKdf : TouchQueObject
{
    public string Name { get; init; } = "";
    public int Iterations { get; init; }
    public int Length { get; init; }
}

public sealed record OfflineTotpVerifiers : TouchQueObject
{
    public long StepSeconds { get; init; }
    public long FromStep { get; init; }
    public int Steps { get; init; }
    public long NotAfterStep { get; init; }
    public OfflineTotpKdf Kdf { get; init; } = new();
    /// <summary>Only users who can use time-based codes now.</summary>
    public IReadOnlyList<OfflineTotpVerifierUser> Users { get; init; } = Array.Empty<OfflineTotpVerifierUser>();
}
