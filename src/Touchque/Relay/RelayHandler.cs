using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque.Relay;

/// <summary>
/// What the relay wants sent back: a status, a JSON body and headers.
/// <c>OnAuthenticated</c> receives the pending success response and may change it
/// (e.g. add a Set-Cookie); the handler sets the body afterwards.
/// </summary>
public sealed class RelayResponse
{
    private readonly List<KeyValuePair<string, string>> _headers = new();

    public RelayResponse(int status = 200, JsonNode? body = null)
    {
        Status = status;
        Body = body ?? new JsonObject();
    }

    public int Status { get; set; }

    /// <summary>Always a JSON object on the wire.</summary>
    public JsonNode Body { get; set; }

    public IReadOnlyList<KeyValuePair<string, string>> Headers => _headers;

    /// <summary>Sets a header, replacing any value it had.</summary>
    public RelayResponse SetHeader(string name, string value)
    {
        _headers.RemoveAll(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase));
        _headers.Add(new(name, value));
        return this;
    }

    /// <summary>Adds a header value, keeping existing ones (several Set-Cookie).</summary>
    public RelayResponse AddHeader(string name, string value)
    {
        _headers.Add(new(name, value));
        return this;
    }

    public string? GetHeader(string name) => _headers.FirstOrDefault(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Value;
}

/// <summary>One relay request, framework-neutral.</summary>
public sealed record RelayRequest<TRequest>
{
    /// <summary>HTTP method (HEAD is treated as GET).</summary>
    public required string Method { get; init; }
    /// <summary>The path relative to where the relay is mounted, e.g. <c>/login</c>.</summary>
    public required string Path { get; init; }
    /// <summary>The decoded JSON body (empty for none).</summary>
    public JsonObject Body { get; init; } = new();
    /// <summary>The real client IP ("" when unknown). Behind a proxy, resolve it from trusted proxy headers first.</summary>
    public string Ip { get; init; } = "";
    public string? UserAgent { get; init; }
    /// <summary>A case-insensitive request header getter.</summary>
    public required Func<string, string?> Header { get; init; }
    /// <summary>Your framework's request, passed to the option callbacks.</summary>
    public required TRequest Native { get; init; }
}

/// <summary>What <c>OnAuthenticated</c> learns: who signed in, and how.</summary>
public sealed record RelayAuthenticated(string ExternalUsername, string? RequestId, string Via);

/// <summary>Options of <see cref="RelayHandler{TRequest}"/>.</summary>
public sealed record RelayOptions<TRequest>
{
    /// <summary>The signed-in user, for the routes that need one (enrollment, passkey management).</summary>
    public required Func<TRequest, string?> GetUserId { get; init; }

    /// <summary>
    /// The user who passed YOUR first factor (password step). STRONGLY RECOMMENDED: /login
    /// and the offline routes then act for this user and ignore any username in the body
    /// (401 FIRST_FACTOR_REQUIRED when it returns nothing).
    /// </summary>
    public Func<TRequest, string?>? GetLoginUser { get; init; }

    /// <summary>Rate limits of the pre-auth routes; null turns them off (rate limit in front of the relay then).</summary>
    public RateLimitOptions? RateLimit { get; init; } = new();

    /// <summary>Let the offline routes trust the body's username (no <see cref="GetLoginUser"/>).</summary>
    public bool AllowOfflineWithoutFirstFactor { get; init; }

    /// <summary>Action type for /login and the offline routes (default LOGIN).</summary>
    public string ActionType { get; init; } = "LOGIN";

    /// <summary>Transaction context for the approval screen; build it from server-side state, never from the body.</summary>
    public Func<TRequest, IReadOnlyList<LoginDetail>?>? GetDetails { get; init; }

    /// <summary>
    /// Called right before a success answer: open your session here. Via is login,
    /// passkey, offline, offline-totp or silent. Change the response (headers, status);
    /// the handler sets the body.
    /// </summary>
    public Func<TRequest, RelayResponse, RelayAuthenticated, Task>? OnAuthenticated { get; init; }

    /// <summary>
    /// Silent sign-ins for /login (default off): a new sign-in whose browser sent its
    /// device-bound key proof (X-Touchque-Browser) first asks Touchque whether anything
    /// about it is new; if nothing is, it succeeds at once with no push.
    /// </summary>
    public SilentSignInOptions? SilentSignIn { get; init; }
}

/// <summary>
/// Framework-agnostic relay: the routes a frontend (<c>@touchque/web</c>) needs for push
/// 2FA, offline codes and passkeys, so you don't hand-write them. Same routes and
/// behaviour as the Node SDK's <c>touchqueRouter</c>:
/// <code>
/// POST   /enroll/start                  (signed in)   generateSecret response
/// GET    /enroll/status                 (signed in)   { linked, used, deviceId }
/// POST   /login                         (pre-auth)    202 { touchque: step, token } until approved
/// POST   /offline/challenge             (pre-auth)    QR for a phone with no internet
/// POST   /offline/verify                (pre-auth)    body.challengeId / code
/// POST   /offline/totp                  (pre-auth)    the time-based code
/// POST   /passkey/authenticate/options  (pre-auth)    body.email; none = any passkey (autofill)
/// POST   /passkey/authenticate/verify   (pre-auth)    body.attemptId / response
/// POST   /passkey/login/options         (pre-auth)    body.requestId: approve a pending request
/// POST   /passkey/login/verify          (pre-auth)    body.requestId / response
/// POST   /passkey/register/options      (signed in)   the phone approves adding a passkey first
/// POST   /passkey/register/verify       (signed in)
/// GET    /passkey/credentials           (signed in)
/// DELETE /passkey/credentials/{id}      (signed in)
/// </code>
/// </summary>
public sealed class RelayHandler<TRequest>
{
    /// <summary>A 1.5 s poll for a 2-minute push is 80 requests: one attempt's worth of polls.</summary>
    private const int PollsPerAttempt = 10;
    /// <summary>Reserved action: the approval on the phone that unlocks adding a passkey.</summary>
    private const string PasskeyEnrollAction = "PASSKEY_ENROLL";

    private static int _warned;

    private readonly TouchqueClient _tq;
    private readonly RelayOptions<TRequest> _o;
    private readonly FixedWindowLimiter? _limiter;
    private readonly bool _offlineEnabled;

    public RelayHandler(TouchqueClient client, RelayOptions<TRequest> options)
    {
        _tq = client;
        _o = options;
        _limiter = options.RateLimit is null ? null : new FixedWindowLimiter(options.RateLimit);
        _offlineEnabled = options.GetLoginUser is not null || options.AllowOfflineWithoutFirstFactor;
        if (options.GetLoginUser is null && Interlocked.Exchange(ref _warned, 1) == 0)
        {
            client.Log.Warn("[Touchque] RelayHandler: POST /login takes the username from the request body"
                + (_offlineEnabled ? ", and so do the offline routes" : "; the offline routes are disabled until you set it")
                + ". Set GetLoginUser to bind them to your first factor (password step) so they cannot be used against arbitrary users.");
        }
    }

    /// <summary>Handles one relay request; null when no relay route matches (answer 404 yourself).</summary>
    public async Task<RelayResponse?> HandleAsync(RelayRequest<TRequest> req, CancellationToken ct = default)
    {
        var method = req.Method.ToUpperInvariant();
        if (method == "HEAD") method = "GET";
        var path = "/" + req.Path.Split('?')[0].Trim('/');
        switch (method + " " + path.ToLowerInvariant())
        {
            case "POST /enroll/start": return await EnrollStartAsync(req, ct).ConfigureAwait(false);
            case "GET /enroll/status": return await EnrollStatusAsync(req, ct).ConfigureAwait(false);
            case "POST /login": return await LoginAsync(req, ct).ConfigureAwait(false);
            case "POST /offline/challenge": return await OfflineChallengeAsync(req, ct).ConfigureAwait(false);
            case "POST /offline/verify": return await OfflineVerifyAsync(req, ct).ConfigureAwait(false);
            case "POST /offline/totp": return await OfflineTotpAsync(req, ct).ConfigureAwait(false);
            case "POST /passkey/authenticate/options": return await PasskeyAuthenticateOptionsAsync(req, ct).ConfigureAwait(false);
            case "POST /passkey/authenticate/verify": return await PasskeyAuthenticateVerifyAsync(req, ct).ConfigureAwait(false);
            case "POST /passkey/login/options": return await PasskeyLoginOptionsAsync(req, ct).ConfigureAwait(false);
            case "POST /passkey/login/verify": return await PasskeyLoginVerifyAsync(req, ct).ConfigureAwait(false);
            case "POST /passkey/register/options": return await PasskeyRegisterOptionsAsync(req, ct).ConfigureAwait(false);
            case "POST /passkey/register/verify": return await PasskeyRegisterVerifyAsync(req, ct).ConfigureAwait(false);
            case "GET /passkey/credentials": return await PasskeyCredentialsAsync(req, ct).ConfigureAwait(false);
        }
        const string prefix = "/passkey/credentials/";
        if (method == "DELETE" && path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && path.Length > prefix.Length && !path[prefix.Length..].Contains('/'))
        {
            return await DeleteCredentialAsync(req, Uri.UnescapeDataString(path[prefix.Length..]), ct).ConfigureAwait(false);
        }
        return null;
    }

    // ── push 2FA: enrollment ──────────────────────────────────────────────

    private async Task<RelayResponse> EnrollStartAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        var userId = UserId(req);
        if (userId is null) return Unauthorized();
        try
        {
            return new RelayResponse(200, Json.ToNode(await _tq.Auth.GenerateSecretAsync(userId, ct).ConfigureAwait(false)));
        }
        catch (TouchqueApiException e) when (e.Status == 409)
        {
            // 409: a QR was issued and not scanned yet (safe to issue a new one), or a phone is
            // ALREADY linked. Replacing a linked phone must never happen from a plain session:
            // that is how an attacker with a stolen password would swap in their own phone.
            try
            {
                var current = await _tq.Auth.GetUserAsync(userId, ct).ConfigureAwait(false);
                if (current.Used || !string.IsNullOrEmpty(current.DeviceId))
                {
                    return new RelayResponse(409, new JsonObject { ["error"] = "already_linked", ["message"] = "A phone is already linked to this account." });
                }
                return new RelayResponse(200, Json.ToNode(await _tq.Auth.ResetSecretAsync(userId, ct).ConfigureAwait(false)));
            }
            catch (Exception retry) when (retry is not OperationCanceledException)
            {
                return RelayError(retry);
            }
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    private async Task<RelayResponse> EnrollStatusAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        var userId = UserId(req);
        if (userId is null) return Unauthorized();
        try
        {
            var u = await _tq.Auth.GetUserAsync(userId, ct).ConfigureAwait(false);
            return new RelayResponse(200, new JsonObject { ["linked"] = u.Used && !string.IsNullOrEmpty(u.DeviceId), ["used"] = u.Used, ["deviceId"] = u.DeviceId });
        }
        catch (TouchqueApiException e) when (e.Status == 404)
        {
            return new RelayResponse(200, new JsonObject { ["linked"] = false, ["used"] = false, ["deviceId"] = null });
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    // ── push 2FA: login ───────────────────────────────────────────────────

    private async Task<RelayResponse> LoginAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        var (user, refusal) = LoginUser(req);
        if (refusal is not null) return refusal;
        var details = _o.GetDetails?.Invoke(req.Native);
        var input = GuardInputFrom(req, user!, _o.ActionType, details, _o.GetLoginUser is not null, _o.SilentSignIn);
        // Polling an approval already sent is not a new attempt: its own, larger per-IP budget, never the user's push budget.
        var poll = Guard.IsStatusPoll(_tq, input);
        var limited = poll
            ? await AllowAsync(req, "login-poll", null, PollsPerAttempt, ct).ConfigureAwait(false)
            : await AllowAsync(req, "login", user, 1, ct).ConfigureAwait(false);
        if (limited is not null) return limited;
        // Unless it starts something after all (a push once the phone is linked, a new first-time QR): that is charged like a fresh attempt.
        if (poll)
        {
            input = input with
            {
                BeforeStart = async () =>
                {
                    var wait = await WaitAsync(req, "login", user, 1, ct).ConfigureAwait(false);
                    return wait == 0 ? null : new GuardResult { Status = 429, Body = RateLimited(wait), Step = new Step { State = "rate_limited", RetryAfter = wait } };
                },
            };
        }
        var result = await Guard.RunAsync(_tq, input, ct).ConfigureAwait(false);
        if (result.Approved is null) return GuardResponse(result);
        var approved = result.Approved;
        var res = new RelayResponse(200);
        try
        {
            if (_o.OnAuthenticated is not null)
            {
                var via = approved.ConfirmedVia switch { "OFFLINE_TOTP" => "offline-totp", "OFFLINE_CODE" => "offline", "SILENT" => "silent", _ => "login" };
                await _o.OnAuthenticated(req.Native, res, new RelayAuthenticated(user!, approved.RequestId, via)).ConfigureAwait(false);
            }
            res.Body = new JsonObject { ["status"] = "success", ["requestId"] = approved.RequestId, ["assurance"] = Json.ToNode(approved.Assurance) };
            return res;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return AuthResultError(e);
        }
    }

    internal static GuardInput GuardInputFrom(RelayRequest<TRequest> req, string user, string action, IReadOnlyList<LoginDetail>? details, bool enroll, SilentSignInOptions? silent)
    {
        var offline = req.Header(Guard.OfflineHeader);
        var proof = silent is null ? null : req.Header(Guard.BrowserHeader);
        return new GuardInput
        {
            User = user,
            Action = action,
            Details = details,
            Ip = req.Ip.Length > 0 ? req.Ip : null,
            UserAgent = req.UserAgent,
            Token = NonEmpty(req.Header(Guard.TokenHeader)),
            Offline = offline is "1" or "true",
            Code = NonEmpty(req.Header(Guard.CodeHeader)),
            CodeType = NonEmpty(req.Header(Guard.CodeTypeHeader)),
            Enroll = enroll,
            BrowserProof = NonEmpty(proof),
            SilentSignIn = silent,
        };
    }

    private static string? NonEmpty(string? s) => string.IsNullOrEmpty(s) ? null : s;

    private static RelayResponse GuardResponse(GuardResult result)
    {
        var res = new RelayResponse(result.Status, result.Body);
        if (result.RetryAfter is { } ra) res.SetHeader("Retry-After", ra.ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach (var (name, value) in result.RefusalHeaders) res.SetHeader(name, value);
        return res.SetHeader("Cache-Control", "no-store");
    }

    // ── Offline Sign ──────────────────────────────────────────────────────
    // The username used for OnAuthenticated is the one Touchque returns for the code, never the body's.

    private async Task<RelayResponse> OfflineChallengeAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        if (!_offlineEnabled) return OfflineDisabled();
        var (user, refusal) = LoginUser(req);
        if (refusal is not null) return refusal;
        var limited = await AllowAsync(req, "offline-challenge", user, 1, ct).ConfigureAwait(false);
        if (limited is not null) return limited;
        try
        {
            // RequestId (the push this QR follows): a phone-side rejection kills the QR and the number carries over.
            var c = await _tq.Offline.ChallengeAsync(new OfflineChallengeOptions
            {
                ExternalUsername = user!, Type = _o.ActionType, Details = _o.GetDetails?.Invoke(req.Native),
                ClientIp = req.Ip.Length > 0 ? req.Ip : null, UserAgent = req.UserAgent, RequestId = BodyString(req.Body, "requestId") is { Length: > 0 } rid ? rid : null,
            }, ct).ConfigureAwait(false);
            var o = new JsonObject
            {
                ["challengeId"] = c.ChallengeId, ["qr"] = c.Qr, ["qrDataUrl"] = c.QrDataUrl, ["expiresAt"] = c.ExpiresAt,
                ["expiresInSeconds"] = c.ExpiresInSeconds, ["totpAvailable"] = c.TotpAvailable,
            };
            if (!string.IsNullOrEmpty(c.ChallengeCode)) o["challengeCode"] = c.ChallengeCode;
            return new RelayResponse(200, o);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    private async Task<RelayResponse> OfflineVerifyAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        if (!_offlineEnabled) return OfflineDisabled();
        var limited = await AllowAsync(req, "offline-verify", null, 1, ct).ConfigureAwait(false);
        if (limited is not null) return limited;
        try
        {
            var r = await _tq.Offline.VerifyAsync(BodyString(req.Body, "challengeId"), BodyString(req.Body, "code"), ct).ConfigureAwait(false);
            if (!r.Approved || string.IsNullOrEmpty(r.ExternalUsername))
            {
                var no = new JsonObject { ["approved"] = false }.Put("reason", r.Reason).Put("attemptsLeft", r.AttemptsLeft);
                return new RelayResponse(r.Reason == "invalid_code" ? 401 : 400, no);
            }
            // With a first factor, the code must belong to the user who passed it.
            if (_o.GetLoginUser is not null && !SameUser(_o.GetLoginUser(req.Native), r.ExternalUsername))
            {
                return new RelayResponse(401, new JsonObject { ["approved"] = false, ["reason"] = "invalid_code" });
            }
            var res = new RelayResponse(200);
            if (_o.OnAuthenticated is not null) await _o.OnAuthenticated(req.Native, res, new RelayAuthenticated(r.ExternalUsername, r.ChallengeId, "offline")).ConfigureAwait(false);
            res.Body = new JsonObject { ["status"] = "success", ["approved"] = true }.Put("requestId", r.ChallengeId);
            return res;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    private async Task<RelayResponse> OfflineTotpAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        if (!_offlineEnabled) return OfflineDisabled();
        var (user, refusal) = LoginUser(req);
        if (refusal is not null) return refusal;
        var limited = await AllowAsync(req, "offline-totp", user, 1, ct).ConfigureAwait(false);
        if (limited is not null) return limited;
        try
        {
            var requestId = BodyString(req.Body, "requestId");
            var r = await _tq.Offline.VerifyTotpAsync(user!, BodyString(req.Body, "code"), _o.ActionType, req.Ip.Length > 0 ? req.Ip : null, requestId.Length > 0 ? requestId : null, ct).ConfigureAwait(false);
            if (!r.Approved || string.IsNullOrEmpty(r.ExternalUsername))
            {
                return new RelayResponse(r.Reason == "invalid_code" ? 401 : 400, new JsonObject { ["approved"] = false }.Put("reason", r.Reason));
            }
            var res = new RelayResponse(200);
            if (_o.OnAuthenticated is not null) await _o.OnAuthenticated(req.Native, res, new RelayAuthenticated(r.ExternalUsername, null, "offline-totp")).ConfigureAwait(false);
            res.Body = new JsonObject { ["status"] = "success", ["approved"] = true };
            return res;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    // ── passkey: passwordless sign-in ─────────────────────────────────────

    private async Task<RelayResponse> PasskeyAuthenticateOptionsAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        var email = BodyString(req.Body, "email").ToLowerInvariant();
        var limited = await AllowAsync(req, "passkey-options", email.Length > 0 ? email : null, 1, ct).ConfigureAwait(false);
        if (limited is not null) return limited;
        try
        {
            return new RelayResponse(200, Json.ToNode(await _tq.WebAuthn.PrimaryOptionsAsync(email.Length > 0 ? email : null, ct).ConfigureAwait(false)));
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    private async Task<RelayResponse> PasskeyAuthenticateVerifyAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        var limited = await AllowAsync(req, "passkey-verify", null, 1, ct).ConfigureAwait(false);
        if (limited is not null) return limited;
        try
        {
            var r = await _tq.WebAuthn.PrimaryVerifyAsync(BodyString(req.Body, "attemptId"), BodyObject(req.Body, "response"), ct).ConfigureAwait(false);
            if (r.Success)
            {
                var res = new RelayResponse(200);
                if (_o.OnAuthenticated is not null) await _o.OnAuthenticated(req.Native, res, new RelayAuthenticated(r.ExternalUsername ?? "", r.RequestId, "passkey")).ConfigureAwait(false);
                res.Body = new JsonObject { ["status"] = "success" }.Put("requestId", r.RequestId);
                return res;
            }
            if (r.RequiresStepUp) return new RelayResponse(200, new JsonObject { ["requiresStepUp"] = true });
            return new RelayResponse(401, new JsonObject { ["error"] = "verification_failed" });
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    // ── passkey: approve a pending 2FA request (second factor) ────────────

    private async Task<RelayResponse> PasskeyLoginOptionsAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        var limited = await AllowAsync(req, "passkey-approve", null, 1, ct).ConfigureAwait(false);
        if (limited is not null) return limited;
        try
        {
            return new RelayResponse(200, await _tq.WebAuthn.AuthenticateOptionsAsync(BodyString(req.Body, "requestId"), ct).ConfigureAwait(false));
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    private async Task<RelayResponse> PasskeyLoginVerifyAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        var limited = await AllowAsync(req, "passkey-approve", null, 1, ct).ConfigureAwait(false);
        if (limited is not null) return limited;
        try
        {
            var r = await _tq.WebAuthn.AuthenticateVerifyAsync(BodyString(req.Body, "requestId"), BodyObject(req.Body, "response"), ct).ConfigureAwait(false);
            var who = r.ExternalUsername;
            // Open the session only for the user Touchque says was approved; a name the browser sent is never trusted.
            if (r.Success && _o.GetLoginUser is not null && who is not null && !SameUser(_o.GetLoginUser(req.Native), who))
            {
                return new RelayResponse(401, new JsonObject { ["error"] = "verification_failed" });
            }
            var res = new RelayResponse(200);
            if (r.Success && _o.OnAuthenticated is not null && !string.IsNullOrEmpty(who))
            {
                var requestId = !string.IsNullOrEmpty(r.RequestId) ? r.RequestId : BodyString(req.Body, "requestId");
                await _o.OnAuthenticated(req.Native, res, new RelayAuthenticated(who, requestId, "passkey")).ConfigureAwait(false);
            }
            res.Body = Json.ToNode(r) ?? new JsonObject();
            return res;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    // ── passkey: enrollment / management (signed in) ──────────────────────

    /// <summary>
    /// A user with a linked phone approves adding a passkey there first: a passkey approves
    /// requests on its own, so a stolen session must not be able to add one. Same two-phase
    /// contract as /login: 202 with the step until approved, then the options.
    /// </summary>
    private async Task<RelayResponse> PasskeyRegisterOptionsAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        var userId = UserId(req);
        if (userId is null) return Unauthorized();
        var input = GuardInputFrom(req, userId, PasskeyEnrollAction, null, false, null);
        try
        {
            if (input.Token is null)
            {
                try
                {
                    return new RelayResponse(200, await _tq.WebAuthn.RegisterOptionsAsync(userId, true, null, ct).ConfigureAwait(false));
                }
                catch (TouchqueApiException e) when (e.Status == 403 && e.Code == "enrollment_approval_required")
                {
                }
            }
            var limited = Guard.IsStatusPoll(_tq, input)
                ? await AllowAsync(req, "login-poll", null, PollsPerAttempt, ct).ConfigureAwait(false)
                : await AllowAsync(req, "passkey-enroll", userId, 1, ct).ConfigureAwait(false);
            if (limited is not null) return limited;
            var result = await Guard.RunAsync(_tq, input, ct).ConfigureAwait(false);
            if (result.Approved is null) return GuardResponse(result);
            return new RelayResponse(200, await _tq.WebAuthn.RegisterOptionsAsync(userId, true, result.Approved.RequestId, ct).ConfigureAwait(false));
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    private async Task<RelayResponse> PasskeyRegisterVerifyAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        var userId = UserId(req);
        if (userId is null) return Unauthorized();
        try
        {
            var label = req.Body["label"] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
            return new RelayResponse(200, Json.ToNode(await _tq.WebAuthn.RegisterVerifyAsync(userId, BodyObject(req.Body, "response"), label, ct).ConfigureAwait(false)));
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    private async Task<RelayResponse> PasskeyCredentialsAsync(RelayRequest<TRequest> req, CancellationToken ct)
    {
        var userId = UserId(req);
        if (userId is null) return Unauthorized();
        try
        {
            var list = await _tq.WebAuthn.ListCredentialsAsync(userId, ct).ConfigureAwait(false);
            return new RelayResponse(200, new JsonObject { ["credentials"] = Json.ToNode(list) });
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    private async Task<RelayResponse> DeleteCredentialAsync(RelayRequest<TRequest> req, string id, CancellationToken ct)
    {
        var userId = UserId(req);
        if (userId is null) return Unauthorized();
        try
        {
            return new RelayResponse(200, new JsonObject { ["deleted"] = await _tq.WebAuthn.DeleteCredentialAsync(id, userId, ct).ConfigureAwait(false) });
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return RelayError(e);
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private string? UserId(RelayRequest<TRequest> req) => NonEmpty(_o.GetUserId(req.Native));

    /// <summary>Who a pre-auth route acts for: the first-factor user when configured, otherwise the typed username.</summary>
    private (string? User, RelayResponse? Refusal) LoginUser(RelayRequest<TRequest> req)
    {
        if (_o.GetLoginUser is not null)
        {
            var u = _o.GetLoginUser(req.Native);
            if (string.IsNullOrEmpty(u))
            {
                return (null, new RelayResponse(401, new JsonObject { ["error"] = "FIRST_FACTOR_REQUIRED", ["message"] = "Sign in with your password first." }));
            }
            return (u.ToLowerInvariant(), null);
        }
        var typed = BodyString(req.Body, "externalUsername").ToLowerInvariant();
        if (typed.Length == 0) return (null, new RelayResponse(400, new JsonObject { ["error"] = "externalUsername_required" }));
        return (typed, null);
    }

    /// <summary>Null when allowed; otherwise the 429 to send (this IP or this user is over the limit for the route).</summary>
    private async Task<RelayResponse?> AllowAsync(RelayRequest<TRequest> req, string route, string? user, int ipFactor, CancellationToken ct)
    {
        var wait = await WaitAsync(req, route, user, ipFactor, ct).ConfigureAwait(false);
        return wait == 0 ? null : new RelayResponse(429, RateLimited(wait)).SetHeader("Retry-After", wait.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>Counts this request on the route's per-IP and per-user limits: seconds to wait when over one, else 0.</summary>
    private async Task<int> WaitAsync(RelayRequest<TRequest> req, string route, string? user, int ipFactor, CancellationToken ct)
    {
        if (_limiter is null) return 0;
        var ipWait = await _limiter.HitAsync("ip|" + route + "|" + (req.Ip.Length > 0 ? req.Ip : "unknown"), _limiter.PerIp * ipFactor, null, ct).ConfigureAwait(false);
        var userWait = string.IsNullOrEmpty(user) ? 0 : await _limiter.HitAsync("user|" + route + "|" + user, _limiter.PerUser, null, ct).ConfigureAwait(false);
        return Math.Max(ipWait, userWait);
    }

    private static JsonObject RateLimited(int wait) =>
        new() { ["error"] = "RATE_LIMITED", ["message"] = "Too many attempts. Try again later.", ["retryAfter"] = wait };

    private static RelayResponse Unauthorized() => new(401, new JsonObject
    {
        ["error"] = "UNAUTHORIZED_FOR_2FA",
        ["message"] = "Could not find user ID in request. Put your own auth middleware in front of this router.",
    });

    private static RelayResponse OfflineDisabled() => new(403, new JsonObject
    {
        ["error"] = "OFFLINE_REQUIRES_FIRST_FACTOR",
        ["message"] = "Offline sign-in is disabled: configure GetLoginUser (or AllowOfflineWithoutFirstFactor) on the Touchque relay.",
    });

    /// <summary>Same status mapping as the guard middleware, kept in sync with the Node SDK.</summary>
    private RelayResponse AuthResultError(Exception e)
    {
        switch (e)
        {
            case TouchqueRejectedException:
                return new RelayResponse(403, new JsonObject { ["error"] = "2FA_REJECTED", ["message"] = "User rejected the 2FA request on their device." });
            case TouchquePasskeyRequiredException p:
                return new RelayResponse(409, new JsonObject { ["error"] = "PASSKEY_REQUIRED", ["requestId"] = p.RequestId, ["message"] = "Approve this sign-in with your passkey." });
            case TouchqueTimeoutException:
                return new RelayResponse(408, new JsonObject { ["error"] = "2FA_TIMEOUT", ["message"] = "User did not respond to the 2FA request in time." });
            case TouchqueApiException a when a.Status < 500:
                return new RelayResponse(a.Status, new JsonObject { ["error"] = FirstText(a.Error, Json.Str(a.Body, "message"), a.Message) ?? "request_failed" });
        }
        _tq.Log.Error($"[Touchque Relay Error] {e.GetType().Name}: {e.Message}");
        return new RelayResponse(503, new JsonObject { ["error"] = "2FA_UNAVAILABLE", ["message"] = "The 2FA verification service is temporarily unavailable." });
    }

    /// <summary>
    /// For plain relay routes: a client-range Touchque status is forwarded with its
    /// machine-readable code only (never Touchque's message text); anything else is 502.
    /// </summary>
    private static RelayResponse RelayError(Exception e)
    {
        if (e is TouchqueApiException a && a.Status < 500)
        {
            return new RelayResponse(a.Status, new JsonObject { ["error"] = FirstText(a.Code, a.Error) ?? "request_failed" });
        }
        return new RelayResponse(502, new JsonObject { ["error"] = "relay_error" });
    }

    private static string? FirstText(params string?[] candidates) => candidates.FirstOrDefault(c => !string.IsNullOrEmpty(c));

    private static bool SameUser(string? expected, string actual) =>
        !string.IsNullOrEmpty(expected) && string.Equals(expected.ToLowerInvariant(), actual.ToLowerInvariant(), StringComparison.Ordinal);

    /// <summary>A body field as a string ("" when missing or not a scalar).</summary>
    private static string BodyString(JsonObject body, string field) => body[field] switch
    {
        JsonValue v when v.TryGetValue<string>(out var s) => s,
        JsonValue v when v.TryGetValue<bool>(out _) => "",
        JsonValue v => v.ToJsonString(),
        _ => "",
    };

    private static JsonNode BodyObject(JsonObject body, string field) => body[field] is JsonObject o ? o.DeepClone() : new JsonObject();
}
