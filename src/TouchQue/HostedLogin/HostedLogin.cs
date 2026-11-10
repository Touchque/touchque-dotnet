using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>A sign-in or token check failed; <see cref="ErrorCode"/> is machine-readable.</summary>
public class HostedLoginException : TouchQueException
{
    public HostedLoginException(string errorCode, string? description = null, int? status = null)
        : base(description is null ? errorCode : $"{errorCode}: {description}")
    {
        ErrorCode = errorCode;
        Description = description;
        Status = status;
    }

    /// <summary>state_mismatch, issuer_mismatch, nonce_mismatch, invalid_token, insufficient_scope, invalid_grant, access_denied…</summary>
    public string ErrorCode { get; }
    public string? Description { get; }
    public int? Status { get; }
}

/// <summary>Settings of a <see cref="HostedLogin"/>.</summary>
public sealed record HostedLoginOptions
{
    /// <summary>Your tenant: <c>acme.login.touchque.com</c> or your own domain. Plain http is accepted only for localhost.</summary>
    public required string Domain { get; init; }
    public required string ClientId { get; init; }
    /// <summary>Confidential apps (server side): sent with HTTP Basic.</summary>
    public string? ClientSecret { get; init; }
    public string? RedirectUri { get; init; }
    public string Scope { get; init; } = "openid profile email";
    /// <summary>The API the access token is for.</summary>
    public string? Audience { get; init; }
    public TimeSpan ClockTolerance { get; init; } = TimeSpan.FromSeconds(60);
    /// <summary>Your own HttpClient (never following redirects).</summary>
    public HttpClient? HttpClient { get; init; }
}

public sealed record AuthorizationOptions
{
    public string? State { get; init; }
    public string? Nonce { get; init; }
    public string? CodeVerifier { get; init; }
    public string? RedirectUri { get; init; }
    public string? Scope { get; init; }
    public string? Audience { get; init; }
    public string? Prompt { get; init; }
    public string? LoginHint { get; init; }
    /// <summary><c>signup</c> opens the sign-up form.</summary>
    public string? ScreenHint { get; init; }
    public string? UiLocales { get; init; }
    /// <summary>0 forces a fresh sign-in (My Account step-up).</summary>
    public int? MaxAge { get; init; }
    public string? Connection { get; init; }
    public string? Organization { get; init; }
    public string? Invitation { get; init; }
    public string? AcrValues { get; init; }
    public string? ResponseMode { get; init; }
    public IReadOnlyDictionary<string, string>? ExtraParams { get; init; }
}

/// <summary>Where to send the browser, and what to keep (in the session) until the callback.</summary>
public sealed record AuthorizationRequest(string Url, string State, string Nonce, string CodeVerifier);

/// <summary>What the callback is checked against: the values kept from <see cref="HostedLogin.AuthorizationUrl"/>.</summary>
public sealed record CallbackChecks
{
    public required string State { get; init; }
    public required string Nonce { get; init; }
    public required string CodeVerifier { get; init; }
    public string? RedirectUri { get; init; }
    public int? MaxAge { get; init; }
}

public sealed record TokenSet
{
    public string AccessToken { get; init; } = "";
    public string TokenType { get; init; } = "Bearer";
    /// <summary>Unix seconds.</summary>
    public long ExpiresAt { get; init; }
    public string Scope { get; init; } = "";
    public string? IdToken { get; init; }
    /// <summary>Rotates: keep the newest one.</summary>
    public string? RefreshToken { get; init; }
    /// <summary>The verified ID token's claims (sign-in, refresh).</summary>
    public JsonObject Claims { get; init; } = new();
    public JsonArray? AuthorizationDetails { get; init; }
    public string? IssuedTokenType { get; init; }
    /// <summary>Token vault: the connection the token is from.</summary>
    public string? Connection { get; init; }
}

public sealed record AskUserOptions
{
    public string? Audience { get; init; }
    /// <summary>At most 64 characters, shown on the phone.</summary>
    public string? BindingMessage { get; init; }
    /// <summary>RFC 9396 authorization details (any object).</summary>
    public object? AuthorizationDetails { get; init; }
    /// <summary>30–300 seconds.</summary>
    public int? RequestedExpiry { get; init; }
}

/// <summary>A CIBA request waiting for the user.</summary>
public sealed record UserApprovalRequest
{
    public string AuthReqId { get; init; } = "";
    /// <summary>Unix seconds.</summary>
    public long ExpiresAt { get; init; }
    public int Interval { get; init; } = 5;
    public string? BindingCode { get; init; }
}

/// <summary>
/// TouchQue Login (hosted sign-in) for your app: an OpenID Connect client for your
/// tenant. PKCE (S256) is always used. ID tokens are checked against the tenant's
/// JWKS (RS256, issuer, audience, expiry, nonce, at_hash). Your API checks access
/// tokens with <see cref="VerifyAccessTokenAsync"/>. In ASP.NET Core,
/// <c>MapTouchQueLogin()</c> wires the routes for you.
/// <code>
/// var login = new HostedLogin(new() { Domain = "acme.login.touchque.com", ClientId = "…", ClientSecret = "…", RedirectUri = "https://app/callback" });
/// var req = login.AuthorizationUrl();   // keep State, Nonce, CodeVerifier; redirect to req.Url
/// var tokens = await login.HandleCallbackAsync(callbackUrl, new() { State = req.State, Nonce = req.Nonce, CodeVerifier = req.CodeVerifier });
/// </code>
/// </summary>
public sealed class HostedLogin
{
    /// <summary>requested_token_type for the token vault (<see cref="GetConnectionTokenAsync"/>).</summary>
    public const string ConnectionTokenType = "urn:touchque:params:oauth:token-type:connection-access-token";

    private static readonly Lazy<HttpClient> SharedClient = new(() => TouchQueHttp.CreateClient(TimeSpan.FromSeconds(10)));

    private readonly HostedLoginOptions _o;
    private readonly HttpClient _client;
    private readonly SemaphoreSlim _keysLock = new(1, 1);
    private Dictionary<string, JsonObject> _keys = new();
    private DateTimeOffset _keysAt;

    public HostedLogin(HostedLoginOptions options)
    {
        if (string.IsNullOrEmpty(options.Domain)) throw new HostedLoginException("config", "Domain is required");
        if (string.IsNullOrEmpty(options.ClientId)) throw new HostedLoginException("config", "ClientId is required");
        _o = options;
        Issuer = IssuerOf(options.Domain) ?? throw new HostedLoginException("config", InsecureIssuer(options.Domain));
        _client = options.HttpClient ?? SharedClient.Value;
    }

    /// <summary>
    /// The issuer URL of a domain: https, or plain http only on localhost (the rule of <c>TouchQueOptions.BaseUrl</c>,
    /// plus <c>*.localhost</c>); null for plain http anywhere else. Codes, PKCE verifiers, the client secret and
    /// every token would travel in the clear.
    /// </summary>
    internal static string? IssuerOf(string domain)
    {
        var raw = domain.TrimEnd('/');
        if (raw.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return raw;
        if (!raw.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return "https://" + raw;
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)) return null;
        var host = uri.Host.ToLowerInvariant();
        return TouchQueOptions.IsLoopback(host) || host.EndsWith(".localhost", StringComparison.Ordinal) ? raw : null;
    }

    internal static string InsecureIssuer(string domain) =>
        $"Refusing a plaintext http:// Domain ({domain.TrimEnd('/')}): use https:// (http:// only on localhost).";

    /// <summary>The tenant's issuer URL.</summary>
    public string Issuer { get; }

    public string ClientId => _o.ClientId;

    public string? RedirectUri => _o.RedirectUri;

    /// <summary>The URL to send the browser to, and the values to keep until the callback.</summary>
    public AuthorizationRequest AuthorizationUrl(AuthorizationOptions? options = null)
    {
        var o = options ?? new AuthorizationOptions();
        var redirect = o.RedirectUri ?? _o.RedirectUri;
        if (string.IsNullOrEmpty(redirect)) throw new HostedLoginException("config", "RedirectUri is required");
        var state = o.State ?? Random(32);
        var nonce = o.Nonce ?? Random(32);
        var verifier = o.CodeVerifier ?? Random(48);
        var p = new List<KeyValuePair<string, string>>
        {
            new("response_type", "code"), new("client_id", _o.ClientId), new("redirect_uri", redirect), new("scope", o.Scope ?? _o.Scope),
            new("state", state), new("nonce", nonce),
            new("code_challenge", Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))), new("code_challenge_method", "S256"),
        };
        void Add(string key, string? value)
        {
            if (!string.IsNullOrEmpty(value)) p.Add(new(key, value));
        }
        Add("audience", o.Audience ?? _o.Audience);
        Add("prompt", o.Prompt);
        Add("login_hint", o.LoginHint);
        Add("screen_hint", o.ScreenHint);
        Add("ui_locales", o.UiLocales);
        Add("max_age", o.MaxAge?.ToString(CultureInfo.InvariantCulture));
        Add("connection", o.Connection);
        Add("organization", o.Organization);
        Add("invitation", o.Invitation);
        Add("acr_values", o.AcrValues);
        Add("response_mode", o.ResponseMode);
        if (o.ExtraParams is not null)
        {
            foreach (var (k, v) in o.ExtraParams) p.Add(new(k, v));
        }
        var url = Issuer + "/authorize?" + string.Join("&", p.Select(x => Uri.EscapeDataString(x.Key) + "=" + Uri.EscapeDataString(x.Value)));
        return new AuthorizationRequest(url, state, nonce, verifier);
    }

    /// <summary>Checks state (and iss), exchanges the code with the PKCE verifier, verifies the ID token.</summary>
    /// <param name="callback">The callback URL (or its query string).</param>
    public Task<TokenSet> HandleCallbackAsync(string callback, CallbackChecks checks, CancellationToken ct = default) =>
        HandleCallbackAsync(ParseQuery(callback), checks, ct);

    /// <summary>Checks state (and iss), exchanges the code with the PKCE verifier, verifies the ID token.</summary>
    /// <param name="parameters">The callback's query or form fields.</param>
    public async Task<TokenSet> HandleCallbackAsync(IReadOnlyDictionary<string, string> parameters, CallbackChecks checks, CancellationToken ct = default)
    {
        parameters.TryGetValue("state", out var state);
        if (string.IsNullOrEmpty(state) || string.IsNullOrEmpty(checks.State) || !FixedEquals(checks.State, state))
        {
            throw new HostedLoginException("state_mismatch", "The state does not match this sign-in");
        }
        // RFC 9207: a response that carries iss (even an empty one) must name this issuer, the one the
        // ID token is checked against. Servers that do not send iss yet (no field, or a null value) are accepted.
        if (parameters.TryGetValue("iss", out var iss) && iss is not null && iss != Issuer)
        {
            throw new HostedLoginException("issuer_mismatch", iss.Length == 0 ? "The response has an empty iss" : $"The response came from {iss}");
        }
        if (parameters.TryGetValue("error", out var error) && !string.IsNullOrEmpty(error))
        {
            throw new HostedLoginException(error, parameters.GetValueOrDefault("error_description"));
        }
        if (!parameters.TryGetValue("code", out var code) || string.IsNullOrEmpty(code))
        {
            throw new HostedLoginException("invalid_request", "The callback has no code");
        }
        var redirect = checks.RedirectUri ?? _o.RedirectUri;
        if (string.IsNullOrEmpty(redirect)) throw new HostedLoginException("config", "RedirectUri is required");
        var tokens = await TokenAsync(new Dictionary<string, string?>
        {
            ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = redirect, ["code_verifier"] = checks.CodeVerifier,
        }, ct).ConfigureAwait(false);
        if (string.IsNullOrEmpty(tokens.IdToken)) throw new HostedLoginException("invalid_token", "No ID token: ask for the openid scope");
        return tokens with { Claims = await VerifyIdTokenAsync(tokens.IdToken, checks.Nonce, tokens.AccessToken, checks.MaxAge, ct).ConfigureAwait(false) };
    }

    /// <summary>A new access token and a rotated refresh token: keep the new one.</summary>
    public async Task<TokenSet> RefreshAsync(string refreshToken, string? scope = null, CancellationToken ct = default)
    {
        var tokens = await TokenAsync(new Dictionary<string, string?> { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken, ["scope"] = scope }, ct).ConfigureAwait(false);
        return string.IsNullOrEmpty(tokens.IdToken) ? tokens : tokens with { Claims = await VerifyIdTokenAsync(tokens.IdToken, null, tokens.AccessToken, null, ct).ConfigureAwait(false) };
    }

    /// <summary>
    /// A token for the My Account API (audience https://&lt;domain&gt;/me/) from the refresh
    /// token a first-party app holds. The refresh token rotates: keep the returned one.
    /// Scopes: read:me, update:me, manage:me:security, delete:me.
    /// </summary>
    public Task<TokenSet> MyAccountTokenAsync(string refreshToken, string scope = "read:me update:me", CancellationToken ct = default) =>
        TokenAsync(new Dictionary<string, string?> { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken, ["audience"] = Issuer + "/me/", ["scope"] = scope }, ct);

    /// <summary>The My Account API for the person holding <paramref name="accessToken"/>.</summary>
    public MyAccount MyAccount(string accessToken) => new(Issuer, accessToken, _client);

    /// <summary>The hosted account page (profile; security, devices or privacy).</summary>
    public string AccountUrl(string? section = null) => Issuer + "/account" + (string.IsNullOrEmpty(section) ? "" : "/" + section);

    /// <summary>Machine to machine: an access token for your API with the app's own credentials.</summary>
    public Task<TokenSet> ClientCredentialsAsync(string audience, string? scope = null, CancellationToken ct = default) =>
        TokenAsync(new Dictionary<string, string?> { ["grant_type"] = "client_credentials", ["audience"] = audience, ["scope"] = scope }, ct);

    /// <summary>
    /// RFC 8693: a signed-in user's access token, traded for one to call
    /// <paramref name="audience"/> on their behalf (sub = the user, act.sub = this app).
    /// </summary>
    public Task<TokenSet> ExchangeTokenAsync(string subjectToken, string audience, string? scope = null, CancellationToken ct = default) =>
        TokenAsync(new Dictionary<string, string?>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange", ["subject_token"] = subjectToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token", ["audience"] = audience, ["scope"] = scope,
        }, ct);

    /// <summary>
    /// Token vault: the provider's own access token (Google, Microsoft, GitHub…) for the
    /// signed-in user, from a connection that stores tokens. TouchQue refreshes it; the
    /// refresh token never leaves. invalid_grant: the user has not signed in with the
    /// connection since it started storing tokens, or they stopped app access.
    /// </summary>
    public Task<TokenSet> GetConnectionTokenAsync(string userAccessToken, string connection, string? scope = null, CancellationToken ct = default) =>
        TokenAsync(new Dictionary<string, string?>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange", ["subject_token"] = userAccessToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token", ["requested_token_type"] = ConnectionTokenType,
            ["connection"] = connection, ["scope"] = scope,
        }, ct);

    /// <summary>CIBA: asks the user (email or usr_ id) to approve on their phone.</summary>
    public async Task<UserApprovalRequest> AskUserAsync(string loginHint, string scope, AskUserOptions? options = null, CancellationToken ct = default)
    {
        var o = options ?? new AskUserOptions();
        var (status, body) = await PostAsync("/bc-authorize", new Dictionary<string, string?>
        {
            ["login_hint"] = loginHint, ["scope"] = scope, ["audience"] = o.Audience, ["binding_message"] = o.BindingMessage,
            ["authorization_details"] = o.AuthorizationDetails is null ? null : Json.Serialize(Json.ToNode(o.AuthorizationDetails)),
            ["requested_expiry"] = o.RequestedExpiry?.ToString(CultureInfo.InvariantCulture),
        }, ct).ConfigureAwait(false);
        if (status >= 400) throw Error(status, body);
        var d = Json.ParseObject(body);
        return new UserApprovalRequest
        {
            AuthReqId = Json.Str(d, "auth_req_id") ?? "",
            ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + (Json.Long(d, "expires_in") ?? 0),
            Interval = Json.Int(d, "interval") ?? 5,
            BindingCode = Json.Str(d, "binding_code"),
        };
    }

    /// <summary>Polls until the user answers: the tokens, or <see cref="HostedLoginException"/> access_denied / expired_token.</summary>
    public async Task<TokenSet> WaitForUserAsync(UserApprovalRequest request, CancellationToken ct = default)
    {
        var interval = request.Interval;
        while (true)
        {
            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > request.ExpiresAt) throw new HostedLoginException("expired_token", "The user did not answer in time");
            await Task.Delay(TimeSpan.FromSeconds(interval), ct).ConfigureAwait(false);
            try
            {
                return await TokenAsync(new Dictionary<string, string?> { ["grant_type"] = "urn:openid:params:grant-type:ciba", ["auth_req_id"] = request.AuthReqId }, ct).ConfigureAwait(false);
            }
            catch (HostedLoginException e) when (e.ErrorCode is "slow_down" or "authorization_pending")
            {
                if (e.ErrorCode == "slow_down") interval += 5;
            }
        }
    }

    public async Task RevokeAsync(string token, CancellationToken ct = default)
    {
        var (status, body) = await PostAsync("/oauth/revoke", new Dictionary<string, string?> { ["token"] = token }, ct).ConfigureAwait(false);
        if (status >= 400) throw Error(status, body);
    }

    public async Task<JsonObject> UserinfoAsync(string accessToken, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, Issuer + "/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var (status, body) = await SendAsync(req, ct).ConfigureAwait(false);
        if (status >= 400) throw Error(status, body);
        return Json.ParseObject(body);
    }

    public string LogoutUrl(string? idTokenHint = null, string? postLogoutRedirectUri = null, string? state = null)
    {
        var p = new List<string> { "client_id=" + Uri.EscapeDataString(_o.ClientId) };
        if (!string.IsNullOrEmpty(idTokenHint)) p.Add("id_token_hint=" + Uri.EscapeDataString(idTokenHint));
        if (!string.IsNullOrEmpty(postLogoutRedirectUri)) p.Add("post_logout_redirect_uri=" + Uri.EscapeDataString(postLogoutRedirectUri));
        if (!string.IsNullOrEmpty(state)) p.Add("state=" + Uri.EscapeDataString(state));
        return Issuer + "/oidc/logout?" + string.Join("&", p);
    }

    /// <summary>For your API: signature, issuer, audience, expiry, typ at+jwt, scopes.</summary>
    public async Task<JsonObject> VerifyAccessTokenAsync(string token, string audience, IEnumerable<string>? requiredScopes = null, CancellationToken ct = default)
    {
        var payload = await VerifyJwtAsync(token, "at+jwt", ct).ConfigureAwait(false);
        if (!Audiences(payload).Contains(audience)) throw new HostedLoginException("invalid_token", "The token is for another audience");
        var scopes = (Json.Str(payload, "scope") ?? "").Split(' ');
        var missing = (requiredScopes ?? Array.Empty<string>()).Where(s => !scopes.Contains(s)).ToList();
        if (missing.Count > 0) throw new HostedLoginException("insufficient_scope", "Missing scope: " + string.Join(" ", missing), 403);
        return payload;
    }

    public async Task<JsonObject> VerifyIdTokenAsync(string idToken, string? nonce = null, string? accessToken = null, int? maxAge = null, CancellationToken ct = default)
    {
        var payload = await VerifyJwtAsync(idToken, null, ct).ConfigureAwait(false);
        var auds = Audiences(payload);
        if (!auds.Contains(_o.ClientId)) throw new HostedLoginException("invalid_token", "The ID token is for another app");
        if (auds.Count > 1 && Json.Str(payload, "azp") != _o.ClientId) throw new HostedLoginException("invalid_token", "azp does not name this app");
        if (nonce is not null && !(Json.Str(payload, "nonce") is { } got && FixedEquals(nonce, got)))
        {
            throw new HostedLoginException("nonce_mismatch", "The nonce does not match this sign-in");
        }
        if (accessToken is not null && Json.Str(payload, "at_hash") is { } atHash)
        {
            var expected = Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)).AsSpan(0, 16));
            if (!FixedEquals(expected, atHash)) throw new HostedLoginException("invalid_token", "at_hash does not match the access token");
        }
        if (maxAge is not null && Json.Long(payload, "auth_time") is { } authTime &&
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() - authTime > maxAge.Value + (long)_o.ClockTolerance.TotalSeconds)
        {
            throw new HostedLoginException("login_required", "The sign-in is older than maxAge");
        }
        return payload;
    }

    // ── internals ────────────────────────────────────────────────────────

    private static string Random(int bytes) => Base64Url.Encode(RandomNumberGenerator.GetBytes(bytes));

    private static bool FixedEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    private static List<string?> Audiences(JsonObject payload) =>
        payload["aud"] is JsonArray a
            ? a.Select(x => x is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).ToList()
            : new List<string?> { Json.Str(payload, "aud") };

    internal static Dictionary<string, string> ParseQuery(string callback)
    {
        var q = callback.Contains('?') ? callback[(callback.IndexOf('?') + 1)..] : callback;
        var hash = q.IndexOf('#');
        if (hash >= 0) q = q[..hash];
        var d = new Dictionary<string, string>();
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var i = part.IndexOf('=');
            var k = Uri.UnescapeDataString((i < 0 ? part : part[..i]).Replace('+', ' '));
            var v = i < 0 ? "" : Uri.UnescapeDataString(part[(i + 1)..].Replace('+', ' '));
            d[k] = v;
        }
        return d;
    }

    private async Task<(int Status, string Body)> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        req.Headers.Accept.ParseAdd("application/json");
        try
        {
            using var res = await _client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            return ((int)res.StatusCode, await TouchQueHttp.ReadLimitedAsync(res, ct).ConfigureAwait(false));
        }
        catch (HttpRequestException e)
        {
            throw new HostedLoginException("network_error", e.Message);
        }
    }

    private Task<(int Status, string Body)> PostAsync(string path, Dictionary<string, string?> fields, CancellationToken ct)
    {
        var form = fields.Where(f => !string.IsNullOrEmpty(f.Value)).Select(f => new KeyValuePair<string, string>(f.Key, f.Value!)).ToList();
        var req = new HttpRequestMessage(HttpMethod.Post, Issuer + path);
        if (_o.ClientSecret is not null)
        {
            var basic = Uri.EscapeDataString(_o.ClientId) + ":" + Uri.EscapeDataString(_o.ClientSecret);
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(basic)));
        }
        else
        {
            form.Add(new("client_id", _o.ClientId));
        }
        req.Content = new FormUrlEncodedContent(form);
        return SendDisposingAsync(req, ct);
    }

    private async Task<(int Status, string Body)> SendDisposingAsync(HttpRequestMessage req, CancellationToken ct)
    {
        using (req) return await SendAsync(req, ct).ConfigureAwait(false);
    }

    private static HostedLoginException Error(int status, string body)
    {
        var d = Json.ParseObject(body);
        return new HostedLoginException(Json.Str(d, "error") ?? $"http_{status}", Json.Str(d, "error_description"), status);
    }

    private async Task<TokenSet> TokenAsync(Dictionary<string, string?> fields, CancellationToken ct)
    {
        var (status, body) = await PostAsync("/oauth/token", fields, ct).ConfigureAwait(false);
        if (status >= 400) throw Error(status, body);
        var d = Json.ParseObject(body);
        return new TokenSet
        {
            AccessToken = Json.Str(d, "access_token") ?? "",
            TokenType = Json.Str(d, "token_type") ?? "Bearer",
            ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + (Json.Long(d, "expires_in") ?? 0),
            Scope = Json.Str(d, "scope") ?? "",
            IdToken = Json.Str(d, "id_token"),
            RefreshToken = Json.Str(d, "refresh_token"),
            AuthorizationDetails = d["authorization_details"] is JsonArray ad ? (JsonArray)ad.DeepClone() : null,
            IssuedTokenType = Json.Str(d, "issued_token_type"),
            Connection = Json.Str(d, "connection"),
        };
    }

    private async Task LoadKeysAsync(bool force, CancellationToken ct)
    {
        await _keysLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var age = DateTimeOffset.UtcNow - _keysAt;
            if (!force && _keys.Count > 0 && age < TimeSpan.FromHours(1)) return;
            if (force && age < TimeSpan.FromSeconds(30)) return;
            using var req = new HttpRequestMessage(HttpMethod.Get, Issuer + "/.well-known/jwks.json");
            var (status, body) = await SendAsync(req, ct).ConfigureAwait(false);
            if (status >= 400) throw new HostedLoginException("jwks_unavailable", $"JWKS answered {status}");
            var keys = new Dictionary<string, JsonObject>();
            if (Json.ParseObject(body)["keys"] is JsonArray list)
            {
                foreach (var k in list.OfType<JsonObject>())
                {
                    var kid = Json.Str(k, "kid");
                    if (Json.Str(k, "kty") == "RSA" && !string.IsNullOrEmpty(kid) && Json.Str(k, "n") is not null && Json.Str(k, "e") is not null && (Json.Str(k, "use") ?? "sig") == "sig")
                    {
                        keys[kid] = k;
                    }
                }
            }
            _keys = keys;
            _keysAt = DateTimeOffset.UtcNow;
        }
        finally
        {
            _keysLock.Release();
        }
    }

    private async Task<JsonObject> VerifyJwtAsync(string token, string? typ, CancellationToken ct)
    {
        var parts = JwsVerify.Split(token) ?? throw new HostedLoginException("invalid_token", "not a JWT");
        var (header, payload, input, sig) = parts;
        if (Json.Str(header, "alg") != "RS256") throw new HostedLoginException("invalid_token", "Unexpected alg");
        if (typ is not null && (Json.Str(header, "typ") ?? "").ToLowerInvariant() != typ) throw new HostedLoginException("invalid_token", "Wrong token type");
        var kid = Json.Str(header, "kid") ?? "";
        await LoadKeysAsync(false, ct).ConfigureAwait(false);
        if (!_keys.ContainsKey(kid)) await LoadKeysAsync(true, ct).ConfigureAwait(false);
        if (!_keys.TryGetValue(kid, out var key)) throw new HostedLoginException("invalid_token", "Unknown signing key");
        if (!JwsVerify.Verify("RS256", key, input, sig)) throw new HostedLoginException("invalid_token", "Bad signature");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var tolerance = (long)_o.ClockTolerance.TotalSeconds;
        if (Json.Str(payload, "iss") != Issuer) throw new HostedLoginException("invalid_token", "Wrong issuer");
        var exp = Json.Long(payload, "exp");
        if (exp is null || now > exp.Value + tolerance) throw new HostedLoginException("invalid_token", "The token expired");
        if (Json.Long(payload, "iat") is { } iat && iat > now + tolerance) throw new HostedLoginException("invalid_token", "The token is from the future");
        return payload;
    }
}
