using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>
/// A refused ID-JAG or exchange (Cross App Access). <see cref="Error"/> is the OAuth error:
/// <c>invalid_grant</c> for a bad ID-JAG, else what the server answered.
/// </summary>
public class TouchqueIdJagException : TouchqueException
{
    public TouchqueIdJagException(string error, string message, int? status = null) : base(message)
    {
        Error = error;
        Status = status;
    }

    public string Error { get; }
    public int? Status { get; }
}

/// <summary>What <see cref="CrossAppAccess.RequestIdJagAsync"/> needs.</summary>
public sealed record RequestIdJagOptions
{
    /// <summary>The identity provider's issuer (its token endpoint is discovered), or give <see cref="TokenEndpoint"/>.</summary>
    public string? Issuer { get; init; }
    public string? TokenEndpoint { get; init; }
    /// <summary>Your app at the identity provider (tqapp_… at Touchque SSO) and its secret.</summary>
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    /// <summary>The member's ID token the identity provider issued to your app.</summary>
    public required string IdToken { get; init; }
    /// <summary>The other service's authorization server (its issuer).</summary>
    public required string Audience { get; init; }
    public string? Resource { get; init; }
    public string? Scope { get; init; }
}

/// <summary>An ID-JAG the identity provider issued.</summary>
public sealed record IdJagGrant(string Assertion, int? ExpiresIn, string? Scope);

/// <summary>What <see cref="CrossAppAccess.RedeemIdJagAsync"/> needs.</summary>
public sealed record RedeemIdJagOptions
{
    public required string TokenEndpoint { get; init; }
    public required string ClientId { get; init; }
    public string? ClientSecret { get; init; }
    public required string Assertion { get; init; }
    public string? Resource { get; init; }
    public string? Scope { get; init; }
}

/// <summary>
/// Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
/// draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An
/// organization's identity provider (Touchque SSO) decides which of its apps may
/// reach which other service for its members; the app trades a member's ID token
/// for an ID-JAG there, then the ID-JAG for an access token at the other
/// service's authorization server, with no consent screen per member. Your own
/// authorization server takes them with <see cref="IdJagVerifier"/>.
/// <code>
/// var jag = await CrossAppAccess.RequestIdJagAsync(new() { Issuer = "https://sso.touchque.com", ClientId = id, ClientSecret = secret,
///     IdToken = idToken, Audience = "https://auth.files.example" });
/// var tokens = await CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = "https://auth.files.example/token", ClientId = "acme",
///     ClientSecret = filesSecret, Assertion = jag.Assertion });
/// </code>
/// </summary>
public static class CrossAppAccess
{
    public const string IdJagTokenType = "urn:ietf:params:oauth:token-type:id-jag";
    public const string IdTokenType = "urn:ietf:params:oauth:token-type:id_token";
    public const string TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
    public const string JwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private static readonly Lazy<HttpClient> SharedClient = new(() => TouchqueHttp.CreateClient(TimeSpan.FromSeconds(10)));

    /// <summary>https, or http on this machine (tests).</summary>
    internal static bool SafeUrl(string? url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) && (u.Scheme == "https" || (u.Scheme == "http" && u.IsLoopback));

    internal static async Task<JsonObject> GetJsonAsync(string url, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.ParseAdd("application/json");
        using var res = await SharedClient.Value.SendAsync(req, ct).ConfigureAwait(false);
        if ((int)res.StatusCode >= 400) throw new InvalidOperationException($"{url} answered {(int)res.StatusCode}");
        return Json.ParseObject(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
    }

    /// <summary>The identity provider's OpenID configuration, checked against its issuer.</summary>
    internal static async Task<JsonObject> DiscoverAsync(string issuer, Func<string, CancellationToken, Task<JsonObject>> fetch, CancellationToken ct)
    {
        var meta = await fetch(issuer.TrimEnd('/') + "/.well-known/openid-configuration", ct).ConfigureAwait(false);
        if (Json.Str(meta, "issuer") != issuer) throw new TouchqueConfigException("the identity provider's metadata does not match its issuer");
        return meta;
    }

    private static async Task<JsonObject> PostFormAsync(string url, Dictionary<string, string?> form, (string Id, string Secret)? basic, CancellationToken ct)
    {
        if (!SafeUrl(url)) throw new TouchqueConfigException($"{url} must be an https URL");
        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new FormUrlEncodedContent(form.Where(kv => kv.Value is not null).Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value!))),
        };
        req.Headers.Accept.ParseAdd("application/json");
        if (basic is { } b)
        {
            var raw = Uri.EscapeDataString(b.Id) + ":" + Uri.EscapeDataString(b.Secret);
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(raw)));
        }
        using var res = await SharedClient.Value.SendAsync(req, ct).ConfigureAwait(false);
        var data = Json.ParseObject(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        var status = (int)res.StatusCode;
        if (status >= 400)
        {
            throw new TouchqueIdJagException(Json.Str(data, "error") ?? "server_error", Json.Str(data, "error_description") ?? $"{url} answered {status}", status);
        }
        return data;
    }

    /// <summary>Trades a member's ID token for an ID-JAG at the identity provider (token exchange, client_secret_basic).</summary>
    public static async Task<IdJagGrant> RequestIdJagAsync(RequestIdJagOptions o, CancellationToken ct = default)
    {
        var endpoint = o.TokenEndpoint;
        if (string.IsNullOrEmpty(endpoint))
        {
            if (string.IsNullOrEmpty(o.Issuer)) throw new TouchqueConfigException("RequestIdJagAsync needs Issuer or TokenEndpoint");
            endpoint = Json.Str(await DiscoverAsync(o.Issuer, GetJsonAsync, ct).ConfigureAwait(false), "token_endpoint")
                ?? throw new TouchqueConfigException("the identity provider names no token_endpoint");
        }
        var data = await PostFormAsync(endpoint, new()
        {
            ["grant_type"] = TokenExchangeGrant, ["requested_token_type"] = IdJagTokenType, ["subject_token"] = o.IdToken,
            ["subject_token_type"] = IdTokenType, ["audience"] = o.Audience, ["resource"] = o.Resource, ["scope"] = o.Scope,
        }, (o.ClientId, o.ClientSecret), ct).ConfigureAwait(false);
        var assertion = Json.Str(data, "access_token");
        if (Json.Str(data, "issued_token_type") != IdJagTokenType || string.IsNullOrEmpty(assertion))
        {
            throw new TouchqueIdJagException("invalid_response", "the identity provider did not answer with an ID-JAG");
        }
        return new IdJagGrant(assertion, (int?)Json.Long(data, "expires_in"), Json.Str(data, "scope"));
    }

    /// <summary>Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer).</summary>
    public static Task<JsonObject> RedeemIdJagAsync(RedeemIdJagOptions o, CancellationToken ct = default) =>
        PostFormAsync(o.TokenEndpoint, new()
        {
            ["grant_type"] = JwtBearerGrant, ["assertion"] = o.Assertion, ["resource"] = o.Resource, ["scope"] = o.Scope,
            ["client_id"] = string.IsNullOrEmpty(o.ClientSecret) ? o.ClientId : null,
        }, string.IsNullOrEmpty(o.ClientSecret) ? null : (o.ClientId, o.ClientSecret), ct);
}

/// <summary>Settings of <see cref="IdJagVerifier"/>.</summary>
public sealed record IdJagVerifierOptions
{
    /// <summary>The identity provider, e.g. https://sso.touchque.com.</summary>
    public required string Issuer { get; init; }
    /// <summary>Your authorization server's issuer identifier (the ID-JAG's aud).</summary>
    public required string Audience { get; init; }
    /// <summary>Its JWKS, when not found from the issuer's /.well-known/openid-configuration.</summary>
    public string? JwksUri { get; init; }
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(60);
    /// <summary>
    /// Records an ID-JAG's jti and says whether it is new (each is used once). Defaults to memory
    /// in this process; give a shared store (Redis SET NX) when several processes take ID-JAGs.
    /// </summary>
    public Func<string, long, bool>? FirstUse { get; init; }
    /// <summary>For tests: how JSON documents are fetched.</summary>
    public Func<string, CancellationToken, Task<JsonObject>>? Fetch { get; init; }
}

/// <summary>A checked ID-JAG.</summary>
public sealed record IdJagClaims
{
    public string Iss { get; init; } = "";
    /// <summary>The member at the identity provider.</summary>
    public string Sub { get; init; } = "";
    public string Aud { get; init; } = "";
    /// <summary>Your client_id of the app that presented it.</summary>
    public string ClientId { get; init; } = "";
    public string Jti { get; init; } = "";
    public long IssuedAt { get; init; }
    public long ExpiresAt { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = Array.Empty<string>();
    public string? Resource { get; init; }
    public string? Tenant { get; init; }
    public string? Email { get; init; }
    public long? AuthTime { get; init; }
    public IReadOnlyList<string> Amr { get; init; } = Array.Empty<string>();
    public JsonObject Claims { get; init; } = new();
}

/// <summary>
/// Your authorization server, taking ID-JAGs from an organization's identity provider:
/// checks the one an authenticated client presents (jwt-bearer grant) and uses it once.
/// <code>
/// var verifier = new IdJagVerifier(new() { Issuer = "https://sso.touchque.com", Audience = "https://auth.files.example" });
/// var claims = await verifier.VerifyAsync(form["assertion"], authenticatedClientId);
/// </code>
/// </summary>
public sealed class IdJagVerifier
{
    private readonly IdJagVerifierOptions _o;
    private readonly Func<string, CancellationToken, Task<JsonObject>> _fetch;
    private readonly SemaphoreSlim _keysLock = new(1, 1);
    private readonly ConcurrentDictionary<string, long> _seen = new();
    private Dictionary<string, JsonObject> _keys = new();
    private string? _jwksUri;
    private DateTimeOffset _keysAt;
    private DateTimeOffset _triedAt;

    public IdJagVerifier(IdJagVerifierOptions options)
    {
        if (string.IsNullOrEmpty(options.Issuer) || string.IsNullOrEmpty(options.Audience))
        {
            throw new TouchqueConfigException("IdJagVerifier needs Issuer (the identity provider) and Audience (your authorization server's issuer)");
        }
        _o = options;
        _jwksUri = options.JwksUri;
        _fetch = options.Fetch ?? CrossAppAccess.GetJsonAsync;
    }

    private bool RememberOnce(string jti, long exp)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        foreach (var (k, until) in _seen)
        {
            if (until < now) _seen.TryRemove(k, out _);
        }
        return _seen.TryAdd(jti, exp + (long)_o.ClockSkew.TotalSeconds);
    }

    private async Task LoadKeysAsync(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(_jwksUri))
        {
            _jwksUri = Json.Str(await CrossAppAccess.DiscoverAsync(_o.Issuer, _fetch, ct).ConfigureAwait(false), "jwks_uri")
                ?? throw new InvalidOperationException("the identity provider names no jwks_uri");
        }
        var keys = new Dictionary<string, JsonObject>();
        if ((await _fetch(_jwksUri, ct).ConfigureAwait(false))["keys"] is JsonArray list)
        {
            foreach (var k in list.OfType<JsonObject>())
            {
                var kid = Json.Str(k, "kid");
                if (!string.IsNullOrEmpty(kid)) keys[kid] = k;
            }
        }
        _keys = keys;
        _keysAt = DateTimeOffset.UtcNow;
    }

    private async Task<JsonObject?> KeyForAsync(string kid, CancellationToken ct)
    {
        await _keysLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_keysAt == default || DateTimeOffset.UtcNow - _keysAt > TimeSpan.FromMinutes(10)) await LoadKeysAsync(ct).ConfigureAwait(false);
            if (!_keys.ContainsKey(kid) && DateTimeOffset.UtcNow - _triedAt > TimeSpan.FromMinutes(1))
            {
                _triedAt = DateTimeOffset.UtcNow;
                await LoadKeysAsync(ct).ConfigureAwait(false);
            }
            return _keys.GetValueOrDefault(kid);
        }
        finally
        {
            _keysLock.Release();
        }
    }

    /// <summary>The ID-JAG, checked and used once; throws <see cref="TouchqueIdJagException"/> (Error invalid_grant).</summary>
    public async Task<IdJagClaims> VerifyAsync(string assertion, string clientId, CancellationToken ct = default)
    {
        static TouchqueIdJagException Bad(string m) => new("invalid_grant", m);
        var parts = JwsVerify.Split(assertion ?? "") ?? throw Bad("assertion is not a JWT");
        var (head, c, input, sig) = parts;
        if (Json.Str(head, "typ") != "oauth-id-jag+jwt") throw Bad("not an ID-JAG (typ oauth-id-jag+jwt)");
        var alg = Json.Str(head, "alg");
        var kid = Json.Str(head, "kid");
        if (alg is not ("RS256" or "ES256" or "EdDSA") || string.IsNullOrEmpty(kid)) throw Bad("unsupported signature");
        JsonObject? key;
        try
        {
            key = await KeyForAsync(kid, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            throw new TouchqueIdJagException("temporarily_unavailable", "the identity provider's keys could not be read: " + e.Message);
        }
        if (key is null || !JwsVerify.Verify(alg, key, input, sig)) throw Bad("signature does not verify");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var skew = (long)_o.ClockSkew.TotalSeconds;
        var auds = c["aud"] is JsonArray a ? a.Select(x => x?.GetValueKind() == System.Text.Json.JsonValueKind.String ? x.GetValue<string>() : null).ToList() : new List<string?> { Json.Str(c, "aud") };
        var exp = Json.Long(c, "exp");
        var iat = Json.Long(c, "iat");
        var sub = Json.Str(c, "sub");
        var jti = Json.Str(c, "jti");
        if (Json.Str(c, "iss") != _o.Issuer) throw Bad("another issuer");
        if (auds.Count != 1 || auds[0] != _o.Audience) throw Bad("not for this authorization server");
        if (string.IsNullOrEmpty(clientId) || Json.Str(c, "client_id") != clientId) throw Bad("issued to another client");
        if (exp is null || exp.Value + skew < now) throw Bad("expired");
        if (iat is null || iat.Value - skew > now) throw Bad("issued in the future");
        if (string.IsNullOrEmpty(sub) || string.IsNullOrEmpty(jti)) throw Bad("sub and jti are required");
        if (!(_o.FirstUse ?? RememberOnce)(jti, exp.Value)) throw Bad("already used");
        var scope = Json.Str(c, "scope");
        return new IdJagClaims
        {
            Iss = _o.Issuer, Sub = sub, Aud = _o.Audience, ClientId = clientId, Jti = jti, IssuedAt = iat.Value, ExpiresAt = exp.Value,
            Scopes = string.IsNullOrEmpty(scope) ? Array.Empty<string>() : scope.Split(' '),
            Resource = Json.Str(c, "resource"), Tenant = Json.Str(c, "tenant"), Email = Json.Str(c, "email"), AuthTime = Json.Long(c, "auth_time"),
            Amr = c["amr"] is JsonArray amr ? amr.Select(x => x?.ToString() ?? "").ToList() : Array.Empty<string>(),
            Claims = c,
        };
    }
}
