using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>Settings of <see cref="McpAuth"/>.</summary>
public sealed record McpAuthOptions
{
    /// <summary>TouchQue SSO's MCP issuer, e.g. https://sso.touchque.com/mcp.</summary>
    public required string Issuer { get; init; }
    /// <summary>This MCP server's URL (the audience of its tokens, RFC 8707).</summary>
    public required string Resource { get; init; }
    /// <summary>Tool name → the scope it needs.</summary>
    public IReadOnlyDictionary<string, string>? Tools { get; init; }
    public string? ResourceName { get; init; }
    /// <summary>Allowed clock skew (default 60 seconds).</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(60);
    /// <summary>For tests: how JSON documents are fetched (default: a GET with this SDK's HttpClient).</summary>
    public Func<string, CancellationToken, Task<JsonObject>>? Fetch { get; init; }
}

/// <summary>A request's checked token.</summary>
public sealed record McpAuthClaims
{
    public string Sub { get; init; } = "";
    public string? Email { get; init; }
    public string ClientId { get; init; } = "";
    public IReadOnlyList<string> Scopes { get; init; } = Array.Empty<string>();
    public string? OrgId { get; init; }
    public long ExpiresAt { get; init; }
    public bool DpopBound { get; init; }
    public JsonObject Claims { get; init; } = new();
}

/// <summary>
/// For an MCP server whose authorization server is TouchQue SSO (Organization → MCP
/// servers in the dashboard):
/// <list type="bullet">
/// <item><see cref="ProtectedResourceMetadata"/> is its RFC 9728 document, served at <see cref="MetadataPaths"/>,
/// so MCP clients find TouchQue and ask for a token for exactly this server;</item>
/// <item><c>VerifyAsync</c> checks a request's token: signed by TouchQue, this issuer, audience = this
/// server, not expired, and for a DPoP-bound token a fresh proof for this request.
/// <see cref="TouchQueMcpAuthException"/> carries the status and the WWW-Authenticate header to send;</item>
/// <item><see cref="RequireTool"/> refuses with 403 insufficient_scope naming the scope a tool needs.</item>
/// </list>
/// </summary>
public sealed class McpAuth
{
    private readonly string _issuer;
    private readonly string _resource;
    private readonly IReadOnlyDictionary<string, string> _tools;
    private readonly string? _resourceName;
    private readonly TimeSpan _skew;
    private readonly Func<string, CancellationToken, Task<JsonObject>> _fetch;
    private readonly SemaphoreSlim _keysLock = new(1, 1);
    private readonly ConcurrentDictionary<string, long> _proofs = new();
    private Dictionary<string, JsonObject> _keys = new();
    private DateTimeOffset _keysAt;
    private DateTimeOffset _triedAt;

    public McpAuth(McpAuthOptions options)
    {
        if (string.IsNullOrEmpty(options.Issuer) || string.IsNullOrEmpty(options.Resource))
        {
            throw new TouchQueConfigException("McpAuth needs Issuer (TouchQue SSO's MCP issuer) and Resource (this server's URL)");
        }
        _issuer = options.Issuer.TrimEnd('/');
        _resource = options.Resource;
        _tools = options.Tools ?? new Dictionary<string, string>();
        _resourceName = options.ResourceName;
        _skew = options.ClockSkew;
        _fetch = options.Fetch ?? GetJsonAsync;
    }

    /// <summary>Where to serve <see cref="ProtectedResourceMetadata"/>.</summary>
    public IReadOnlyList<string> MetadataPaths()
    {
        var path = new Uri(_resource).AbsolutePath.TrimEnd('/');
        return path.Length == 0
            ? new[] { "/.well-known/oauth-protected-resource" }
            : new[] { "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource" + path };
    }

    public string MetadataUrl()
    {
        var u = new Uri(_resource);
        return u.GetLeftPart(UriPartial.Authority) + MetadataPaths()[^1];
    }

    /// <summary>The RFC 9728 protected resource metadata of this server.</summary>
    public JsonObject ProtectedResourceMetadata()
    {
        var doc = new JsonObject
        {
            ["resource"] = _resource,
            ["authorization_servers"] = new JsonArray(_issuer),
            ["bearer_methods_supported"] = new JsonArray("header"),
            ["scopes_supported"] = new JsonArray(_tools.Values.Distinct().Select(s => (JsonNode)s).ToArray()),
            ["dpop_signing_alg_values_supported"] = new JsonArray("ES256", "EdDSA"),
        };
        if (_resourceName is not null) doc["resource_name"] = _resourceName;
        return doc;
    }

    /// <summary>A request's token, checked.</summary>
    /// <param name="header">A case-insensitive header getter (e.g. <c>name => request.Headers[name]</c>).</param>
    public async Task<McpAuthClaims> VerifyAsync(string method, string url, Func<string, string?> header, CancellationToken ct = default)
    {
        var auth = (header("authorization") ?? "").Trim();
        var space = auth.IndexOf(' ');
        var scheme = space < 0 ? auth.ToLowerInvariant() : auth[..space].ToLowerInvariant();
        var token = space < 0 ? "" : auth[(space + 1)..].Trim();
        if (scheme is not ("bearer" or "dpop") || token.Count(c => c == '.') != 2)
        {
            throw Fail(401, "missing_token", "A TouchQue access token is required");
        }
        var claims = await ClaimsAsync(token, ct).ConfigureAwait(false);
        var jkt = Json.Str(claims["cnf"], "jkt");
        if (!string.IsNullOrEmpty(jkt))
        {
            if (scheme != "dpop") throw Fail(401, "invalid_token", "This token is bound to a DPoP key: send it as DPoP with a proof");
            CheckProof(header("dpop"), method, url, token, jkt);
        }
        return new McpAuthClaims
        {
            Sub = Json.Str(claims, "sub") ?? "",
            Email = Json.Str(claims, "email"),
            ClientId = Json.Str(claims, "client_id") ?? "",
            Scopes = (Json.Str(claims, "scope") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries),
            OrgId = Json.Str(claims, "org_id"),
            ExpiresAt = Json.Long(claims, "exp") ?? 0,
            DpopBound = !string.IsNullOrEmpty(jkt),
            Claims = claims,
        };
    }

    /// <summary>Checks a request's token from a header dictionary (any key case).</summary>
    public Task<McpAuthClaims> VerifyAsync(string method, string url, IReadOnlyDictionary<string, string> headers, CancellationToken ct = default)
    {
        var lower = headers.ToDictionary(h => h.Key.ToLowerInvariant(), h => h.Value);
        return VerifyAsync(method, url, name => lower.GetValueOrDefault(name.ToLowerInvariant()), ct);
    }

    public void RequireScope(McpAuthClaims claims, string scope)
    {
        if (!claims.Scopes.Contains(scope)) throw Fail(403, "insufficient_scope", $"This needs the {scope} scope", scope);
    }

    public void RequireTool(McpAuthClaims claims, string tool)
    {
        if (!_tools.TryGetValue(tool, out var scope) || string.IsNullOrEmpty(scope))
        {
            throw Fail(403, "insufficient_scope", $"No scope is set for the tool {tool}");
        }
        RequireScope(claims, scope);
    }

    private TouchQueMcpAuthException Fail(int status, string code, string message, string? scope = null)
    {
        var parts = new List<string> { $"resource_metadata=\"{MetadataUrl()}\"" };
        if (code != "missing_token")
        {
            parts.Add($"error=\"{code}\"");
            parts.Add($"error_description=\"{message.Replace('"', '\'')}\"");
            if (scope is not null) parts.Add($"scope=\"{scope}\"");
        }
        return new TouchQueMcpAuthException(status, code, message, "Bearer " + string.Join(", ", parts));
    }

    private async Task<JsonObject> ClaimsAsync(string token, CancellationToken ct)
    {
        var parts = JwsVerify.Split(token) ?? throw Fail(401, "invalid_token", "The token is malformed");
        var (head, claims, input, sig) = parts;
        var alg = Json.Str(head, "alg");
        if (Json.Str(head, "typ") != "at+jwt" || alg is not ("RS256" or "ES256"))
        {
            throw Fail(401, "invalid_token", "Not a TouchQue access token");
        }
        JsonObject? key;
        try
        {
            key = await KeyForAsync(Json.Str(head, "kid") ?? "", ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException and not TouchQueMcpAuthException)
        {
            throw Fail(401, "invalid_token", "The authorization server's keys could not be read");
        }
        if (key is null || !JwsVerify.Verify(alg, key, input, sig)) throw Fail(401, "invalid_token", "The token signature does not verify");
        if ((Json.Str(claims, "iss") ?? "").TrimEnd('/') != _issuer) throw Fail(401, "invalid_token", "The token is from another issuer");
        var aud = claims["aud"];
        var audiences = aud is JsonArray a ? a.Select(x => x is JsonValue v && v.TryGetValue<string>(out var s) ? s : null) : new[] { Json.Str(claims, "aud") };
        if (!audiences.Contains(_resource)) throw Fail(401, "invalid_token", "The token is for another server");
        var exp = Json.Long(claims, "exp");
        if (exp is null || exp.Value + (long)_skew.TotalSeconds <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) throw Fail(401, "invalid_token", "The token expired");
        return claims;
    }

    private async Task LoadKeysAsync(CancellationToken ct)
    {
        var u = new Uri(_issuer);
        var meta = await _fetch(u.GetLeftPart(UriPartial.Authority) + "/.well-known/oauth-authorization-server" + u.AbsolutePath.TrimEnd('/'), ct).ConfigureAwait(false);
        var jwksUri = Json.Str(meta, "jwks_uri");
        if ((Json.Str(meta, "issuer") ?? "").TrimEnd('/') != _issuer || string.IsNullOrEmpty(jwksUri))
        {
            throw new InvalidOperationException("the authorization server metadata does not match the issuer");
        }
        var keys = new Dictionary<string, JsonObject>();
        if ((await _fetch(jwksUri, ct).ConfigureAwait(false))["keys"] is JsonArray list)
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

    private void CheckProof(string? proof, string method, string url, string token, string jkt)
    {
        TouchQueMcpAuthException Reject(string why) => Fail(401, "invalid_dpop_proof", "DPoP proof: " + why);
        if (string.IsNullOrEmpty(proof) || proof.Count(c => c == '.') != 2) throw Reject("missing");
        var parts = JwsVerify.Split(proof) ?? throw Reject("malformed");
        var (head, claims, input, sig) = parts;
        var jwk = head["jwk"] as JsonObject;
        if (Json.Str(head, "typ") != "dpop+jwt" || jwk is null || jwk.ContainsKey("d") || Json.Str(jwk, "kty") is not ("EC" or "OKP") || AgentKeys.Thumbprint(jwk) != jkt)
        {
            throw Reject("not the bound key");
        }
        if (!JwsVerify.Verify(Json.Str(head, "alg") ?? "", jwk, input, sig)) throw Reject("signature");
        var htu = new Uri(url).GetLeftPart(UriPartial.Path);
        if (Json.Str(claims, "htm") != method.ToUpperInvariant() || Json.Str(claims, "htu") != htu) throw Reject("htm/htu");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (Math.Abs((Json.Long(claims, "iat") ?? 0) - now) > (long)_skew.TotalSeconds) throw Reject("iat");
        if (Json.Str(claims, "ath") != AgentKeys.AccessTokenHash(token)) throw Reject("ath");
        foreach (var (k, until) in _proofs)
        {
            if (until < now) _proofs.TryRemove(k, out _);
        }
        var jti = Json.Str(claims, "jti") ?? "";
        if (jti.Length == 0 || !_proofs.TryAdd(jti, now + 2 * (long)_skew.TotalSeconds)) throw Reject("jti used");
    }

    private static readonly Lazy<HttpClient> SharedClient = new(() => TouchQueHttp.CreateClient(TimeSpan.FromSeconds(5)));

    private static async Task<JsonObject> GetJsonAsync(string url, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.ParseAdd("application/json");
        using var res = await SharedClient.Value.SendAsync(req, ct).ConfigureAwait(false);
        if ((int)res.StatusCode >= 400) throw new InvalidOperationException($"{url} answered {(int)res.StatusCode}");
        return Json.ParseObject(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
    }
}
