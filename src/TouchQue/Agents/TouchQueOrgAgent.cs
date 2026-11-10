using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>Settings of a <see cref="TouchQueOrgAgent"/>; null falls back to the environment.</summary>
public sealed record TouchQueOrgAgentOptions
{
    /// <summary>The <c>oagt_…</c> id from Organization → AI agents (default: TQ_ORG_AGENT_ID).</summary>
    public string? AgentId { get; init; }
    /// <summary>TouchQue SSO (default: TQ_SSO_URL, else https://sso.touchque.com).</summary>
    public string? Issuer { get; init; }
    /// <summary>The agent's own key: a JWK (JsonObject or JSON) or an EC P-256 PEM (default: TQ_ORG_AGENT_KEY).</summary>
    public object? PrivateKey { get; init; }
    public string? Kid { get; init; }
    /// <summary>Or the token the agent's platform gives it (GitHub Actions, GitLab, Google Cloud, Azure, Kubernetes): see <see cref="TouchQueOrgAgent.GitHubActionsToken"/>, <see cref="TouchQueOrgAgent.FileToken"/>.</summary>
    public Func<CancellationToken, Task<string>>? Assertion { get; init; }
    /// <summary>The app (tqapp_…) tokens are for by default.</summary>
    public string? Resource { get; init; }
    public string? Scope { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);
    public HttpClient? HttpClient { get; init; }
}

/// <summary>
/// An organization's AI agent on TouchQue SSO (Organization → AI agents in the
/// dashboard): it gets 5-minute tokens for one of the organization's apps, proving
/// who it is with its own key (private_key_jwt) or with the token its platform
/// already gives it, and binds each token to a DPoP key made when it starts. The
/// app checks the token with TouchQue's JWKS and the DPoP proof on every call.
/// <code>
/// var agent = new TouchQueOrgAgent(new() { AgentId = "oagt_…", PrivateKey = Environment.GetEnvironmentVariable("TQ_ORG_AGENT_KEY") });
/// var headers = await agent.AuthorizationAsync("GET", "https://payments.acme.com/invoices", resource: "tqapp_…");
/// // In a GitHub Actions job (permissions: id-token: write), with no key to store:
/// var ci = new TouchQueOrgAgent(new() { AgentId = "oagt_…", Assertion = TouchQueOrgAgent.GitHubActionsToken("touchque") });
/// </code>
/// </summary>
public sealed partial class TouchQueOrgAgent : IDisposable
{
    private readonly string _issuer;
    private readonly SigningKey? _key;
    private readonly string? _kid;
    private readonly Func<CancellationToken, Task<string>>? _assertion;
    private readonly SigningKey _dpopKey = SigningKey.NewEs256();
    private readonly string? _resource;
    private readonly string? _scope;
    private readonly TimeSpan _timeout;
    private readonly HttpClient _client;
    private readonly bool _ownsClient;
    private readonly ConcurrentDictionary<string, (OrgAgentToken Token, DateTimeOffset ExpiresAt)> _tokens = new();

    [GeneratedRegex("^oagt_[a-z2-9]{20}$")]
    private static partial Regex AgentIdRe();

    public TouchQueOrgAgent() : this(new TouchQueOrgAgentOptions()) { }

    public TouchQueOrgAgent(TouchQueOrgAgentOptions options)
    {
        var agentId = options.AgentId ?? Environment.GetEnvironmentVariable("TQ_ORG_AGENT_ID") ?? "";
        if (!AgentIdRe().IsMatch(agentId))
        {
            throw new TouchQueConfigException("Set TQ_ORG_AGENT_ID (or AgentId): the oagt_… id from Organization → AI agents");
        }
        AgentId = agentId;
        _issuer = (options.Issuer ?? Environment.GetEnvironmentVariable("TQ_SSO_URL") ?? "https://sso.touchque.com").TrimEnd('/');
        TouchQueOptions.AssertSafeBaseUrl(_issuer, "Issuer");
        if (options.Assertion is not null)
        {
            _assertion = options.Assertion;
        }
        else
        {
            var privateKey = options.PrivateKey ?? Environment.GetEnvironmentVariable("TQ_ORG_AGENT_KEY");
            if (privateKey is null || privateKey is string { Length: 0 })
            {
                throw new TouchQueConfigException("Pass PrivateKey (or set TQ_ORG_AGENT_KEY), or Assertion with the platform's token");
            }
            _key = SigningKey.Load(privateKey, "TouchQueOrgAgent");
            var jwk = privateKey as JsonObject ?? (privateKey is string s && s.TrimStart().StartsWith('{') ? Json.Parse(s) as JsonObject : null);
            _kid = options.Kid ?? Json.Str(jwk, "kid") ?? AgentKeys.Thumbprint(_key.PublicJwk);
        }
        _resource = options.Resource;
        _scope = options.Scope;
        _timeout = options.Timeout;
        _ownsClient = options.HttpClient is null;
        _client = options.HttpClient ?? TouchQueHttp.CreateClient(options.Timeout);
    }

    public string AgentId { get; }

    /// <summary>The token a GitHub Actions job may ask for (the job needs <c>permissions: id-token: write</c>).</summary>
    public static Func<CancellationToken, Task<string>> GitHubActionsToken(string audience = "touchque") => async ct =>
    {
        var url = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL");
        var bearer = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(bearer))
        {
            throw new TouchQueConfigException("Not in a GitHub Actions job with `permissions: id-token: write`");
        }
        using var client = TouchQueHttp.CreateClient(TimeSpan.FromSeconds(10));
        using var req = new HttpRequestMessage(HttpMethod.Get, url + (url.Contains('?') ? "&" : "?") + "audience=" + Uri.EscapeDataString(audience));
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        using var res = await client.SendAsync(req, ct).ConfigureAwait(false);
        var value = Json.Str(Json.ParseObject(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false)), "value");
        return string.IsNullOrEmpty(value) ? throw new TouchQueConfigException("GitHub gave no token") : value;
    };

    /// <summary>A token the platform writes to a file and renews (a Kubernetes projected service account token…).</summary>
    public static Func<CancellationToken, Task<string>> FileToken(string path) => async ct => (await File.ReadAllTextAsync(path, ct).ConfigureAwait(false)).Trim();

    /// <summary>A DPoP proof (RFC 9449) for one request: with the token, for a call to the app.</summary>
    public string DpopProof(string method, string url, string? accessToken = null)
    {
        var u = new Uri(url);
        var htu = u.GetLeftPart(UriPartial.Path);
        var claims = new JsonObject
        {
            ["htm"] = method.ToUpperInvariant(), ["htu"] = htu, ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["jti"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
        };
        if (accessToken is not null) claims["ath"] = AgentKeys.AccessTokenHash(accessToken);
        return _dpopKey.Jws(new JsonObject { ["typ"] = "dpop+jwt", ["jwk"] = _dpopKey.PublicJwk.DeepClone() }, claims);
    }

    private async Task<string> ClientAssertionAsync(CancellationToken ct)
    {
        if (_assertion is not null) return await _assertion(ct).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return _key!.Jws(new JsonObject { ["typ"] = "JWT", ["kid"] = _kid }, new JsonObject
        {
            ["iss"] = AgentId, ["sub"] = AgentId, ["aud"] = _issuer + "/sso/token", ["iat"] = now, ["exp"] = now + 60,
            ["jti"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
        });
    }

    /// <summary>POSTs to the SSO with the agent's client assertion (and, at /sso/token, a DPoP proof).</summary>
    private async Task<JsonObject> PostAsync(string path, IEnumerable<KeyValuePair<string, string?>> fields, bool dpop, CancellationToken ct)
    {
        var url = _issuer + path;
        var form = new List<KeyValuePair<string, string>>
        {
            new("client_id", AgentId), new("client_assertion_type", TouchQueAgent.AssertionType), new("client_assertion", await ClientAssertionAsync(ct).ConfigureAwait(false)),
        };
        foreach (var (k, v) in fields)
        {
            if (!string.IsNullOrEmpty(v)) form.Add(new(k, v));
        }
        using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new FormUrlEncodedContent(form) };
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (dpop) req.Headers.TryAddWithoutValidation("DPoP", DpopProof("POST", url));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_timeout);
        try
        {
            using var res = await _client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            var data = Json.ParseObject(await TouchQueHttp.ReadLimitedAsync(res, timeout.Token).ConfigureAwait(false));
            if ((int)res.StatusCode != 200) throw TouchQueAgent.Failure((int)res.StatusCode, data);
            return data;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TouchQueNetworkException("timed out");
        }
        catch (HttpRequestException e)
        {
            throw new TouchQueNetworkException(e.Message, e);
        }
    }

    private static OrgAgentToken TokenOf(JsonObject data) => new()
    {
        AccessToken = Json.Str(data, "access_token") ?? "",
        TokenType = "DPoP",
        ExpiresIn = Json.Int(data, "expires_in") ?? 300,
        Scope = Json.Str(data, "scope") ?? "",
        AuthorizationDetails = data["authorization_details"] as JsonArray is { } ad ? (JsonArray)ad.DeepClone() : null,
    };

    /// <summary>A token for one app (renewed 30 seconds before it expires).</summary>
    public async Task<OrgAgentToken> GetTokenAsync(string? resource = null, string? scope = null, CancellationToken ct = default)
    {
        resource ??= _resource;
        scope ??= _scope;
        var cacheKey = (resource ?? "") + " " + (scope ?? "");
        if (_tokens.TryGetValue(cacheKey, out var cached) && cached.ExpiresAt - DateTimeOffset.UtcNow > TimeSpan.FromSeconds(30)) return cached.Token;
        var token = TokenOf(await PostAsync("/sso/token", new Dictionary<string, string?>
        {
            ["grant_type"] = "client_credentials", ["resource"] = resource, ["scope"] = scope,
        }, true, ct).ConfigureAwait(false));
        _tokens[cacheKey] = (token, DateTimeOffset.UtcNow.AddSeconds(token.ExpiresIn));
        return token;
    }

    /// <summary>A token for a member, with their own access token for one of the agent's apps (RFC 8693): sub is the member, act the agent.</summary>
    public async Task<OrgAgentToken> ExchangeTokenAsync(string subjectToken, string? resource = null, string? scope = null, CancellationToken ct = default) =>
        TokenOf(await PostAsync("/sso/token", new Dictionary<string, string?>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange", ["subject_token"] = subjectToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token", ["resource"] = resource ?? _resource, ["scope"] = scope ?? _scope,
        }, true, ct).ConfigureAwait(false));

    /// <summary>
    /// The token vault: a member's own access token at another service (Google, Microsoft 365,
    /// GitHub…) they connected on TouchQue, for a connection that names this agent.
    /// <paramref name="subjectToken"/> is the member's token, as for <see cref="ExchangeTokenAsync"/>;
    /// <paramref name="scope"/> may only narrow what the member granted. <see cref="TouchQueApiException"/>
    /// invalid_grant: the member has not connected it (or disconnected, or left).
    /// </summary>
    public async Task<OrgAgentConnectionToken> GetConnectionTokenAsync(string subjectToken, string connection, string? scope = null, CancellationToken ct = default)
    {
        var data = await PostAsync("/sso/token", new Dictionary<string, string?>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange", ["subject_token"] = subjectToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["requested_token_type"] = "urn:touchque:params:oauth:token-type:connection-access-token", ["connection"] = connection, ["scope"] = scope,
        }, true, ct).ConfigureAwait(false);
        return new OrgAgentConnectionToken
        {
            AccessToken = Json.Str(data, "access_token") ?? "", TokenType = "Bearer", ExpiresIn = Json.Int(data, "expires_in"),
            Scope = Json.Str(data, "scope") ?? "", Connection = Json.Str(data, "connection") ?? connection,
        };
    }

    /// <summary>
    /// Asks to open a shared account (its key, from Organization → AI agents → Access) for a
    /// member. The member opens <c>OpenUrl</c> in the browser where their TouchQue extension is
    /// paired; their phone approves with this agent named and the extension signs in there. The
    /// agent never sees the password. <paramref name="message"/> (at most 64 characters) is shown marked unverified.
    /// </summary>
    public async Task<SharedAccountAsk> AskToOpenSharedAccountAsync(string account, string loginHint, string? message = null, CancellationToken ct = default)
    {
        var data = await PostAsync("/sso/agents/shared-accounts/asks", new Dictionary<string, string?>
        {
            ["account"] = account, ["login_hint"] = loginHint, ["binding_message"] = message,
        }, false, ct).ConfigureAwait(false);
        return new SharedAccountAsk
        {
            AskId = Json.Str(data, "ask_id") ?? "", OpenUrl = Json.Str(data, "open_url") ?? "", Status = Json.Str(data, "status") ?? "",
            ExpiresIn = Json.Int(data, "expires_in") ?? 600,
        };
    }

    /// <summary>Where an ask stands; never anything of the account.</summary>
    public async Task<SharedAccountAskStatus> SharedAccountAskStatusAsync(string askId, CancellationToken ct = default)
    {
        var data = await PostAsync("/sso/agents/shared-accounts/asks/" + Uri.EscapeDataString(askId), Array.Empty<KeyValuePair<string, string?>>(), false, ct).ConfigureAwait(false);
        return new SharedAccountAskStatus { Status = Json.Str(data, "status") ?? "", Reason = Json.Str(data, "reason"), CaseCode = Json.Str(data, "case_code") };
    }

    /// <summary>Polls an ask until it ends: opened, refused, declined or expired.</summary>
    public async Task<SharedAccountAskStatus> WaitForSharedAccountAsync(SharedAccountAsk ask, TimeSpan? interval = null, CancellationToken ct = default)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(ask.ExpiresIn + 5);
        while (true)
        {
            var s = await SharedAccountAskStatusAsync(ask.AskId, ct).ConfigureAwait(false);
            if (s.Status is not ("waiting_member" or "asked_phone") || DateTimeOffset.UtcNow > deadline) return s;
            await Task.Delay(interval ?? TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
        }
    }

    /// <summary>Asks a member to approve on their phone (CIBA). Show <c>BindingCode</c> in the conversation.</summary>
    public async Task<MemberRequest> AskMemberAsync(string loginHint, AskMemberOptions? options = null, CancellationToken ct = default)
    {
        var o = options ?? new AskMemberOptions();
        var data = await PostAsync("/sso/bc-authorize", new Dictionary<string, string?>
        {
            ["login_hint"] = loginHint, ["binding_message"] = o.BindingMessage, ["resource"] = o.Resource ?? _resource, ["scope"] = o.Scope ?? _scope,
            ["authorization_details"] = o.AuthorizationDetails is null ? null : Json.Serialize(Json.ToNode(o.AuthorizationDetails)),
            ["requested_expiry"] = o.RequestedExpiry?.ToString(System.Globalization.CultureInfo.InvariantCulture),
        }, false, ct).ConfigureAwait(false);
        return new MemberRequest
        {
            AuthReqId = Json.Str(data, "auth_req_id") ?? "", ExpiresIn = Json.Int(data, "expires_in") ?? 300,
            Interval = Json.Int(data, "interval") ?? 5, BindingCode = Json.Str(data, "binding_code"),
        };
    }

    /// <summary>
    /// The member's answer (polling at the interval, slower when asked): the token once they
    /// approve; <see cref="TouchQueApiException"/> access_denied or expired_token otherwise,
    /// <see cref="TouchQueTimeoutException"/> after it expired.
    /// </summary>
    public async Task<OrgAgentToken> WaitForMemberAsync(MemberRequest request, CancellationToken ct = default)
    {
        var interval = Math.Max(1, request.Interval);
        var deadline = DateTimeOffset.UtcNow.AddSeconds(request.ExpiresIn + 5);
        while (DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromSeconds(interval), ct).ConfigureAwait(false);
            try
            {
                return TokenOf(await PostAsync("/sso/token", new Dictionary<string, string?>
                {
                    ["grant_type"] = "urn:openid:params:grant-type:ciba", ["auth_req_id"] = request.AuthReqId,
                }, true, ct).ConfigureAwait(false));
            }
            catch (TouchQueApiException e) when (e.Code == "authorization_pending")
            {
            }
            catch (TouchQueApiException e) when (e.Code == "slow_down")
            {
                interval += 5;
            }
        }
        throw new TouchQueTimeoutException("The member did not answer in time");
    }

    /// <summary>The two headers for one call to the app: <c>Authorization: DPoP …</c> and <c>DPoP</c>.</summary>
    public async Task<IReadOnlyDictionary<string, string>> AuthorizationAsync(string method, string url, string? resource = null, string? scope = null, CancellationToken ct = default)
    {
        var token = (await GetTokenAsync(resource, scope, ct).ConfigureAwait(false)).AccessToken;
        return new Dictionary<string, string> { ["Authorization"] = "DPoP " + token, ["DPoP"] = DpopProof(method, url, token) };
    }

    /// <summary>Sets <c>Authorization: DPoP …</c> and a fresh DPoP proof on a request to the app.</summary>
    public async Task AuthorizeAsync(HttpRequestMessage request, string? resource = null, string? scope = null, CancellationToken ct = default)
    {
        foreach (var (k, v) in await AuthorizationAsync(request.Method.Method, request.RequestUri!.ToString(), resource, scope, ct).ConfigureAwait(false))
        {
            request.Headers.Remove(k);
            request.Headers.TryAddWithoutValidation(k, v);
        }
    }

    public void Dispose()
    {
        _key?.Dispose();
        _dpopKey.Dispose();
        if (_ownsClient) _client.Dispose();
    }
}

/// <summary>A DPoP-bound access token for one app.</summary>
public sealed record OrgAgentToken
{
    public string AccessToken { get; init; } = "";
    public string TokenType { get; init; } = "DPoP";
    public int ExpiresIn { get; init; }
    public string Scope { get; init; } = "";
    /// <summary>CIBA: what the member approved.</summary>
    public JsonArray? AuthorizationDetails { get; init; }
}

/// <summary>A member's own access token at another service (token vault).</summary>
public sealed record OrgAgentConnectionToken
{
    public string AccessToken { get; init; } = "";
    public string TokenType { get; init; } = "Bearer";
    /// <summary>Null when the service does not say.</summary>
    public int? ExpiresIn { get; init; }
    public string Scope { get; init; } = "";
    public string Connection { get; init; } = "";
}

public sealed record SharedAccountAsk
{
    public string AskId { get; init; } = "";
    public string OpenUrl { get; init; } = "";
    public string Status { get; init; } = "";
    public int ExpiresIn { get; init; }
}

/// <summary>waiting_member, asked_phone, opened, refused, declined or expired.</summary>
public sealed record SharedAccountAskStatus
{
    public string Status { get; init; } = "";
    public string? Reason { get; init; }
    public string? CaseCode { get; init; }
}

public sealed record AskMemberOptions
{
    public string? BindingMessage { get; init; }
    /// <summary>RFC 9396 authorization details (any object).</summary>
    public object? AuthorizationDetails { get; init; }
    public string? Resource { get; init; }
    public string? Scope { get; init; }
    public int? RequestedExpiry { get; init; }
}

/// <summary>A CIBA request waiting for the member.</summary>
public sealed record MemberRequest
{
    public string AuthReqId { get; init; } = "";
    public int ExpiresIn { get; init; }
    public int Interval { get; init; }
    public string? BindingCode { get; init; }
}
