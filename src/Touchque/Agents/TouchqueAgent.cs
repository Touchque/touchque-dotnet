using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Touchque.Internal;

namespace Touchque;

/// <summary>Settings of a <see cref="TouchqueAgent"/>; null falls back to the environment.</summary>
public sealed record TouchqueAgentOptions
{
    /// <summary>The <c>agt_…</c> id from <c>Agents.CreateAsync</c> (default: TQ_AGENT_ID).</summary>
    public string? AgentId { get; init; }
    /// <summary>The agent's private key: a JWK (JsonObject or its JSON text) or an EC P-256 PEM (default: TQ_AGENT_KEY).</summary>
    public object? PrivateKey { get; init; }
    /// <summary>The kid it was registered with (default: the JWK's kid, else its RFC 7638 thumbprint).</summary>
    public string? Kid { get; init; }
    /// <summary>The API's address (default: TQ_API_URL, else https://api.touchque.com).</summary>
    public string? BaseUrl { get; init; }
    /// <summary>Scopes to ask for (default: all the agent has).</summary>
    public string? Scope { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);
    /// <summary>Your own HttpClient (never following redirects).</summary>
    public HttpClient? HttpClient { get; init; }
}

/// <summary>
/// The agent side: an AI agent calls Touchque with its OWN key, never with your API
/// key. It signs a private_key_jwt assertion (RFC 7523) for a 10-minute token bound
/// to its key with DPoP (RFC 9449), and proves the key on every call, so a stolen
/// token is useless on its own.
/// <code>
/// var agent = new TouchqueAgent();      // TQ_AGENT_ID, TQ_AGENT_KEY
/// var asked = await agent.RequireApprovalAsync("ayse@example.com", "PAY_INVOICE", new[] { payment },
///     onChallenge: s => Console.WriteLine($"Type {s.ChallengeCode} on your phone"));
/// </code>
/// </summary>
public sealed partial class TouchqueAgent : IDisposable
{
    public const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static readonly HashSet<string> Ended = new() { "rejected", "blocked", "revoked", "expired", "stale", "redeemed" };

    private readonly SigningKey _key;
    private readonly string _kid;
    private readonly string _baseUrl;
    private readonly string? _scope;
    private readonly HttpClient _client;
    private readonly bool _ownsClient;
    private readonly TimeSpan _timeout;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);
    private string? _token;
    private DateTimeOffset _tokenExpiresAt;

    [GeneratedRegex("^agt_[a-z2-9]{20}$")]
    private static partial Regex AgentIdRe();

    public TouchqueAgent() : this(new TouchqueAgentOptions()) { }

    public TouchqueAgent(TouchqueAgentOptions options)
    {
        var agentId = options.AgentId ?? Environment.GetEnvironmentVariable("TQ_AGENT_ID") ?? "";
        if (!AgentIdRe().IsMatch(agentId))
        {
            throw new TouchqueConfigException("Set TQ_AGENT_ID (or AgentId): the agt_… id from Agents.CreateAsync()");
        }
        AgentId = agentId;
        var privateKey = options.PrivateKey ?? Environment.GetEnvironmentVariable("TQ_AGENT_KEY");
        if (privateKey is null || privateKey is string { Length: 0 })
        {
            throw new TouchqueConfigException("Set TQ_AGENT_KEY (or PrivateKey): the agent's private key");
        }
        _key = SigningKey.Load(privateKey, "TouchqueAgent");
        var jwk = privateKey as JsonObject ?? (privateKey is string s && s.TrimStart().StartsWith('{') ? Json.Parse(s) as JsonObject : null);
        _kid = options.Kid ?? Json.Str(jwk, "kid") ?? AgentKeys.Thumbprint(_key.PublicJwk);
        _baseUrl = (options.BaseUrl ?? Environment.GetEnvironmentVariable("TQ_API_URL") ?? TouchqueOptions.DefaultBaseUrl).TrimEnd('/');
        TouchqueOptions.AssertSafeBaseUrl(_baseUrl, "BaseUrl");
        _scope = options.Scope;
        _timeout = options.Timeout;
        _ownsClient = options.HttpClient is null;
        _client = options.HttpClient ?? TouchqueHttp.CreateClient(options.Timeout);
    }

    public string AgentId { get; }

    /// <summary>The agent's current token (renewed a minute before it expires).</summary>
    public async Task<string> AccessTokenAsync(CancellationToken ct = default)
    {
        await _tokenLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_token is not null && _tokenExpiresAt - DateTimeOffset.UtcNow > TimeSpan.FromSeconds(60)) return _token;
            return await FetchTokenAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    private async Task<string> FetchTokenAsync(CancellationToken ct)
    {
        var url = _baseUrl + "/agents/token";
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var assertion = _key.Jws(new JsonObject { ["typ"] = "JWT", ["kid"] = _kid }, new JsonObject
        {
            ["iss"] = AgentId, ["sub"] = AgentId, ["aud"] = url, ["iat"] = now, ["exp"] = now + 60, ["jti"] = Nonce(),
        });
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "client_credentials"), new("client_assertion_type", AssertionType), new("client_assertion", assertion),
        };
        if (!string.IsNullOrEmpty(_scope)) form.Add(new("scope", _scope));
        using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new FormUrlEncodedContent(form) };
        req.Headers.TryAddWithoutValidation("DPoP", DpopProof("POST", url, null));
        var (status, data) = await SendAsync(req, ct).ConfigureAwait(false);
        if (status != 200) throw Failure(status, data);
        _token = Json.Str(data, "access_token") ?? throw Failure(status, data);
        _tokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(Json.Long(data, "expires_in") ?? 600);
        return _token;
    }

    private string DpopProof(string method, string url, string? accessToken)
    {
        var claims = new JsonObject { ["htm"] = method, ["htu"] = url, ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["jti"] = Nonce() };
        if (accessToken is not null) claims["ath"] = AgentKeys.AccessTokenHash(accessToken);
        return _key.Jws(new JsonObject { ["typ"] = "dpop+jwt", ["jwk"] = _key.PublicJwk.DeepClone() }, claims);
    }

    private static string Nonce() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    private async Task<(int Status, JsonObject Data)> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        req.Headers.TryAddWithoutValidation("User-Agent", "touchque-dotnet-sdk/" + TouchqueHttp.SdkVersion + " agent");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_timeout);
        try
        {
            using var res = await _client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            var text = await TouchqueHttp.ReadLimitedAsync(res, timeout.Token).ConfigureAwait(false);
            return ((int)res.StatusCode, Json.ParseObject(text));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TouchqueNetworkException("timed out");
        }
        catch (HttpRequestException e)
        {
            throw new TouchqueNetworkException(e.Message, e);
        }
    }

    internal static TouchqueApiException Failure(int status, JsonObject data)
    {
        if (!data.ContainsKey("code") && Json.Str(data, "error") is { } err) data["code"] = err;
        if (!data.ContainsKey("retryAfter") && Json.Int(data, "retry_after") is { } ra) data["retryAfter"] = ra;
        return TouchqueApiException.For(status, data, Json.Str(data, "error_description") ?? Json.Str(data, "error") ?? $"Touchque API error: HTTP {status}");
    }

    /// <summary>A call with the agent's token and a fresh DPoP proof; one retry with a new token when Touchque no longer knows it.</summary>
    private async Task<JsonObject> RequestAsync(HttpMethod method, string path, JsonNode? body, CancellationToken ct, bool retried = false)
    {
        var token = await AccessTokenAsync(ct).ConfigureAwait(false);
        var url = _baseUrl + path;
        using var req = new HttpRequestMessage(method, url);
        req.Headers.TryAddWithoutValidation("Authorization", "DPoP " + token);
        req.Headers.TryAddWithoutValidation("DPoP", DpopProof(method.Method, url.Split('?')[0], token));
        if (body is not null) req.Content = new StringContent(Json.Serialize(body), new UTF8Encoding(false), "application/json");
        var (status, data) = await SendAsync(req, ct).ConfigureAwait(false);
        if (status == 401 && !retried && Json.Str(data, "code") == "invalid_token")
        {
            await _tokenLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_token == token) _token = null;
            }
            finally
            {
                _tokenLock.Release();
            }
            return await RequestAsync(method, path, body, ct, true).ConfigureAwait(false);
        }
        if (status is < 200 or >= 300) throw Failure(status, data);
        return data;
    }

    /// <summary>The agent as Touchque sees it: its action types, owner, review date and workspace.</summary>
    public async Task<AgentSelf> MeAsync(CancellationToken ct = default) =>
        Json.To<AgentSelf>(await RequestAsync(HttpMethod.Get, "/agents/me", null, ct).ConfigureAwait(false));

    /// <summary>
    /// Asks the person to approve on their Touchque phone. Show <c>ChallengeCode</c> in
    /// your conversation (presence interactive, the default): the person types it on the
    /// phone. Touchque draws the phone's rows from <paramref name="authorizationDetails"/>
    /// (RFC 9396; any object).
    /// </summary>
    public async Task<AgentApprovalState> RequestApprovalAsync(string user, string type, object authorizationDetails, AgentApprovalOptions? options = null, CancellationToken ct = default)
    {
        var body = new JsonObject { ["externalUsername"] = user, ["type"] = type, ["authorizationDetails"] = Json.ToNode(authorizationDetails) };
        if (options is not null)
        {
            body.Put("reason", options.Reason).Put("presence", options.Presence).Put("expiresIn", options.ExpiresIn).Put("locale", options.Locale)
                .Put("referenceId", options.ReferenceId).Put("clientIp", options.ClientIp).Put("userAgent", options.UserAgent).Put("mandateId", options.MandateId);
        }
        return Json.To<AgentApprovalState>(await RequestAsync(HttpMethod.Post, "/agents/approvals", body, ct).ConfigureAwait(false));
    }

    /// <summary>
    /// Asks the person for a mandate: one approval on the phone for a bounded series of
    /// requests. Once active, pass <c>MandateId</c> to <see cref="RequestApprovalAsync"/>: no push.
    /// </summary>
    public async Task<Mandate> RequestMandateAsync(string user, string type, int maxCount, MandateAmount maxTotal, MandateOptions? options = null, CancellationToken ct = default)
    {
        var body = new JsonObject
        {
            ["externalUsername"] = user, ["type"] = type, ["maxCount"] = maxCount,
            ["maxTotal"] = new JsonObject { ["currency"] = maxTotal.Currency, ["amount"] = maxTotal.Amount },
        };
        if (options is not null)
        {
            if (options.PerRequest is not null) body["perRequest"] = new JsonObject { ["currency"] = options.PerRequest.Currency, ["amount"] = options.PerRequest.Amount };
            if (options.Recipients is not null) body["recipients"] = new JsonArray(options.Recipients.Select(r => (JsonNode)r).ToArray());
            body.Put("validFor", options.ValidFor).Put("reason", options.Reason).Put("expiresIn", options.ExpiresIn).Put("locale", options.Locale);
        }
        return Json.To<Mandate>(await RequestAsync(HttpMethod.Post, "/agents/mandates", body, ct).ConfigureAwait(false));
    }

    /// <summary>
    /// The token vault: a person's own access token at another service, for a connection
    /// that names this agent. Touchque refreshes it; the refresh token never leaves.
    /// <see cref="TouchqueApiException"/> not_connected when nothing is kept.
    /// </summary>
    public async Task<AgentConnectionToken> GetConnectionTokenAsync(string user, string connection, string? scope = null, CancellationToken ct = default)
    {
        var body = new JsonObject { ["externalUsername"] = user, ["connection"] = connection }.Put("scope", scope);
        return Json.To<AgentConnectionToken>(await RequestAsync(HttpMethod.Post, "/agents/vault/token", body, ct).ConfigureAwait(false));
    }

    /// <summary>A mandate's state and what is left.</summary>
    public async Task<Mandate> GetMandateAsync(string mandateId, CancellationToken ct = default) =>
        Json.To<Mandate>(await RequestAsync(HttpMethod.Get, "/agents/mandates/" + TouchqueHttp.Seg(mandateId), null, ct).ConfigureAwait(false));

    /// <summary>Gives up a mandate.</summary>
    public async Task<Mandate> RevokeMandateAsync(string mandateId, CancellationToken ct = default) =>
        Json.To<Mandate>(await RequestAsync(HttpMethod.Post, "/agents/mandates/" + TouchqueHttp.Seg(mandateId) + "/revoke", new JsonObject(), ct).ConfigureAwait(false));

    /// <summary>Where an approval request is; <c>ApprovalToken</c> once approved.</summary>
    public async Task<AgentApprovalState> GetApprovalAsync(string approvalId, CancellationToken ct = default) =>
        Json.To<AgentApprovalState>(await RequestAsync(HttpMethod.Get, "/agents/approvals/" + TouchqueHttp.Seg(approvalId), null, ct).ConfigureAwait(false));

    /// <summary>
    /// Asks the person's phone and waits for the answer: the approved state (holding
    /// <c>ApprovalToken</c>), or <see cref="TouchqueApprovalException"/> / a timeout.
    /// <paramref name="onChallenge"/> gets the state while the phone waits: show its
    /// <c>ChallengeCode</c> in the conversation. Put it in front of any tool call an agent
    /// framework makes, so the call runs only after the person approved.
    /// </summary>
    public async Task<AgentApprovalState> RequireApprovalAsync(string user, string type, object authorizationDetails, AgentApprovalOptions? options = null,
        Func<AgentApprovalState, Task>? onChallenge = null, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var asked = await RequestApprovalAsync(user, type, authorizationDetails, options, ct).ConfigureAwait(false);
        if (asked.Status == "approved" && !string.IsNullOrEmpty(asked.ApprovalToken)) return asked;
        if (!string.IsNullOrEmpty(asked.ChallengeCode) && onChallenge is not null) await onChallenge(asked).ConfigureAwait(false);
        return await WaitForApprovalAsync(asked.ApprovalId, timeout ?? TimeSpan.FromMinutes(5), null, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Polls until the person approves (the state holding <c>ApprovalToken</c>). Throws
    /// <see cref="TouchqueApprovalException"/> when it ends otherwise and
    /// <see cref="TouchqueTimeoutException"/> after <paramref name="timeout"/>. An approval given
    /// during a phone call stays provisional until the phone confirms it.
    /// </summary>
    public async Task<AgentApprovalState> WaitForApprovalAsync(string approvalId, TimeSpan? timeout = null, TimeSpan? interval = null, CancellationToken ct = default)
    {
        var every = interval is { } i && i > TimeSpan.FromMilliseconds(500) ? i : TimeSpan.FromSeconds(interval is null ? 2 : 0.5);
        var limit = timeout ?? TimeSpan.FromMinutes(10);
        var end = DateTimeOffset.UtcNow + limit;
        while (true)
        {
            var state = await GetApprovalAsync(approvalId, ct).ConfigureAwait(false);
            if (state.Status == "approved" && !string.IsNullOrEmpty(state.ApprovalToken)) return state;
            if (Ended.Contains(state.Status)) throw new TouchqueApprovalException(approvalId, state.Status, state.Reason);
            if (DateTimeOffset.UtcNow + every > end)
            {
                throw new TouchqueTimeoutException($"Touchque: approval '{approvalId}' was not approved within {limit.TotalSeconds:0}s", approvalId);
            }
            await Task.Delay(every, ct).ConfigureAwait(false);
        }
    }

    public void Dispose()
    {
        _key.Dispose();
        if (_ownsClient) _client.Dispose();
    }
}

public sealed record AgentApprovalOptions
{
    /// <summary>Why the agent asks (shown on the phone marked unverified).</summary>
    public string? Reason { get; init; }
    /// <summary>interactive (default: the person is in the conversation) or background.</summary>
    public string? Presence { get; init; }
    public int? ExpiresIn { get; init; }
    public string? Locale { get; init; }
    public string? ReferenceId { get; init; }
    public string? ClientIp { get; init; }
    public string? UserAgent { get; init; }
    /// <summary>An active mandate: no push.</summary>
    public string? MandateId { get; init; }
}

/// <summary>An amount in a currency, e.g. <c>new("TRY", "1000")</c>.</summary>
public sealed record MandateAmount(string Currency, string Amount);

public sealed record MandateOptions
{
    public MandateAmount? PerRequest { get; init; }
    /// <summary>IBANs (or other recipients) the mandate is limited to.</summary>
    public IReadOnlyList<string>? Recipients { get; init; }
    /// <summary>Seconds the mandate is valid for once approved.</summary>
    public int? ValidFor { get; init; }
    public string? Reason { get; init; }
    public int? ExpiresIn { get; init; }
    public string? Locale { get; init; }
}

public sealed record AgentApprovalState : TouchqueObject
{
    public string ApprovalId { get; init; } = "";
    /// <summary>pending, approved, provisional, rejected, blocked, revoked, expired, stale, redeemed.</summary>
    public string Status { get; init; } = "";
    public string? Presence { get; init; }
    /// <summary>The number to show in the conversation; the person types it on the phone.</summary>
    public string? ChallengeCode { get; init; }
    /// <summary>Over the policy's RequirePasskeyAbove: the person approves with a passkey on your page (<c>&lt;touchque-approval request-id="..."&gt;</c>), not on the phone.</summary>
    public bool? RequiresPasskey { get; init; }
    public string? ExpiresAt { get; init; }
    public string? CaseCode { get; init; }
    public string? Reason { get; init; }
    /// <summary>Once approved: hand it to the partner's server, which redeems it once.</summary>
    public string? ApprovalToken { get; init; }
    public int? TokenExpiresIn { get; init; }
    /// <summary>Four eyes: who approves second, and their number.</summary>
    public string? SecondApprover { get; init; }
    public string? SecondChallengeCode { get; init; }
    public string? MandateId { get; init; }
    public Mandate? Mandate { get; init; }
}

public sealed record AgentSelfInfo : TouchqueObject
{
    public string Id { get; init; } = "";
    public string? Name { get; init; }
    public string? Platform { get; init; }
    public IReadOnlyList<string>? AllowedTypes { get; init; }
    public string? ReviewAt { get; init; }
    public AgentOwner? Owner { get; init; }
}

public sealed record AgentWorkspace : TouchqueObject
{
    public string? CompanyName { get; init; }
}

public sealed record AgentSelf : TouchqueObject
{
    public AgentSelfInfo Agent { get; init; } = new();
    public AgentWorkspace? Workspace { get; init; }
    public string? Scope { get; init; }
}

/// <summary>A person's access token at another service (token vault).</summary>
public sealed record AgentConnectionToken : TouchqueObject
{
    [System.Text.Json.Serialization.JsonPropertyName("access_token")]
    public string AccessToken { get; init; } = "";
    [System.Text.Json.Serialization.JsonPropertyName("token_type")]
    public string TokenType { get; init; } = "Bearer";
    [System.Text.Json.Serialization.JsonPropertyName("expires_in")]
    public int? ExpiresIn { get; init; }
    public string? Scope { get; init; }
    public string? Connection { get; init; }
}
