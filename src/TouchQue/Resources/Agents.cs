using System.Text.Json.Nodes;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>
/// AI agents as identities of their own: register an agent with its PUBLIC key,
/// give it an accountable owner and the action types it may ask approvals for,
/// suspend, revoke or stop every agent at once. The agent itself never gets your
/// API key: it signs in with its own key (<see cref="TouchQueAgent"/>).
/// <code>
/// var keys = AgentKeys.Generate();                       // where the agent runs
/// var agent = await tq.Agents.CreateAsync(new CreateAgentOptions { Name = "Invoice bot", AllowedTypes = ["PAY_INVOICE"], PublicKey = keys.PublicJwk });
/// </code>
/// </summary>
public sealed class AgentsResource
{
    private readonly TouchQueHttp _http;
    private readonly SemaphoreSlim _jwksLock = new(1, 1);
    private JsonObject? _jwks;
    private DateTimeOffset _jwksAt;
    private volatile string? _audience;

    internal AgentsResource(TouchQueHttp http)
    {
        _http = http;
        Vault = new AgentVaultResource(http);
    }

    /// <summary>The token vault: people's tokens at other services, for your agents.</summary>
    public AgentVaultResource Vault { get; }

    /// <summary>
    /// Uses an agent's approval exactly once, right before you execute: checks
    /// <paramref name="expect"/> against the token first (nothing is used on a
    /// mismatch), then TouchQue checks the token and marks it used, and the answer is checked again.
    /// </summary>
    public async Task<RedeemedApproval> RedeemApprovalAsync(string token, ApprovalExpectation? expect = null, CancellationToken ct = default)
    {
        ApprovalToken.AssertMatches(ApprovalToken.Decode(token).Claims, expect);
        var res = await _http.PostAsync("/agents/approvals/redeem", new JsonObject { ["token"] = token }, ct).ConfigureAwait(false);
        var approval = res?["approval"] as JsonObject ?? new JsonObject();
        ApprovalToken.AssertMatches(new JsonObject
        {
            ["sub"] = Json.Str(approval, "externalUsername"),
            ["type"] = Json.Str(approval, "type"),
            ["authorization_details"] = approval["authorizationDetails"]?.DeepClone(),
        }, expect);
        return Json.To<RedeemedApproval>(approval);
    }

    /// <summary>
    /// The <c>aud</c> of this workspace's approval tokens (<c>touchque:workspace:&lt;id&gt;</c>),
    /// from GET /agents/approval-audience; asked once, then kept.
    /// </summary>
    public async Task<string> ApprovalAudienceAsync(CancellationToken ct = default)
    {
        if (_audience is { Length: > 0 } known) return known;
        var body = await _http.GetAsync("/agents/approval-audience", null, ct).ConfigureAwait(false) as JsonObject;
        var audience = body is null ? null : Json.Str(body, "audience");
        if (string.IsNullOrEmpty(audience)) throw new TouchQueApprovalMismatchException("Touchque did not name this workspace's approval audience");
        _audience = audience;
        return audience;
    }

    /// <summary>
    /// Verifies an approval token offline (Touchque's published keys, expiry, <c>aud</c>,
    /// <paramref name="expect"/>). <c>aud</c> must be this workspace's: <paramref name="audience"/>
    /// defaults to <see cref="ApprovalAudienceAsync"/>, and a token without aud or for another
    /// workspace is refused. It does not make the token single-use: <see cref="RedeemApprovalAsync"/> does.
    /// </summary>
    public async Task<JsonObject> VerifyApprovalTokenAsync(string token, string? audience = null, ApprovalExpectation? expect = null, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(audience)) audience = await ApprovalAudienceAsync(ct).ConfigureAwait(false);
        var jwks = await JwksAsync(false, ct).ConfigureAwait(false);
        try
        {
            return ApprovalToken.VerifyWith(token, jwks, audience, expect);
        }
        catch (TouchQueApprovalMismatchException e) when (e.Message.Contains("unknown key", StringComparison.Ordinal))
        {
            jwks = await JwksAsync(true, ct).ConfigureAwait(false);
            return ApprovalToken.VerifyWith(token, jwks, audience, expect);
        }
    }

    private async Task<JsonObject> JwksAsync(bool force, CancellationToken ct)
    {
        await _jwksLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (force || _jwks is null || DateTimeOffset.UtcNow - _jwksAt > TimeSpan.FromMinutes(5))
            {
                _jwks = await _http.GetAsync("/agents/jwks.json", null, ct).ConfigureAwait(false) as JsonObject ?? new JsonObject();
                _jwksAt = DateTimeOffset.UtcNow;
            }
            return _jwks;
        }
        finally
        {
            _jwksLock.Release();
        }
    }

    /// <summary>Refuses a private key before it leaves this process.</summary>
    private static JsonNode PublicOnly(JsonObject jwk)
    {
        if (jwk.ContainsKey("d"))
        {
            throw new TouchQueConfigException("Pass the agent's PUBLIC key: this one has private parts (d). The private key must stay where the agent runs.");
        }
        return jwk.DeepClone();
    }

    /// <summary>Registers an agent (needs the agents:write scope).</summary>
    public async Task<AgentInfo> CreateAsync(CreateAgentOptions options, CancellationToken ct = default)
    {
        var body = new JsonObject
        {
            ["name"] = options.Name,
            ["allowedTypes"] = new JsonArray(options.AllowedTypes.Select(t => (JsonNode)t).ToArray()),
        };
        body.Put("description", options.Description).Put("ownerEmail", options.OwnerEmail).Put("platform", options.Platform).Put("reviewInDays", options.ReviewInDays);
        if (options.PublicKey is not null) body["publicKey"] = PublicOnly(options.PublicKey);
        if (options.PublicKeys is not null) body["publicKeys"] = new JsonArray(options.PublicKeys.Select(PublicOnly).ToArray());
        return Agent(await _http.PostAsync("/agents", body, ct).ConfigureAwait(false));
    }

    /// <summary>The agents (optionally by status) and the kill switch.</summary>
    public async Task<AgentList> ListAsync(string? status = null, CancellationToken ct = default) =>
        Json.To<AgentList>(await _http.GetAsync("/agents", new Dictionary<string, string?> { ["status"] = string.IsNullOrEmpty(status) ? null : status }, ct).ConfigureAwait(false));

    public async Task<AgentInfo> GetAsync(string agentId, CancellationToken ct = default) =>
        Agent(await _http.GetAsync(Path(agentId), null, ct).ConfigureAwait(false));

    /// <summary>Changes, hands over (OwnerEmail) or renews (ReviewInDays) an agent.</summary>
    public async Task<AgentInfo> UpdateAsync(string agentId, UpdateAgentOptions changes, CancellationToken ct = default)
    {
        var body = new JsonObject();
        body.Put("name", changes.Name);
        if (changes.Description is not null) body["description"] = changes.Description;
        body.Put("ownerEmail", changes.OwnerEmail).Put("platform", changes.Platform).Put("reviewInDays", changes.ReviewInDays);
        if (changes.AllowedTypes is not null) body["allowedTypes"] = new JsonArray(changes.AllowedTypes.Select(t => (JsonNode)t).ToArray());
        return Agent(await _http.PatchAsync(Path(agentId), body, ct).ConfigureAwait(false));
    }

    /// <summary>Adds a key (rotation: add the new one, move the agent to it, then remove the old one).</summary>
    public async Task<AgentInfo> AddKeyAsync(string agentId, JsonObject publicKey, CancellationToken ct = default) =>
        Agent(await _http.PostAsync(Path(agentId) + "/keys", new JsonObject { ["publicKey"] = PublicOnly(publicKey) }, ct).ConfigureAwait(false));

    /// <summary>Removes a key; tokens the agent got with it stop at once.</summary>
    public async Task<AgentInfo> RemoveKeyAsync(string agentId, string kid, CancellationToken ct = default) =>
        Agent(await _http.DeleteAsync(Path(agentId) + "/keys/" + TouchQueHttp.Seg(kid), ct).ConfigureAwait(false));

    /// <summary>Stops an agent at once (its tokens too) until resumed.</summary>
    public async Task<AgentInfo> SuspendAsync(string agentId, string? reason = null, CancellationToken ct = default) =>
        Agent(await _http.PostAsync(Path(agentId) + "/suspend", new JsonObject().Put("reason", reason), ct).ConfigureAwait(false));

    public async Task<AgentInfo> ResumeAsync(string agentId, CancellationToken ct = default) =>
        Agent(await _http.PostAsync(Path(agentId) + "/resume", new JsonObject(), ct).ConfigureAwait(false));

    /// <summary>Revokes an agent for good (the record stays for the audit trail).</summary>
    public async Task<AgentInfo> RevokeAsync(string agentId, CancellationToken ct = default) =>
        Agent(await _http.DeleteAsync(Path(agentId), ct).ConfigureAwait(false));

    /// <summary>
    /// Sets the agent's budgets, amounts, recipients and background rule (a full
    /// replacement; left-out fields take the defaults).
    /// </summary>
    public async Task<AgentInfo> SetPolicyAsync(string agentId, AgentPolicy policy, CancellationToken ct = default) =>
        Agent(await _http.PutAsync(Path(agentId) + "/policy", new JsonObject { ["policy"] = Json.ToNode(policy) }, ct).ConfigureAwait(false));

    /// <summary>
    /// The workspace's agent events for a SIEM, oldest first. Keep <c>Next</c> and pass it
    /// as <paramref name="after"/>; the first call reads from <paramref name="since"/>
    /// (ISO 8601; default the last 24 hours).
    /// </summary>
    public async Task<AgentEventPage> ListEventsAsync(string? after = null, string? since = null, int? limit = null, CancellationToken ct = default) =>
        Json.To<AgentEventPage>(await _http.GetAsync("/agents/events", new Dictionary<string, string?>
        {
            ["after"] = after,
            ["since"] = since,
            ["limit"] = limit?.ToString(System.Globalization.CultureInfo.InvariantCulture),
        }, ct).ConfigureAwait(false)) ?? new AgentEventPage();

    /// <summary>The workspace's policy: every agent's floor (an agent's own policy can only make it stricter).</summary>
    public async Task<AgentPolicy> GetWorkspacePolicyAsync(CancellationToken ct = default) =>
        Json.To<AgentPolicy>((await _http.GetAsync("/agents/workspace-policy", null, ct).ConfigureAwait(false))?["policy"]) ?? new AgentPolicy();

    /// <summary>Sets the workspace's policy (a full replacement; a field left out sets no floor).</summary>
    public async Task<AgentPolicy> SetWorkspacePolicyAsync(AgentPolicy policy, CancellationToken ct = default) =>
        Json.To<AgentPolicy>((await _http.PutAsync("/agents/workspace-policy", new JsonObject { ["policy"] = Json.ToNode(policy) }, ct).ConfigureAwait(false))?["policy"]) ?? new AgentPolicy();

    /// <summary>The people who stopped this agent asking them (reason not_me, coached or rejections).</summary>
    public async Task<IReadOnlyList<AgentBlock>> ListBlocksAsync(string agentId, CancellationToken ct = default) =>
        Json.To<List<AgentBlock>>((await _http.GetAsync(Path(agentId) + "/blocks", null, ct).ConfigureAwait(false))?["blocks"]) ?? new List<AgentBlock>();

    /// <summary>Lets the agent ask this person again (check with them first).</summary>
    public async Task LiftBlockAsync(string agentId, string user, CancellationToken ct = default) =>
        await _http.DeleteAsync(Path(agentId) + "/blocks/" + TouchQueHttp.Seg(user), ct).ConfigureAwait(false);

    /// <summary>An agent's mandates, optionally one person's.</summary>
    public async Task<IReadOnlyList<Mandate>> ListMandatesAsync(string agentId, string? user = null, CancellationToken ct = default) =>
        Json.To<List<Mandate>>((await _http.GetAsync(Path(agentId) + "/mandates", new Dictionary<string, string?> { ["externalUsername"] = string.IsNullOrEmpty(user) ? null : user }, ct).ConfigureAwait(false))?["mandates"]) ?? new List<Mandate>();

    /// <summary>Ends an agent's mandate at once.</summary>
    public async Task<Mandate> RevokeMandateAsync(string agentId, string mandateId, CancellationToken ct = default)
    {
        var res = await _http.PostAsync(Path(agentId) + "/mandates/" + TouchQueHttp.Seg(mandateId) + "/revoke", new JsonObject(), ct).ConfigureAwait(false);
        return Json.To<Mandate>(res?["mandate"] ?? res);
    }

    /// <summary>Stops (true) or restarts (false) every agent of the workspace at once.</summary>
    public async Task<AgentKillSwitch> SetKillSwitchAsync(bool engaged, string? reason = null, CancellationToken ct = default)
    {
        var body = new JsonObject { ["engaged"] = engaged }.Put("reason", reason);
        return Json.To<AgentKillSwitch>((await _http.PutAsync("/agents/kill-switch", body, ct).ConfigureAwait(false))?["killSwitch"]);
    }

    private static string Path(string agentId) => "/agents/" + TouchQueHttp.Seg(agentId);

    private static AgentInfo Agent(JsonNode? res) => Json.To<AgentInfo>(res?["agent"]);
}

/// <summary>
/// The token vault for your agents (<c>tq.Agents.Vault</c>): after your own OAuth
/// flow with a person, deposit their tokens; TouchQue keeps them sealed and
/// refreshes them, and the agents a connection names get a short-lived access
/// token (<see cref="TouchQueAgent.GetConnectionTokenAsync"/>), never the refresh token.
/// </summary>
public sealed class AgentVaultResource
{
    private readonly TouchQueHttp _http;

    internal AgentVaultResource(TouchQueHttp http) => _http = http;

    public async Task<IReadOnlyList<AgentVaultConnection>> ListConnectionsAsync(CancellationToken ct = default) =>
        Json.To<List<AgentVaultConnection>>((await _http.GetAsync("/agents/vault/connections", null, ct).ConfigureAwait(false))?["connections"]) ?? new List<AgentVaultConnection>();

    /// <summary>Adds or replaces a connection; the client secret is kept when left out of a replacement.</summary>
    public async Task<AgentVaultConnection> PutConnectionAsync(string name, AgentVaultConnectionOptions connection, CancellationToken ct = default)
    {
        var body = new JsonObject { ["provider"] = connection.Provider, ["clientId"] = connection.ClientId };
        body.Put("clientSecret", connection.ClientSecret).Put("tenant", connection.Tenant).Put("issuer", connection.Issuer);
        if (connection.AgentIds is not null) body["agentIds"] = new JsonArray(connection.AgentIds.Select(a => (JsonNode)a).ToArray());
        return Json.To<AgentVaultConnection>((await _http.PutAsync("/agents/vault/connections/" + TouchQueHttp.Seg(name), body, ct).ConfigureAwait(false))?["connection"]);
    }

    /// <summary>Removes it, and every person's tokens kept for it.</summary>
    public Task<JsonObject> RemoveConnectionAsync(string name, CancellationToken ct = default) =>
        _http.DeleteAsync<JsonObject>("/agents/vault/connections/" + TouchQueHttp.Seg(name), ct);

    /// <summary>Keeps a person's tokens (replacing earlier ones) after your own OAuth flow with them.</summary>
    public async Task<AgentVaultAccount> DepositAsync(string connection, string user, AgentVaultDeposit tokens, CancellationToken ct = default)
    {
        var body = new JsonObject { ["accessToken"] = tokens.AccessToken };
        body.Put("refreshToken", tokens.RefreshToken).Put("expiresIn", tokens.ExpiresIn).Put("scope", tokens.Scope);
        return Json.To<AgentVaultAccount>((await _http.PutAsync("/agents/vault/accounts/" + TouchQueHttp.Seg(connection) + "/" + TouchQueHttp.Seg(user), body, ct).ConfigureAwait(false))?["account"]);
    }

    /// <summary>A person's accounts in the vault (never a token).</summary>
    public async Task<IReadOnlyList<AgentVaultAccount>> ListAccountsAsync(string user, CancellationToken ct = default) =>
        Json.To<List<AgentVaultAccount>>((await _http.GetAsync("/agents/vault/accounts", new Dictionary<string, string?> { ["externalUsername"] = user }, ct).ConfigureAwait(false))?["accounts"]) ?? new List<AgentVaultAccount>();

    /// <summary>Deletes a person's tokens: agents get nothing more for them there.</summary>
    public async Task RemoveAccountAsync(string connection, string user, CancellationToken ct = default) =>
        await _http.DeleteAsync("/agents/vault/accounts/" + TouchQueHttp.Seg(connection) + "/" + TouchQueHttp.Seg(user), ct).ConfigureAwait(false);
}

public sealed record CreateAgentOptions
{
    public required string Name { get; init; }
    public required IReadOnlyList<string> AllowedTypes { get; init; }
    public JsonObject? PublicKey { get; init; }
    public IReadOnlyList<JsonObject>? PublicKeys { get; init; }
    public string? Description { get; init; }
    /// <summary>The accountable member (default: the API key's creator); the agent stops when they leave.</summary>
    public string? OwnerEmail { get; init; }
    /// <summary>e.g. openai-agents, claude-agent-sdk, langgraph.</summary>
    public string? Platform { get; init; }
    /// <summary>1-365 (default 90).</summary>
    public int? ReviewInDays { get; init; }
}

public sealed record UpdateAgentOptions
{
    public string? Name { get; init; }
    public string? Description { get; init; }
    public string? OwnerEmail { get; init; }
    public string? Platform { get; init; }
    public IReadOnlyList<string>? AllowedTypes { get; init; }
    public int? ReviewInDays { get; init; }
}

/// <summary>An agent's budgets and limits. Amounts are decimal strings by currency, e.g. <c>{"TRY": "1000.00"}</c>.</summary>
public sealed record AgentPolicy
{
    public int? RequestsPer10Min { get; init; }
    public int? RequestsPerUserPer10Min { get; init; }
    public IReadOnlyDictionary<string, string>? AmountPerRequest { get; init; }
    public IReadOnlyDictionary<string, string>? AmountPerDay { get; init; }
    /// <summary>non_critical or never.</summary>
    public string? Background { get; init; }
    /// <summary>ask or deny.</summary>
    public string? NewRecipients { get; init; }
    public IReadOnlyList<string>? RecipientAllowlist { get; init; }
    public FourEyes? FourEyes { get; init; }
    /// <summary>{ TRY: "10000.00" }: over it the person approves with a passkey on your page, never on the phone or with a mandate.</summary>
    public IReadOnlyDictionary<string, string>? RequirePasskeyAbove { get; init; }
}

/// <summary>A second approver for large or listed requests.</summary>
public sealed record FourEyes
{
    public IReadOnlyList<string> Approvers { get; init; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, string>? Above { get; init; }
    public IReadOnlyList<string>? Types { get; init; }
}

public sealed record AgentOwner : TouchQueObject
{
    public string? Email { get; init; }
    public string? UserId { get; init; }
}

public sealed record AgentKeyInfo : TouchQueObject
{
    public string Kid { get; init; } = "";
    public string? Kty { get; init; }
    public string? Crv { get; init; }
    public string? Alg { get; init; }
    public string? AddedAt { get; init; }
}

public sealed record AgentInfo : TouchQueObject
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Description { get; init; }
    public string? Platform { get; init; }
    public AgentOwner? Owner { get; init; }
    /// <summary>active, suspended or revoked.</summary>
    public string Status { get; init; } = "";
    public string? StatusReason { get; init; }
    public string? Blocked { get; init; }
    public IReadOnlyList<string> AllowedTypes { get; init; } = Array.Empty<string>();
    public JsonObject? Policy { get; init; }
    public IReadOnlyList<AgentKeyInfo> Keys { get; init; } = Array.Empty<AgentKeyInfo>();
    public string? ReviewAt { get; init; }
    public string? LastUsedAt { get; init; }
    public string? CreatedBy { get; init; }
    public string? CreatedAt { get; init; }
    public string? UpdatedAt { get; init; }
}

public sealed record AgentKillSwitch : TouchQueObject
{
    public bool Engaged { get; init; }
    public string? Since { get; init; }
    public string? By { get; init; }
    public string? Reason { get; init; }
}

public sealed record AgentList : TouchQueObject
{
    public IReadOnlyList<AgentInfo> Agents { get; init; } = Array.Empty<AgentInfo>();
    public AgentKillSwitch? KillSwitch { get; init; }
}

/// <summary>A page of the workspace's agent events, oldest first; ask again with <c>Next</c> as <c>after</c>.</summary>
public sealed record AgentEventPage : TouchQueObject
{
    public IReadOnlyList<AgentEvent> Events { get; init; } = Array.Empty<AgentEvent>();
    public string Next { get; init; } = "";
    public bool HasMore { get; init; }
}

/// <summary>One of the workspace's agent events (AGENT_*, AGENTS_*).</summary>
public sealed record AgentEvent : TouchQueObject
{
    public string Id { get; init; } = "";
    public string Type { get; init; } = "";
    public string? OccurredAt { get; init; }
    public AgentEventAgent? Agent { get; init; }
    public string? ExternalUsername { get; init; }
    public string? ApprovalId { get; init; }
    public string? CaseCode { get; init; }
    public string? Ip { get; init; }
    public string? Note { get; init; }
    public System.Text.Json.Nodes.JsonObject? Data { get; init; }
}

/// <summary>The agent of an event.</summary>
public sealed record AgentEventAgent : TouchQueObject
{
    public string Id { get; init; } = "";
    public string? Name { get; init; }
}

public sealed record AgentBlock : TouchQueObject
{
    public string ExternalUsername { get; init; } = "";
    public string? Reason { get; init; }
    public string? ApprovalId { get; init; }
    public string? CreatedAt { get; init; }
}

public sealed record Mandate : TouchQueObject
{
    public string MandateId { get; init; } = "";
    /// <summary>pending, active, used_up, expired, revoked, rejected.</summary>
    public string Status { get; init; } = "";
    public string? ExternalUsername { get; init; }
    public string? Type { get; init; }
    public int MaxCount { get; init; }
    public int UsedCount { get; init; }
    public Dictionary<string, string>? MaxTotal { get; init; }
    public Dictionary<string, string>? Used { get; init; }
    public Dictionary<string, string>? PerRequest { get; init; }
    public IReadOnlyList<string>? Recipients { get; init; }
    public string? ValidUntil { get; init; }
    public string? ChallengeCode { get; init; }
    public string? RevokedAt { get; init; }
}

public sealed record RedeemedApprovalAgent : TouchQueObject
{
    public string Id { get; init; } = "";
    public string? Name { get; init; }
}

/// <summary>An agent's approval, used once.</summary>
public sealed record RedeemedApproval : TouchQueObject
{
    public string Id { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    public string Type { get; init; } = "";
    public RedeemedApprovalAgent? Agent { get; init; }
    public JsonArray? AuthorizationDetails { get; init; }
    public IReadOnlyList<LoginDetail>? Details { get; init; }
    public string? Presence { get; init; }
    public bool NumberMatched { get; init; }
    public string? DecidedAt { get; init; }
    public JsonObject? ApprovalProof { get; init; }
    public string? CaseCode { get; init; }
}

public sealed record AgentVaultConnectionOptions
{
    /// <summary>google, microsoft, github, facebook, linkedin, x or oidc.</summary>
    public required string Provider { get; init; }
    public required string ClientId { get; init; }
    public string? ClientSecret { get; init; }
    public string? Tenant { get; init; }
    public string? Issuer { get; init; }
    /// <summary>The agents that may get tokens of this connection.</summary>
    public IReadOnlyList<string>? AgentIds { get; init; }
}

public sealed record AgentVaultConnection : TouchQueObject
{
    public string Name { get; init; } = "";
    public string Provider { get; init; } = "";
    public string? ClientId { get; init; }
    public bool HasClientSecret { get; init; }
    public Dictionary<string, string>? Options { get; init; }
    public IReadOnlyList<string>? AgentIds { get; init; }
    public int Connected { get; init; }
    public string? CreatedAt { get; init; }
    public string? UpdatedAt { get; init; }
}

public sealed record AgentVaultDeposit
{
    public required string AccessToken { get; init; }
    public string? RefreshToken { get; init; }
    public int? ExpiresIn { get; init; }
    public string? Scope { get; init; }
}

public sealed record AgentVaultAccount : TouchQueObject
{
    public string Connection { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    public IReadOnlyList<string>? Scopes { get; init; }
    public bool CanRefresh { get; init; }
    public string? LastUsedAt { get; init; }
    public string? LastAgentId { get; init; }
    public string? CreatedAt { get; init; }
    public string? UpdatedAt { get; init; }
}
