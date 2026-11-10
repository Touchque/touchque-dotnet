using System.Globalization;
using System.Text.Json.Nodes;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>
/// TouchQue Login Management API: your customers' accounts, roles,
/// business-customer organizations, apps, APIs, connections and the tenant
/// itself, from your server with your workspace key. Bodies are any object
/// (anonymous, dictionary, JsonObject) with the API's camelCase fields; answers
/// are the API's JSON.
/// <code>
/// var found = await tq.Identity.Users.ListAsync(new { q = "ayse" });
/// await tq.Identity.Users.BlockAsync(userId, "chargeback");
/// var job = await tq.Identity.Imports.StartAsync(new { users = new[] { new { email, passwordHash = "$2b$10$…" } } });
/// </code>
/// </summary>
public sealed class IdentityResource
{
    private readonly TouchQueHttp _http;

    internal IdentityResource(TouchQueHttp http)
    {
        _http = http;
        Users = new IdentityUsers(http);
        Imports = new IdentityJobs(http, "imports");
        Exports = new IdentityJobs(http, "exports");
        Roles = new IdentityCrud(http, "/identity/roles", "roles");
        Organizations = new IdentityOrganizations(http);
        Clients = new IdentityClients(http);
        Apis = new IdentityCrud(http, "/identity/apis", "apis");
        Connections = new IdentityCrud(http, "/identity/connections", "connections");
        CustomDomains = new IdentityCrud(http, "/identity/custom-domains", "domains");
    }

    public IdentityUsers Users { get; }
    public IdentityJobs Imports { get; }
    public IdentityJobs Exports { get; }
    public IdentityCrud Roles { get; }
    public IdentityOrganizations Organizations { get; }
    public IdentityClients Clients { get; }
    public IdentityCrud Apis { get; }
    public IdentityCrud Connections { get; }
    public IdentityCrud CustomDomains { get; }

    /// <summary>The tenant (404 not_enabled until it is set up).</summary>
    public Task<JsonObject> GetTenantAsync(CancellationToken ct = default) => _http.GetAsync<JsonObject>("/identity/tenant", null, ct);

    /// <summary>Turns TouchQue Login on (slug, displayName) or changes its settings.</summary>
    public Task<JsonObject> UpdateTenantAsync(object body, CancellationToken ct = default) => _http.PutAsync<JsonObject>("/identity/tenant", Json.ToNode(body), ct);

    /// <summary>Retires the tenant's signing key and makes a new one active.</summary>
    public Task<JsonObject> RotateSigningKeyAsync(CancellationToken ct = default) => _http.PostAsync<JsonObject>("/identity/tenant/signing-keys/rotate", new JsonObject(), ct);

    /// <summary>
    /// The phone app the hosted pages tell customers to approve on ("Approve on the Acme app").
    /// null: your brand name when the Mobile SDK is set up, else TouchQue (<c>approverApp</c> in the tenant shows which).
    /// </summary>
    public Task<JsonObject> SetApproverAppNameAsync(string? name, CancellationToken ct = default) =>
        _http.PutAsync<JsonObject>("/identity/tenant", new JsonObject { ["branding"] = new JsonObject { ["approverAppName"] = name } }, ct);

    /// <summary>
    /// Serve sign-in only on the primary custom domain: {slug}.login.touchque.com redirects page loads there and
    /// refuses other calls. Turning it on needs a verified primary domain with a working certificate.
    /// </summary>
    public Task<JsonObject> SetCustomDomainOnlyAsync(bool on, CancellationToken ct = default) =>
        _http.PutAsync<JsonObject>("/identity/tenant", new JsonObject { ["customDomainOnly"] = on }, ct);

    /// <summary>Checks a verified custom domain's certificate at the sign-in edge now (<c>certificate</c>: pending | active | error).</summary>
    public Task<JsonObject> CheckDomainCertificateAsync(string domainId, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>("/identity/custom-domains/" + TouchQueHttp.Seg(domainId) + "/check-certificate", new JsonObject(), ct);

    /// <summary>The delivery log. Message text only in the local dev inbox.</summary>
    public Task<JsonObject> OutboxAsync(object? query = null, CancellationToken ct = default) => _http.GetAsync<JsonObject>("/identity/outbox", IdentityQuery.Of(query), ct);

    /// <summary>Wrong passwords, suspicious addresses, bot challenge, breached passwords, new-browser notices, the risk engine.</summary>
    public Task<JsonObject> GetAttackProtectionAsync(CancellationToken ct = default) => _http.GetAsync<JsonObject>("/identity/attack-protection", null, ct);

    /// <summary>Partial; the bot challenge's secret is write-only.</summary>
    public Task<JsonObject> SetAttackProtectionAsync(object settings, CancellationToken ct = default) => _http.PutAsync<JsonObject>("/identity/attack-protection", Json.ToNode(settings), ct);

    /// <summary>What attack protection caught lately.</summary>
    public Task<JsonObject> AttackEventsAsync(object? query = null, CancellationToken ct = default) => _http.GetAsync<JsonObject>("/identity/attack-protection/events", IdentityQuery.Of(query), ct);

    /// <summary>The email and SMS providers; secrets never come back (secretsSet).</summary>
    public Task<JsonObject> GetDeliveryAsync(CancellationToken ct = default) => _http.GetAsync<JsonObject>("/identity/delivery", null, ct);

    /// <summary>
    /// Your own provider: email smtp, ses, postmark, sendgrid; sms twilio, netgsm, e.g.
    /// <c>new { provider = "postmark", from = "login@acme.com", serverToken }</c>. A secret left out keeps its stored value.
    /// </summary>
    public Task<JsonObject> SetDeliveryAsync(string channel, object provider, CancellationToken ct = default) =>
        _http.PutAsync<JsonObject>("/identity/delivery/" + TouchQueHttp.Seg(channel), Json.ToNode(provider), ct);

    /// <summary>Back to TouchQue's transport.</summary>
    public Task<JsonObject> RemoveDeliveryAsync(string channel, CancellationToken ct = default) =>
        _http.DeleteAsync<JsonObject>("/identity/delivery/" + TouchQueHttp.Seg(channel), ct);

    /// <summary>One test message through the provider in use.</summary>
    public Task<JsonObject> TestDeliveryAsync(string channel, string to, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>("/identity/delivery/" + TouchQueHttp.Seg(channel) + "/test", new JsonObject { ["to"] = to }, ct);
}

internal static class IdentityQuery
{
    /// <summary>A query from any object: its fields as strings (booleans lower-case), nulls left out.</summary>
    public static Dictionary<string, string?>? Of(object? query)
    {
        if (query is null) return null;
        var node = Json.ToNode(query) as JsonObject;
        if (node is null) return null;
        var d = new Dictionary<string, string?>();
        foreach (var (k, v) in node)
        {
            d[k] = v switch
            {
                null => null,
                JsonValue jv when jv.TryGetValue<string>(out var s) => s,
                JsonValue jv when jv.TryGetValue<bool>(out var b) => b ? "true" : "false",
                _ => v.ToJsonString(),
            };
        }
        return d;
    }
}

/// <summary>List, get, create, update and delete for one kind of TouchQue Login object.</summary>
public class IdentityCrud
{
    private protected readonly TouchQueHttp Http;
    private protected readonly string Base;
    private readonly string _listKey;

    internal IdentityCrud(TouchQueHttp http, string basePath, string listKey)
    {
        Http = http;
        Base = basePath;
        _listKey = listKey;
    }

    public async Task<JsonArray> ListAsync(object? query = null, CancellationToken ct = default)
    {
        var res = await Http.GetAsync(Base, IdentityQuery.Of(query), ct).ConfigureAwait(false);
        return res?[_listKey]?.DeepClone() as JsonArray ?? new JsonArray();
    }

    public Task<JsonObject> GetAsync(string id, CancellationToken ct = default) => Http.GetAsync<JsonObject>(Base + "/" + TouchQueHttp.Seg(id), null, ct);

    public Task<JsonObject> CreateAsync(object body, CancellationToken ct = default) => Http.PostAsync<JsonObject>(Base, Json.ToNode(body), ct);

    public Task<JsonObject> UpdateAsync(string id, object body, CancellationToken ct = default) => Http.PatchAsync<JsonObject>(Base + "/" + TouchQueHttp.Seg(id), Json.ToNode(body), ct);

    public Task<JsonObject> DeleteAsync(string id, CancellationToken ct = default) => Http.DeleteAsync<JsonObject>(Base + "/" + TouchQueHttp.Seg(id), ct);
}

/// <summary>Business customers, their members and invitations.</summary>
public sealed class IdentityOrganizations : IdentityCrud
{
    internal IdentityOrganizations(TouchQueHttp http) : base(http, "/identity/organizations", "organizations") { }

    public Task<JsonObject> MembersAsync(string orgId, CancellationToken ct = default) => Http.GetAsync<JsonObject>(Org(orgId) + "/members", null, ct);

    public Task<JsonObject> AddMembersAsync(string orgId, IEnumerable<string> userIds, CancellationToken ct = default) =>
        Http.PostAsync<JsonObject>(Org(orgId) + "/members", new JsonObject { ["userIds"] = new JsonArray(userIds.Select(u => (JsonNode)u).ToArray()) }, ct);

    public Task<JsonObject> RemoveMemberAsync(string orgId, string userId, CancellationToken ct = default) =>
        Http.DeleteAsync<JsonObject>(Org(orgId) + "/members/" + TouchQueHttp.Seg(userId), ct);

    public Task<JsonObject> SetConnectionsAsync(string orgId, object connections, CancellationToken ct = default) =>
        Http.PutAsync<JsonObject>(Org(orgId) + "/connections", new JsonObject { ["connections"] = Json.ToNode(connections) }, ct);

    public Task<JsonObject> InvitationsAsync(string orgId, CancellationToken ct = default) => Http.GetAsync<JsonObject>(Org(orgId) + "/invitations", null, ct);

    /// <summary>The link opens the app's sign-in route (initiateLoginUri) with organization and invitation.</summary>
    public Task<JsonObject> InviteAsync(string orgId, object invitation, CancellationToken ct = default) =>
        Http.PostAsync<JsonObject>(Org(orgId) + "/invitations", Json.ToNode(invitation), ct);

    public Task<JsonObject> RevokeInvitationAsync(string orgId, string invitationId, CancellationToken ct = default) =>
        Http.DeleteAsync<JsonObject>(Org(orgId) + "/invitations/" + TouchQueHttp.Seg(invitationId), ct);

    private string Org(string orgId) => Base + "/" + TouchQueHttp.Seg(orgId);
}

/// <summary>Your customers' apps (OpenID Connect clients).</summary>
public sealed class IdentityClients : IdentityCrud
{
    internal IdentityClients(TouchQueHttp http) : base(http, "/identity/clients", "clients") { }

    /// <summary>A new client secret: it is in the answer, this once.</summary>
    public Task<JsonObject> RotateSecretAsync(string clientId, CancellationToken ct = default) =>
        Http.PostAsync<JsonObject>(Base + "/" + TouchQueHttp.Seg(clientId) + "/rotate-secret", new JsonObject(), ct);
}

/// <summary>Bulk user imports and exports, running in the background.</summary>
public sealed class IdentityJobs
{
    private readonly TouchQueHttp _http;
    private readonly string _kind;

    internal IdentityJobs(TouchQueHttp http, string kind)
    {
        _http = http;
        _kind = kind;
    }

    /// <summary>Imports: <c>{ users, upsert }</c>; exports: <c>{ format = "csv" | "json" }</c>.</summary>
    public Task<JsonObject> StartAsync(object body, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>("/identity/users-" + _kind, Json.ToNode(body), ct);

    public Task<JsonObject> GetAsync(string jobId, CancellationToken ct = default) =>
        _http.GetAsync<JsonObject>("/identity/users-" + _kind + "/" + TouchQueHttp.Seg(jobId), null, ct);

    /// <summary>Exports: the finished file (CSV or JSON text).</summary>
    public Task<string> FileAsync(string jobId, CancellationToken ct = default) =>
        _http.GetTextAsync("/identity/users-" + _kind + "/" + TouchQueHttp.Seg(jobId) + "/file", ct);

    /// <summary>Polls until the job is done or failed (or the timeout passes: the last state).</summary>
    public async Task<JsonObject> WaitAsync(string jobId, TimeSpan? interval = null, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var end = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromMinutes(10));
        while (true)
        {
            var job = await GetAsync(jobId, ct).ConfigureAwait(false);
            if (Json.Str(job, "status") != "running" || DateTimeOffset.UtcNow > end) return job;
            await Task.Delay(interval ?? TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
        }
    }
}

/// <summary>A tenant's customer accounts.</summary>
public sealed class IdentityUsers
{
    private readonly TouchQueHttp _http;

    internal IdentityUsers(TouchQueHttp http) => _http = http;

    private static string U(string userId) => "/identity/users/" + TouchQueHttp.Seg(userId);

    /// <summary>Query fields: q, blocked, emailVerified, connection, organization, limit, cursor.</summary>
    public Task<JsonObject> ListAsync(object? query = null, CancellationToken ct = default) => _http.GetAsync<JsonObject>("/identity/users", IdentityQuery.Of(query), ct);

    public Task<JsonObject> GetAsync(string userId, CancellationToken ct = default) => _http.GetAsync<JsonObject>(U(userId), null, ct);

    /// <summary>
    /// email and: password, passwordHash (bcrypt/argon2), customPasswordHash, emailVerified, name,
    /// givenName, familyName, phone, locale, userMetadata, appMetadata, sendVerificationEmail.
    /// </summary>
    public Task<JsonObject> CreateAsync(object user, CancellationToken ct = default) => _http.PostAsync<JsonObject>("/identity/users", Json.ToNode(user), ct);

    /// <summary>Metadata is merged; a key set to null is removed.</summary>
    public Task<JsonObject> UpdateAsync(string userId, object changes, CancellationToken ct = default) =>
        _http.PatchAsync<JsonObject>(U(userId), JsonNodeWithNulls(changes), ct);

    /// <summary>Erasure (KVKK/GDPR): the account and every workspace row that names it.</summary>
    public Task<JsonObject> DeleteAsync(string userId, CancellationToken ct = default) => _http.DeleteAsync<JsonObject>(U(userId), ct);

    public Task<JsonObject> BlockAsync(string userId, string? reason = null, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>(U(userId) + "/block", reason is null ? new JsonObject() : new JsonObject { ["reason"] = reason }, ct);

    public Task<JsonObject> UnblockAsync(string userId, CancellationToken ct = default) => _http.PostAsync<JsonObject>(U(userId) + "/unblock", new JsonObject(), ct);

    /// <summary>Everything about the person (KVKK/GDPR access request); never hashes.</summary>
    public Task<JsonObject> ExportAsync(string userId, CancellationToken ct = default) => _http.GetAsync<JsonObject>(U(userId) + "/export", null, ct);

    public Task<JsonObject> SessionsAsync(string userId, CancellationToken ct = default) => _http.GetAsync<JsonObject>(U(userId) + "/sessions", null, ct);

    /// <summary>Ends one of the user's sessions.</summary>
    public Task<JsonObject> EndSessionAsync(string userId, string sessionId, CancellationToken ct = default) =>
        _http.DeleteAsync<JsonObject>(U(userId) + "/sessions/" + TouchQueHttp.Seg(sessionId), ct);

    public Task<JsonObject> SignOutEverywhereAsync(string userId, CancellationToken ct = default) => _http.DeleteAsync<JsonObject>(U(userId) + "/sessions", ct);

    /// <summary>Removes passkeys, unlinks the TouchQue app, turns email codes off, signs out everywhere.</summary>
    public Task<JsonObject> ResetMfaAsync(string userId, CancellationToken ct = default) => _http.DeleteAsync<JsonObject>(U(userId) + "/mfa", ct);

    /// <summary>Accounts at providers whose tokens the vault keeps for the user (connections with tokenVault on).</summary>
    public Task<JsonObject> ConnectedAccountsAsync(string userId, CancellationToken ct = default) => _http.GetAsync<JsonObject>(U(userId) + "/connected-accounts", null, ct);

    /// <summary>Deletes the stored tokens: apps stop using the account for the user; signing in with it stays.</summary>
    public Task<JsonObject> DisconnectAccountAsync(string userId, string accountId, CancellationToken ct = default) =>
        _http.DeleteAsync<JsonObject>(U(userId) + "/connected-accounts/" + TouchQueHttp.Seg(accountId), ct);

    public Task<JsonObject> UnlinkIdentityAsync(string userId, string identityId, bool force = false, CancellationToken ct = default) =>
        _http.DeleteAsync<JsonObject>(U(userId) + "/identities/" + TouchQueHttp.Seg(identityId) + (force ? "?force=true" : ""), ct);

    public Task<JsonObject> SendVerificationEmailAsync(string userId, string? returnTo = null, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>(U(userId) + "/verification-email", new JsonObject().Put("returnTo", returnTo), ct);

    /// <summary><paramref name="sendEmail"/> false: the link comes back for you to deliver.</summary>
    public Task<JsonObject> PasswordResetAsync(string userId, bool sendEmail = true, int? ttlSec = null, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>(U(userId) + "/password-reset", new JsonObject { ["sendEmail"] = sendEmail }.Put("ttlSec", ttlSec), ct);

    public Task<JsonObject> RolesAsync(string userId, CancellationToken ct = default) => _http.GetAsync<JsonObject>(U(userId) + "/roles", null, ct);

    public Task<JsonObject> AddRolesAsync(string userId, IEnumerable<string> roleIds, string? organizationId = null, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>(U(userId) + "/roles", new JsonObject { ["roleIds"] = new JsonArray(roleIds.Select(r => (JsonNode)r).ToArray()) }.Put("organizationId", organizationId), ct);

    public Task<JsonObject> RemoveRoleAsync(string userId, string roleId, string? organizationId = null, CancellationToken ct = default) =>
        _http.DeleteAsync<JsonObject>(U(userId) + "/roles/" + TouchQueHttp.Seg(roleId) + (organizationId is null ? "" : "?organizationId=" + TouchQueHttp.Seg(organizationId)), ct);

    public Task<JsonObject> LogsAsync(string userId, int? limit = null, CancellationToken ct = default) =>
        _http.GetAsync<JsonObject>(U(userId) + "/logs", new Dictionary<string, string?> { ["limit"] = limit?.ToString(CultureInfo.InvariantCulture) }, ct);

    private static readonly System.Text.Json.JsonSerializerOptions KeepNulls =
        new(Json.Options) { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never };

    /// <summary>A body that keeps explicit nulls (they remove metadata keys).</summary>
    private static JsonNode? JsonNodeWithNulls(object value) =>
        value is JsonNode n ? n.DeepClone() : System.Text.Json.JsonSerializer.SerializeToNode(value, KeepNulls);
}
