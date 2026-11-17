using System.Globalization;
using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>
/// Touchque Login Management API: your customers' accounts, roles,
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
    private readonly TouchqueHttp _http;

    internal IdentityResource(TouchqueHttp http)
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
        CustomDomains = new IdentityCustomDomains(http);
    }

    public IdentityUsers Users { get; }
    public IdentityJobs Imports { get; }
    public IdentityJobs Exports { get; }
    public IdentityCrud Roles { get; }
    public IdentityOrganizations Organizations { get; }
    public IdentityClients Clients { get; }
    public IdentityCrud Apis { get; }
    public IdentityCrud Connections { get; }

    /// <summary>Your own sign-in domains (<c>login.acme.com</c>): list, overview, get, create, verify, update (primary), delete.</summary>
    public IdentityCustomDomains CustomDomains { get; }

    /// <summary>The tenant (404 not_enabled until it is set up).</summary>
    public Task<JsonObject> GetTenantAsync(CancellationToken ct = default) => _http.GetAsync<JsonObject>("/identity/tenant", null, ct);

    /// <summary>Turns Touchque Login on (slug, displayName) or changes its settings.</summary>
    public Task<JsonObject> UpdateTenantAsync(object body, CancellationToken ct = default) => _http.PutAsync<JsonObject>("/identity/tenant", Json.ToNode(body), ct);

    /// <summary>Retires the tenant's signing key and makes a new one active.</summary>
    public Task<JsonObject> RotateSigningKeyAsync(CancellationToken ct = default) => _http.PostAsync<JsonObject>("/identity/tenant/signing-keys/rotate", new JsonObject(), ct);

    /// <summary>
    /// The phone app the hosted pages tell customers to approve on ("Approve on the Acme app").
    /// null: your brand name when the Mobile SDK is set up, else Touchque (<c>approverApp</c> in the tenant shows which).
    /// </summary>
    public Task<JsonObject> SetApproverAppNameAsync(string? name, CancellationToken ct = default) =>
        _http.PutAsync<JsonObject>("/identity/tenant", new JsonObject { ["branding"] = new JsonObject { ["approverAppName"] = name } }, ct);

    /// <summary>
    /// Serve sign-in only on the primary custom domain: {slug}.login.touchque.com redirects page loads there and
    /// refuses other calls. Turning it on needs a verified primary domain with a working certificate.
    /// </summary>
    public Task<JsonObject> SetCustomDomainOnlyAsync(bool on, CancellationToken ct = default) =>
        _http.PutAsync<JsonObject>("/identity/tenant", new JsonObject { ["customDomainOnly"] = on }, ct);

    /// <summary>
    /// The domain customer passkeys are made for (their relying party ID): null or "" for none (a passkey belongs to the
    /// host it was made on), one of your verified custom domains, or a domain above one of them that your organization
    /// verified (Organization → Domains: <c>acme.com</c> for <c>login.acme.com</c>), so passkeys keep working when
    /// sign-in moves to another host under it. Answers the tenant (<c>passkeyDomain</c>). Refusals are <see cref="TouchqueApiException"/>
    /// with the code in <see cref="TouchqueApiException.Error"/> and the field in <c>Body["field"]</c>: 400
    /// <c>invalid_request</c> (field <c>passkeyDomain</c>) for a value that is not a domain; 409 <c>not_your_domain</c>;
    /// 409 <c>organization_unavailable</c> (your organization's domains could not be read: try again); 409
    /// <c>passkeys_exist</c> (<c>Body["count"]</c> customer passkeys would stop working: set it before customers make
    /// passkeys). Before Touchque Login is set up for the workspace: 400 <c>invalid_request</c> with field <c>slug</c>
    /// (set it up with <see cref="UpdateTenantAsync"/> first).
    /// </summary>
    public Task<JsonObject> SetPasskeyDomainAsync(string? domain, CancellationToken ct = default) =>
        _http.PutAsync<JsonObject>("/identity/tenant", new JsonObject { ["passkeyDomain"] = domain }, ct);

    /// <summary>
    /// An alias of <see cref="IdentityCustomDomains.OverviewAsync"/> (<c>CustomDomains.OverviewAsync()</c>): the
    /// custom-domain list as Touchque answers it, the domains with <c>VerifiedDomains</c> and <c>SlugPasskeys</c>.
    /// </summary>
    public Task<CustomDomainsOverview> GetCustomDomainsAsync(CancellationToken ct = default) => CustomDomains.OverviewAsync(ct);

    /// <summary>Checks a verified custom domain's certificate at the sign-in edge now (<c>certificate</c>: pending | active | error).</summary>
    public Task<JsonObject> CheckDomainCertificateAsync(string domainId, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>("/identity/custom-domains/" + TouchqueHttp.Seg(domainId) + "/check-certificate", new JsonObject(), ct);

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
        _http.PutAsync<JsonObject>("/identity/delivery/" + TouchqueHttp.Seg(channel), Json.ToNode(provider), ct);

    /// <summary>Back to Touchque's transport.</summary>
    public Task<JsonObject> RemoveDeliveryAsync(string channel, CancellationToken ct = default) =>
        _http.DeleteAsync<JsonObject>("/identity/delivery/" + TouchqueHttp.Seg(channel), ct);

    /// <summary>One test message through the provider in use.</summary>
    public Task<JsonObject> TestDeliveryAsync(string channel, string to, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>("/identity/delivery/" + TouchqueHttp.Seg(channel) + "/test", new JsonObject { ["to"] = to }, ct);

    /// <summary>
    /// Moving your customers in from your own user database: <c>url</c>, <c>enabled</c>, <c>active</c> (asked only
    /// while it is enabled and passwords are on), <c>movedIn</c> (accounts made from it so far), <c>lastCall</c> ({ at, event, ok, status,
    /// ms, error } or null), <c>paused</c> (5 failed calls in a row pause it for a minute), <c>updatedAt</c>. Touchque
    /// POSTs <c>user_store.verify_password</c> { email, password } and <c>user_store.get_user</c> { email } to <c>url</c>,
    /// signed like its webhooks: check each with <see cref="WebhookResource.VerifyAsync"/> (or <c>MapTouchqueWebhook</c>),
    /// then answer 200 { "user": { "id", "email", … } } or { "user": null } (the same for an unknown address and a wrong
    /// password; 404 counts as null) within 5 seconds.
    /// </summary>
    public Task<JsonObject> GetUserStoreAsync(CancellationToken ct = default) =>
        _http.GetAsync<JsonObject>("/identity/user-store", null, ct);

    /// <summary>
    /// Sets the endpoint and whether it is asked. A null argument is left out: the endpoint set stays, and
    /// <paramref name="enabled"/> stays as it is (on for a new one). Answers like <see cref="GetUserStoreAsync"/>.
    /// Refusals (<see cref="TouchqueApiException.Error"/>): 409 <c>passwords_off</c> (turning it on while passwords are off),
    /// 400 <c>invalid_request</c> with <c>field</c> url (not a full https URL, a user name or password in it, a local address,
    /// over 500 characters, or none given and none set).
    /// </summary>
    public Task<JsonObject> SetUserStoreAsync(string? url = null, bool? enabled = null, CancellationToken ct = default)
    {
        var body = new JsonObject();
        if (url != null) body["url"] = url;
        if (enabled != null) body["enabled"] = enabled;
        return _http.PutAsync<JsonObject>("/identity/user-store", body, ct);
    }

    /// <summary>
    /// One signed <c>user_store.ping</c> to <paramref name="url"/> (null or "": the endpoint set, sent as <c>{}</c>):
    /// { ok, error, ms }. An endpoint that fails is an answer (<c>ok</c> false, <c>error</c> says why), not an exception,
    /// and it never pauses the endpoint.
    /// </summary>
    public Task<JsonObject> TestUserStoreAsync(string? url = null, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>("/identity/user-store/test", string.IsNullOrEmpty(url) ? new JsonObject() : new JsonObject { ["url"] = url }, ct);

    /// <summary>
    /// Stops asking your user database and forgets the endpoint; accounts already moved in stay. Answers an empty object
    /// (204), also when none is set; 404 <c>not_enabled</c> means Touchque Login is not set up.
    /// </summary>
    public Task<JsonObject> RemoveUserStoreAsync(CancellationToken ct = default) =>
        _http.DeleteAsync<JsonObject>("/identity/user-store", ct);
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

/// <summary>List, get, create, update and delete for one kind of Touchque Login object.</summary>
public class IdentityCrud
{
    private protected readonly TouchqueHttp Http;
    private protected readonly string Base;
    private readonly string _listKey;

    internal IdentityCrud(TouchqueHttp http, string basePath, string listKey)
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

    public virtual Task<JsonObject> GetAsync(string id, CancellationToken ct = default) => Http.GetAsync<JsonObject>(Base + "/" + TouchqueHttp.Seg(id), null, ct);

    public Task<JsonObject> CreateAsync(object body, CancellationToken ct = default) => Http.PostAsync<JsonObject>(Base, Json.ToNode(body), ct);

    public Task<JsonObject> UpdateAsync(string id, object body, CancellationToken ct = default) => Http.PatchAsync<JsonObject>(Base + "/" + TouchqueHttp.Seg(id), Json.ToNode(body), ct);

    public Task<JsonObject> DeleteAsync(string id, CancellationToken ct = default) => Http.DeleteAsync<JsonObject>(Base + "/" + TouchqueHttp.Seg(id), ct);
}

/// <summary>
/// Your own sign-in domains (<c>login.acme.com</c>). <see cref="IdentityCrud.ListAsync"/> answers the domains, each
/// with <c>dns</c> (what its DNS said at the last check) and <c>autoCheckUntil</c>; <see cref="OverviewAsync"/> the
/// whole answer. The API has no read by id: <see cref="GetAsync"/> finds the domain in the list.
/// </summary>
public sealed class IdentityCustomDomains : IdentityCrud
{
    internal IdentityCustomDomains(TouchqueHttp http) : base(http, "/identity/custom-domains", "domains") { }

    /// <summary>
    /// The list as Touchque answers it: the domains (what <see cref="IdentityCrud.ListAsync"/> returns), your
    /// organization's verified domains and <c>slugPasskeys</c>. <see cref="IdentityResource.GetCustomDomainsAsync"/>
    /// is an alias.
    /// </summary>
    public Task<CustomDomainsOverview> OverviewAsync(CancellationToken ct = default) =>
        Http.GetAsync<CustomDomainsOverview>(Base, null, ct);

    /// <summary>
    /// The domain with this id, found in <see cref="IdentityCrud.ListAsync"/>. None: a <see cref="TouchqueApiException"/>
    /// shaped like the API's 404 (<see cref="TouchqueApiException.Status"/> 404, <see cref="TouchqueApiException.Error"/>
    /// <c>not_found</c>).
    /// </summary>
    public override async Task<JsonObject> GetAsync(string id, CancellationToken ct = default)
    {
        foreach (var domain in await ListAsync(null, ct).ConfigureAwait(false))
        {
            if (domain is JsonObject found && Json.Str(found, "id") == id) return (JsonObject)found.DeepClone();
        }
        throw new TouchqueApiException(404, new JsonObject { ["error"] = "not_found", ["message"] = "No custom domain with this id" });
    }

    /// <summary>
    /// Checks the domain's DNS TXT record now (a domain on one your organization verified needs none, only its CNAME)
    /// and looks at its DNS (<c>dns</c>); answers the domain (<c>status</c> verified once it is). Touchque also checks a
    /// new domain by itself every 5 minutes until <c>autoCheckUntil</c>, 72 hours after it was added.
    /// </summary>
    public Task<JsonObject> VerifyAsync(string id, CancellationToken ct = default) =>
        Http.PostAsync<JsonObject>(Base + "/" + TouchqueHttp.Seg(id) + "/verify", new JsonObject(), ct);
}

/// <summary>Your custom domains as <c>GET /identity/custom-domains</c> answers them (<see cref="IdentityCustomDomains.OverviewAsync"/>).</summary>
public sealed record CustomDomainsOverview : TouchqueObject
{
    /// <summary>
    /// The domains, what <see cref="IdentityCrud.ListAsync"/> returns: each the API's JSON (<c>id</c>, <c>domain</c>,
    /// <c>status</c>, <c>primary</c>, <c>proof</c>, <c>records</c>, <c>certificate</c>, <c>dns</c>, <c>autoCheckUntil</c>…).
    /// </summary>
    public JsonArray Domains { get; init; } = new();

    /// <summary>
    /// Your organization's verified domains (Organization → Domains): a passkey domain above a custom domain must be one
    /// of them. Null when they could not be read.
    /// </summary>
    public IReadOnlyList<string>? VerifiedDomains { get; init; }

    /// <summary>Customer passkeys made on <c>{slug}.login.touchque.com</c>: they belong to that name and do not work on a custom domain.</summary>
    public int SlugPasskeys { get; init; }
}

/// <summary>Business customers, their members and invitations.</summary>
public sealed class IdentityOrganizations : IdentityCrud
{
    internal IdentityOrganizations(TouchqueHttp http) : base(http, "/identity/organizations", "organizations") { }

    public Task<JsonObject> MembersAsync(string orgId, CancellationToken ct = default) => Http.GetAsync<JsonObject>(Org(orgId) + "/members", null, ct);

    public Task<JsonObject> AddMembersAsync(string orgId, IEnumerable<string> userIds, CancellationToken ct = default) =>
        Http.PostAsync<JsonObject>(Org(orgId) + "/members", new JsonObject { ["userIds"] = new JsonArray(userIds.Select(u => (JsonNode)u).ToArray()) }, ct);

    public Task<JsonObject> RemoveMemberAsync(string orgId, string userId, CancellationToken ct = default) =>
        Http.DeleteAsync<JsonObject>(Org(orgId) + "/members/" + TouchqueHttp.Seg(userId), ct);

    public Task<JsonObject> SetConnectionsAsync(string orgId, object connections, CancellationToken ct = default) =>
        Http.PutAsync<JsonObject>(Org(orgId) + "/connections", new JsonObject { ["connections"] = Json.ToNode(connections) }, ct);

    public Task<JsonObject> InvitationsAsync(string orgId, CancellationToken ct = default) => Http.GetAsync<JsonObject>(Org(orgId) + "/invitations", null, ct);

    /// <summary>The link opens the app's sign-in route (initiateLoginUri) with organization and invitation.</summary>
    public Task<JsonObject> InviteAsync(string orgId, object invitation, CancellationToken ct = default) =>
        Http.PostAsync<JsonObject>(Org(orgId) + "/invitations", Json.ToNode(invitation), ct);

    public Task<JsonObject> RevokeInvitationAsync(string orgId, string invitationId, CancellationToken ct = default) =>
        Http.DeleteAsync<JsonObject>(Org(orgId) + "/invitations/" + TouchqueHttp.Seg(invitationId), ct);

    private string Org(string orgId) => Base + "/" + TouchqueHttp.Seg(orgId);
}

/// <summary>Your customers' apps (OpenID Connect clients).</summary>
public sealed class IdentityClients : IdentityCrud
{
    internal IdentityClients(TouchqueHttp http) : base(http, "/identity/clients", "clients") { }

    /// <summary>A new client secret: it is in the answer, this once.</summary>
    public Task<JsonObject> RotateSecretAsync(string clientId, CancellationToken ct = default) =>
        Http.PostAsync<JsonObject>(Base + "/" + TouchqueHttp.Seg(clientId) + "/rotate-secret", new JsonObject(), ct);
}

/// <summary>Bulk user imports and exports, running in the background.</summary>
public sealed class IdentityJobs
{
    private readonly TouchqueHttp _http;
    private readonly string _kind;

    internal IdentityJobs(TouchqueHttp http, string kind)
    {
        _http = http;
        _kind = kind;
    }

    /// <summary>Imports: <c>{ users, upsert }</c>; exports: <c>{ format = "csv" | "json" }</c>.</summary>
    public Task<JsonObject> StartAsync(object body, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>("/identity/users-" + _kind, Json.ToNode(body), ct);

    public Task<JsonObject> GetAsync(string jobId, CancellationToken ct = default) =>
        _http.GetAsync<JsonObject>("/identity/users-" + _kind + "/" + TouchqueHttp.Seg(jobId), null, ct);

    /// <summary>Exports: the finished file (CSV or JSON text).</summary>
    public Task<string> FileAsync(string jobId, CancellationToken ct = default) =>
        _http.GetTextAsync("/identity/users-" + _kind + "/" + TouchqueHttp.Seg(jobId) + "/file", ct);

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
    private readonly TouchqueHttp _http;

    internal IdentityUsers(TouchqueHttp http) => _http = http;

    private static string U(string userId) => "/identity/users/" + TouchqueHttp.Seg(userId);

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
        _http.DeleteAsync<JsonObject>(U(userId) + "/sessions/" + TouchqueHttp.Seg(sessionId), ct);

    public Task<JsonObject> SignOutEverywhereAsync(string userId, CancellationToken ct = default) => _http.DeleteAsync<JsonObject>(U(userId) + "/sessions", ct);

    /// <summary>Removes passkeys, unlinks the Touchque app, turns email codes off, signs out everywhere.</summary>
    public Task<JsonObject> ResetMfaAsync(string userId, CancellationToken ct = default) => _http.DeleteAsync<JsonObject>(U(userId) + "/mfa", ct);

    /// <summary>Accounts at providers whose tokens the vault keeps for the user (connections with tokenVault on).</summary>
    public Task<JsonObject> ConnectedAccountsAsync(string userId, CancellationToken ct = default) => _http.GetAsync<JsonObject>(U(userId) + "/connected-accounts", null, ct);

    /// <summary>Deletes the stored tokens: apps stop using the account for the user; signing in with it stays.</summary>
    public Task<JsonObject> DisconnectAccountAsync(string userId, string accountId, CancellationToken ct = default) =>
        _http.DeleteAsync<JsonObject>(U(userId) + "/connected-accounts/" + TouchqueHttp.Seg(accountId), ct);

    public Task<JsonObject> UnlinkIdentityAsync(string userId, string identityId, bool force = false, CancellationToken ct = default) =>
        _http.DeleteAsync<JsonObject>(U(userId) + "/identities/" + TouchqueHttp.Seg(identityId) + (force ? "?force=true" : ""), ct);

    public Task<JsonObject> SendVerificationEmailAsync(string userId, string? returnTo = null, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>(U(userId) + "/verification-email", new JsonObject().Put("returnTo", returnTo), ct);

    /// <summary><paramref name="sendEmail"/> false: the link comes back for you to deliver.</summary>
    public Task<JsonObject> PasswordResetAsync(string userId, bool sendEmail = true, int? ttlSec = null, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>(U(userId) + "/password-reset", new JsonObject { ["sendEmail"] = sendEmail }.Put("ttlSec", ttlSec), ct);

    public Task<JsonObject> RolesAsync(string userId, CancellationToken ct = default) => _http.GetAsync<JsonObject>(U(userId) + "/roles", null, ct);

    public Task<JsonObject> AddRolesAsync(string userId, IEnumerable<string> roleIds, string? organizationId = null, CancellationToken ct = default) =>
        _http.PostAsync<JsonObject>(U(userId) + "/roles", new JsonObject { ["roleIds"] = new JsonArray(roleIds.Select(r => (JsonNode)r).ToArray()) }.Put("organizationId", organizationId), ct);

    public Task<JsonObject> RemoveRoleAsync(string userId, string roleId, string? organizationId = null, CancellationToken ct = default) =>
        _http.DeleteAsync<JsonObject>(U(userId) + "/roles/" + TouchqueHttp.Seg(roleId) + (organizationId is null ? "" : "?organizationId=" + TouchqueHttp.Seg(organizationId)), ct);

    public Task<JsonObject> LogsAsync(string userId, int? limit = null, CancellationToken ct = default) =>
        _http.GetAsync<JsonObject>(U(userId) + "/logs", new Dictionary<string, string?> { ["limit"] = limit?.ToString(CultureInfo.InvariantCulture) }, ct);

    private static readonly System.Text.Json.JsonSerializerOptions KeepNulls =
        new(Json.Options) { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never };

    /// <summary>A body that keeps explicit nulls (they remove metadata keys).</summary>
    private static JsonNode? JsonNodeWithNulls(object value) =>
        value is JsonNode n ? n.DeepClone() : System.Text.Json.JsonSerializer.SerializeToNode(value, KeepNulls);
}
