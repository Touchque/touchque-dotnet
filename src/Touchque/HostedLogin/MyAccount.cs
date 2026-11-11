using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>A My Account API call failed; <see cref="IsStepUp"/> means the sign-in is too old for it (RFC 9470).</summary>
public class MyAccountException : TouchqueException
{
    public MyAccountException(string errorCode, int status, string? description = null, int? maxAge = null)
        : base(description is null ? errorCode : $"{errorCode}: {description}")
    {
        ErrorCode = errorCode;
        Status = status;
        Description = description;
        MaxAge = maxAge;
    }

    public string ErrorCode { get; }
    public int Status { get; }
    public string? Description { get; }
    public int? MaxAge { get; }

    /// <summary>True when the person must sign in again (AuthorizationUrl with MaxAge 0) before this change.</summary>
    public bool IsStepUp => ErrorCode == "insufficient_user_authentication";
}

/// <summary>
/// The Touchque Login My Account API (/me/v1) from your server: the signed-in
/// customer's own profile, sign-in methods, devices, apps and data, called with
/// their access token for audience https://&lt;domain&gt;/me/.
/// Security changes, the data export and deletion need a recent sign-in; when it is
/// too old a <see cref="MyAccountException"/> with <see cref="MyAccountException.IsStepUp"/> is thrown.
/// <code>
/// var me = await login.MyAccountTokenAsync(refreshToken, "read:me update:me");   // keep me.RefreshToken
/// var account = login.MyAccount(me.AccessToken);
/// var profile = (await account.GetAsync())["profile"];
/// </code>
/// </summary>
public sealed class MyAccount
{
    private readonly string _issuer;
    private readonly string _accessToken;
    private readonly HttpClient _client;

    public MyAccount(string domain, string accessToken, HttpClient? httpClient = null)
    {
        if (string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(accessToken))
        {
            throw new MyAccountException("config", 0, "domain and accessToken are required");
        }
        _issuer = HostedLogin.IssuerOf(domain) ?? throw new MyAccountException("config", 0, HostedLogin.InsecureIssuer(domain));
        _accessToken = accessToken;
        _client = httpClient ?? DefaultClient.Value;
    }

    private static readonly Lazy<HttpClient> DefaultClient = new(() => TouchqueHttp.CreateClient(TimeSpan.FromSeconds(10)));

    /// <summary>The hosted account page, optionally at security, devices or privacy.</summary>
    public string AccountPageUrl(string? section = null) => _issuer + "/account" + (string.IsNullOrEmpty(section) ? "" : "/" + section);

    private async Task<JsonObject> CallAsync(HttpMethod method, string path, JsonNode? body, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(method, _issuer + "/me/v1" + path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
        req.Headers.Accept.ParseAdd("application/json");
        if (body is not null) req.Content = new StringContent(Json.Serialize(body), new UTF8Encoding(false), "application/json");
        int status;
        string text;
        try
        {
            using var res = await _client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            status = (int)res.StatusCode;
            text = await TouchqueHttp.ReadLimitedAsync(res, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException e)
        {
            throw new MyAccountException("network_error", 0, e.Message);
        }
        if (status == 204) return new JsonObject();
        var d = Json.ParseObject(text);
        if (status >= 400) throw new MyAccountException(Json.Str(d, "error") ?? $"http_{status}", status, Json.Str(d, "error_description"), Json.Int(d, "max_age"));
        return d;
    }

    private static string Seg(string v) => TouchqueHttp.Seg(v);

    public Task<JsonObject> GetAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Get, "", null, ct);

    public Task<JsonObject> GetProfileAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Get, "/profile", null, ct);

    /// <summary>name, givenName, familyName, nickname, locale, userMetadata (merged; null removes a key).</summary>
    public Task<JsonObject> UpdateProfileAsync(object changes, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Patch, "/profile", changes as JsonNode ?? System.Text.Json.JsonSerializer.SerializeToNode(changes, KeepNulls), ct);

    private static readonly System.Text.Json.JsonSerializerOptions KeepNulls =
        new(Json.Options) { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never };

    public Task<JsonObject> AuthenticationMethodsAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Get, "/authentication-methods", null, ct);

    public Task RenamePasskeyAsync(string id, string label, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Patch, "/authentication-methods/passkeys/" + Seg(id), new JsonObject { ["label"] = label }, ct);

    /// <summary>Needs a recent sign-in.</summary>
    public Task RemovePasskeyAsync(string id, CancellationToken ct = default) => CallAsync(HttpMethod.Delete, "/authentication-methods/passkeys/" + Seg(id), null, ct);

    /// <summary>Needs a recent sign-in.</summary>
    public Task UnlinkTouchqueAppAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Delete, "/authentication-methods/touchque", null, ct);

    /// <summary>Email codes as a second step. Needs a recent sign-in.</summary>
    public Task<JsonObject> SetEmailCodesAsync(bool enabled, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Put, "/authentication-methods/email", new JsonObject { ["enabled"] = enabled }, ct);

    /// <summary>Texts a code to a new number for text-message codes. Needs a recent sign-in.</summary>
    public Task<JsonObject> StartSmsEnrollmentAsync(string phone, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Post, "/authentication-methods/sms", new JsonObject { ["phone"] = phone }, ct);

    /// <summary>The code from that text: text-message codes are on. Needs a recent sign-in.</summary>
    public Task<JsonObject> VerifySmsEnrollmentAsync(string code, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Post, "/authentication-methods/sms/verify", new JsonObject { ["code"] = code }, ct);

    /// <summary>Needs a recent sign-in.</summary>
    public Task RemoveSmsCodesAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Delete, "/authentication-methods/sms", null, ct);

    /// <summary>Needs a recent sign-in.</summary>
    public Task UnlinkIdentityAsync(string id, CancellationToken ct = default) => CallAsync(HttpMethod.Delete, "/identities/" + Seg(id), null, ct);

    /// <summary>Apps stop using a linked account for the person (token vault: the identity's appAccess id); signing in with it stays.</summary>
    public Task StopAppAccessAsync(string id, CancellationToken ct = default) => CallAsync(HttpMethod.Delete, "/app-access/" + Seg(id), null, ct);

    /// <summary>Sets or changes the password; other sessions end. Needs a recent sign-in.</summary>
    public Task<JsonObject> SetPasswordAsync(string password, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Put, "/password", new JsonObject { ["password"] = password }, ct);

    /// <summary>Needs a recent sign-in and another way to sign in.</summary>
    public Task RemovePasswordAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Delete, "/password", null, ct);

    /// <summary>A confirmation link goes to the new address. Needs a recent sign-in.</summary>
    public Task<JsonObject> ChangeEmailAsync(string email, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Post, "/email", new JsonObject { ["email"] = email }, ct);

    public Task<JsonObject> SendVerificationEmailAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Post, "/email/verification", null, ct);

    public Task<JsonObject> SessionsAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Get, "/sessions", null, ct);

    public Task EndSessionAsync(string id, CancellationToken ct = default) => CallAsync(HttpMethod.Delete, "/sessions/" + Seg(id), null, ct);

    public Task<JsonObject> EndOtherSessionsAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Delete, "/sessions", null, ct);

    public Task<JsonObject> AppsAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Get, "/apps", null, ct);

    public Task<JsonObject> RevokeAppAsync(string clientId, CancellationToken ct = default) => CallAsync(HttpMethod.Delete, "/apps/" + Seg(clientId), null, ct);

    public Task<JsonObject> ConsentsAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Get, "/consents", null, ct);

    public Task<JsonObject> SetMarketingAsync(bool granted, CancellationToken ct = default) =>
        CallAsync(HttpMethod.Put, "/consents/marketing", new JsonObject { ["granted"] = granted }, ct);

    /// <summary>Everything about the person (KVKK/GDPR). Needs a recent sign-in.</summary>
    public Task<JsonObject> ExportDataAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Get, "/export", null, ct);

    /// <summary>Erases the account at once. Needs delete:me and a recent sign-in.</summary>
    public Task<JsonObject> DeleteAccountAsync(CancellationToken ct = default) => CallAsync(HttpMethod.Delete, "", null, ct);
}
