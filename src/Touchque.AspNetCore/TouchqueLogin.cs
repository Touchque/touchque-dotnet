using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Touchque.AspNetCore;

/// <summary>Touchque Login (hosted sign-in) in an ASP.NET Core app.</summary>
public sealed class TouchqueLoginOptions
{
    /// <summary>
    /// The authentication scheme of the session cookie. Its value is part of the cookie's
    /// Data Protection purpose, so it keeps its original spelling: another value would sign
    /// every signed-in user out.
    /// </summary>
    public const string DefaultScheme = "TouchQue";

    /// <summary>Your tenant: <c>acme.login.touchque.com</c> or your own domain.</summary>
    public string Domain { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string? ClientSecret { get; set; }
    /// <summary>Absolute, or a path of this app (default: <see cref="CallbackPath"/>).</summary>
    public string? RedirectUri { get; set; }
    /// <summary>Add <c>offline_access</c> to keep the session alive with refresh tokens.</summary>
    public string Scope { get; set; } = "openid profile email";
    public string? Audience { get; set; }
    public string LoginPath { get; set; } = "/login";
    public string CallbackPath { get; set; } = "/callback";
    public string LogoutPath { get; set; } = "/logout";
    /// <summary>Where to go after signing out (must be a registered sign-out URL).</summary>
    public string? PostLogoutRedirectUri { get; set; }
    public string Scheme { get; set; } = DefaultScheme;
    /// <summary>How long the session cookie lives (default 7 days).</summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromDays(7);
    /// <summary>Runs after a successful sign-in, before the redirect (link the user to your records, add claims).</summary>
    public Func<HttpContext, TokenSet, ClaimsPrincipal, Task>? AfterSignIn { get; set; }
}

/// <summary>A bearer handler for your API: Touchque Login access tokens (at+jwt).</summary>
public sealed class TouchqueBearerOptions : AuthenticationSchemeOptions
{
    public const string DefaultScheme = "TouchqueBearer";

    /// <summary>Your tenant: <c>acme.login.touchque.com</c> or your own domain.</summary>
    public string Domain { get; set; } = "";
    /// <summary>Your API's identifier: the token's <c>aud</c>.</summary>
    public string Audience { get; set; } = "";
    /// <summary>Scopes every request needs (403 insufficient_scope otherwise).</summary>
    public IReadOnlyList<string> RequiredScopes { get; set; } = Array.Empty<string>();
    /// <summary>The HttpClient that fetches the tenant's keys (default: the SDK's own).</summary>
    public HttpClient? Backchannel { get; set; }
}

/// <summary>
/// Two lines for Touchque Login:
/// <code>
/// builder.Services.AddTouchqueLogin(o => { o.Domain = "acme.login.touchque.com"; o.ClientId = "…"; o.ClientSecret = "…"; });
/// app.MapTouchqueLogin();                       // GET /login, /callback, /logout
/// app.MapGet("/account", (ClaimsPrincipal user) => user.FindFirstValue("email")).RequireAuthorization();
/// </code>
/// The session is ASP.NET Core's cookie authentication (encrypted with Data Protection,
/// split across cookies when large). The tokens are kept in it
/// (<c>HttpContext.GetTokenAsync("access_token")</c>); a token about to expire is refreshed
/// when a refresh token is there (ask for <c>offline_access</c>).
/// </summary>
public static class TouchqueLoginExtensions
{
    private const string TxCookie = "tq_login_tx";

    public static AuthenticationBuilder AddTouchqueLogin(this IServiceCollection services, Action<TouchqueLoginOptions> configure)
    {
        var options = new TouchqueLoginOptions();
        configure(options);
        if (string.IsNullOrEmpty(options.Domain) || string.IsNullOrEmpty(options.ClientId))
        {
            throw new TouchqueConfigException("AddTouchqueLogin needs Domain and ClientId");
        }
        services.AddSingleton(options);
        services.AddDataProtection();
        services.AddSingleton(sp => new HostedLogin(new HostedLoginOptions
        {
            Domain = options.Domain, ClientId = options.ClientId, ClientSecret = options.ClientSecret, Scope = options.Scope, Audience = options.Audience,
            RedirectUri = IsWebUrl(options.RedirectUri) ? options.RedirectUri : null,
        }));
        return services.AddAuthentication(options.Scheme).AddCookie(options.Scheme, c =>
        {
            c.LoginPath = options.LoginPath;
            c.ReturnUrlParameter = "returnTo";
            c.Cookie.Name = "tq_session";
            c.Cookie.HttpOnly = true;
            c.Cookie.SameSite = SameSiteMode.Lax;
            c.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            c.ExpireTimeSpan = options.SessionLifetime;
            c.SlidingExpiration = false;
            c.Events.OnValidatePrincipal = RefreshAsync;
            // APIs get 401/403 instead of a redirect to the sign-in page.
            c.Events.OnRedirectToLogin = ctx => ApiOr(ctx, 401);
            c.Events.OnRedirectToAccessDenied = ctx => ApiOr(ctx, 403);
        });
    }

    private static Task ApiOr(RedirectContext<CookieAuthenticationOptions> ctx, int status)
    {
        var accept = ctx.Request.Headers.Accept.ToString();
        if (accept.Contains("application/json", StringComparison.OrdinalIgnoreCase) && !accept.Contains("text/html", StringComparison.OrdinalIgnoreCase))
        {
            ctx.Response.StatusCode = status;
            return ctx.Response.WriteAsJsonAsync(new { error = status == 401 ? "sign_in_required" : "forbidden" });
        }
        ctx.Response.Redirect(ctx.RedirectUri);
        return Task.CompletedTask;
    }

    /// <summary>Refreshes the access token when it is about to expire and a refresh token is there; otherwise the session ends.</summary>
    private static async Task RefreshAsync(CookieValidatePrincipalContext ctx)
    {
        var expiresAt = ctx.Properties.GetTokenValue("expires_at");
        if (expiresAt is null || !DateTimeOffset.TryParse(expiresAt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at)) return;
        if (at - DateTimeOffset.UtcNow > TimeSpan.FromSeconds(30)) return;
        var refreshToken = ctx.Properties.GetTokenValue("refresh_token");
        if (string.IsNullOrEmpty(refreshToken))
        {
            ctx.RejectPrincipal();
            return;
        }
        try
        {
            var login = ctx.HttpContext.RequestServices.GetRequiredService<HostedLogin>();
            var tokens = await login.RefreshAsync(refreshToken, null, ctx.HttpContext.RequestAborted).ConfigureAwait(false);
            ctx.Properties.StoreTokens(TokensOf(tokens, ctx.Properties));
            ctx.ShouldRenew = true;
        }
        catch (HostedLoginException)
        {
            ctx.RejectPrincipal();
        }
    }

    private static IEnumerable<AuthenticationToken> TokensOf(TokenSet tokens, AuthenticationProperties? previous)
    {
        var list = new List<AuthenticationToken>
        {
            new() { Name = "access_token", Value = tokens.AccessToken },
            new() { Name = "token_type", Value = tokens.TokenType },
            new() { Name = "expires_at", Value = DateTimeOffset.FromUnixTimeSeconds(tokens.ExpiresAt).ToString("o", CultureInfo.InvariantCulture) },
        };
        var idToken = tokens.IdToken ?? previous?.GetTokenValue("id_token");
        if (!string.IsNullOrEmpty(idToken)) list.Add(new() { Name = "id_token", Value = idToken });
        var refreshToken = tokens.RefreshToken ?? previous?.GetTokenValue("refresh_token");
        if (!string.IsNullOrEmpty(refreshToken)) list.Add(new() { Name = "refresh_token", Value = refreshToken });
        return list;
    }

    /// <summary>Maps GET /login, /callback and /logout (paths from <see cref="TouchqueLoginOptions"/>).</summary>
    public static IEndpointRouteBuilder MapTouchqueLogin(this IEndpointRouteBuilder endpoints)
    {
        var options = endpoints.ServiceProvider.GetRequiredService<TouchqueLoginOptions>();

        endpoints.MapGet(options.LoginPath, (HttpContext http, HostedLogin login, IDataProtectionProvider dp) =>
        {
            var q = http.Request.Query;
            var returnTo = SafeReturnTo(q["returnTo"].ToString());
            var auth = login.AuthorizationUrl(new AuthorizationOptions
            {
                RedirectUri = RedirectUri(http, options),
                ScreenHint = q["screen_hint"] == "signup" ? "signup" : null,
                LoginHint = Opt(q["login_hint"]),
                Connection = Opt(q["connection"]),
                Organization = Opt(q["organization"]),
                Invitation = Opt(q["invitation"]),
            });
            var tx = new JsonObject { ["state"] = auth.State, ["nonce"] = auth.Nonce, ["codeVerifier"] = auth.CodeVerifier, ["returnTo"] = returnTo };
            http.Response.Cookies.Append(TxCookie, Protector(dp).Protect(tx.ToJsonString(), TimeSpan.FromMinutes(15)), CookieOptions(http, TimeSpan.FromMinutes(15)));
            return Results.Redirect(auth.Url);
        });

        endpoints.MapGet(options.CallbackPath, async (HttpContext http, HostedLogin login, IDataProtectionProvider dp, ILoggerFactory logs) =>
        {
            JsonObject? tx = null;
            try
            {
                var raw = http.Request.Cookies[TxCookie];
                if (!string.IsNullOrEmpty(raw)) tx = JsonNode.Parse(Protector(dp).Unprotect(raw)) as JsonObject;
            }
            catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or JsonException)
            {
                tx = null;
            }
            http.Response.Cookies.Delete(TxCookie, CookieOptions(http, TimeSpan.Zero));
            if (tx is null) return Results.BadRequest(new { error = "state_missing", error_description = "This sign-in expired or started in another browser" });
            TokenSet tokens;
            try
            {
                var query = http.Request.Query.ToDictionary(p => p.Key, p => p.Value.ToString());
                tokens = await login.HandleCallbackAsync(query, new CallbackChecks
                {
                    State = (string?)tx["state"] ?? "", Nonce = (string?)tx["nonce"] ?? "", CodeVerifier = (string?)tx["codeVerifier"] ?? "",
                    RedirectUri = RedirectUri(http, options),
                }, http.RequestAborted).ConfigureAwait(false);
            }
            catch (HostedLoginException e)
            {
                logs.CreateLogger("Touchque.Login").LogWarning("Touchque sign-in failed: {Code}", e.ErrorCode);
                return Results.BadRequest(new { error = e.ErrorCode, error_description = e.Description });
            }
            var principal = new ClaimsPrincipal(Identity(tokens.Claims, options.Scheme));
            if (options.AfterSignIn is not null) await options.AfterSignIn(http, tokens, principal).ConfigureAwait(false);
            var props = new AuthenticationProperties { IsPersistent = true, ExpiresUtc = DateTimeOffset.UtcNow + options.SessionLifetime };
            props.StoreTokens(TokensOf(tokens, null));
            await http.SignInAsync(options.Scheme, principal, props).ConfigureAwait(false);
            return Results.Redirect(SafeReturnTo((string?)tx["returnTo"]));
        });

        endpoints.MapGet(options.LogoutPath, async (HttpContext http, HostedLogin login) =>
        {
            var idToken = await http.GetTokenAsync(options.Scheme, "id_token").ConfigureAwait(false);
            await http.SignOutAsync(options.Scheme).ConfigureAwait(false);
            return Results.Redirect(login.LogoutUrl(idToken, options.PostLogoutRedirectUri));
        });
        return endpoints;
    }

    /// <summary>Touchque Login access tokens for your API (Authorization: Bearer).</summary>
    public static AuthenticationBuilder AddTouchqueBearer(this AuthenticationBuilder builder, Action<TouchqueBearerOptions> configure, string scheme = TouchqueBearerOptions.DefaultScheme) =>
        builder.AddScheme<TouchqueBearerOptions, TouchqueBearerHandler>(scheme, configure);

    private static string? Opt(Microsoft.Extensions.Primitives.StringValues v) => v.Count == 0 || string.IsNullOrEmpty(v[0]) ? null : v[0];

    // The purpose of the sign-in cookie in flight: it keeps its original spelling so a sign-in started before an upgrade still completes.
    private static ITimeLimitedDataProtector Protector(IDataProtectionProvider dp) => dp.CreateProtector("TouchQue.Login.Transaction").ToTimeLimitedDataProtector();

    private static CookieOptions CookieOptions(HttpContext http, TimeSpan maxAge) => new()
    {
        HttpOnly = true, Secure = http.Request.IsHttps, SameSite = SameSiteMode.Lax, Path = "/", MaxAge = maxAge,
    };

    private static string RedirectUri(HttpContext http, TouchqueLoginOptions o)
    {
        var target = o.RedirectUri ?? o.CallbackPath;
        if (IsWebUrl(target)) return target;
        return $"{http.Request.Scheme}://{http.Request.Host}{http.Request.PathBase}{(target.StartsWith('/') ? "" : "/")}{target}";
    }

    /// <summary>An absolute http(s) URL ("/callback" parses as an absolute file URI on Unix).</summary>
    private static bool IsWebUrl(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || u.Scheme == Uri.UriSchemeHttp);

    /// <summary>A path inside this app to return to after sign-in (never another site).</summary>
    public static string SafeReturnTo(string? value, string fallback = "/")
    {
        if (string.IsNullOrEmpty(value) || !value.StartsWith('/') || value.StartsWith("//", StringComparison.Ordinal) || value.StartsWith("/\\", StringComparison.Ordinal) || value.Length > 2000)
        {
            return fallback;
        }
        return value;
    }

    /// <summary>The ID token's claims as a ClaimsIdentity (sub = NameIdentifier, name, email).</summary>
    internal static ClaimsIdentity Identity(JsonObject claims, string scheme)
    {
        var identity = new ClaimsIdentity(scheme, "name", "role");
        foreach (var (k, v) in claims)
        {
            if (v is null) continue;
            if (v is JsonArray arr)
            {
                foreach (var item in arr) identity.AddClaim(new Claim(k, Text(item)));
            }
            else
            {
                identity.AddClaim(new Claim(k, Text(v)));
            }
        }
        if (claims["sub"] is JsonValue sub) identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, Text(sub)));
        if (claims["email"] is JsonValue email) identity.AddClaim(new Claim(ClaimTypes.Email, Text(email)));
        if (identity.FindFirst("name") is null && claims["email"] is JsonValue e) identity.AddClaim(new Claim("name", Text(e)));
        return identity;
    }

    private static string Text(JsonNode? n) => n switch
    {
        null => "",
        JsonValue v when v.TryGetValue<string>(out var s) => s,
        _ => n.ToJsonString(),
    };
}

/// <summary>Checks <c>Authorization: Bearer</c> Touchque Login access tokens: signature, issuer, audience, expiry, typ at+jwt, scopes.</summary>
public sealed class TouchqueBearerHandler : AuthenticationHandler<TouchqueBearerOptions>
{
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<TouchqueBearerOptions, HostedLogin> Logins = new();
    private string? _error;

    public TouchqueBearerHandler(IOptionsMonitor<TouchqueBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return AuthenticateResult.NoResult();
        var token = header["Bearer ".Length..].Trim();
        if (string.IsNullOrEmpty(Options.Domain) || string.IsNullOrEmpty(Options.Audience))
        {
            return AuthenticateResult.Fail("TouchqueBearerOptions needs Domain and Audience");
        }
        var login = Logins.GetValue(Options, o => new HostedLogin(new HostedLoginOptions { Domain = o.Domain, ClientId = o.Audience, HttpClient = o.Backchannel }));
        try
        {
            var claims = await login.VerifyAccessTokenAsync(token, Options.Audience, Options.RequiredScopes, Context.RequestAborted).ConfigureAwait(false);
            var identity = TouchqueLoginExtensions.Identity(claims, Scheme.Name);
            foreach (var s in (Touchque.Internal.Json.Str(claims, "scope") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                identity.AddClaim(new Claim("scp", s));
            }
            return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
        }
        catch (HostedLoginException e)
        {
            _error = e.ErrorCode;
            return AuthenticateResult.Fail(e.Message);
        }
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var insufficient = _error == "insufficient_scope";
        Response.StatusCode = insufficient ? 403 : 401;
        Response.Headers.WWWAuthenticate = _error is null ? "Bearer" : $"Bearer error=\"{(insufficient ? "insufficient_scope" : "invalid_token")}\"";
        return Response.WriteAsJsonAsync(new { error = _error ?? "invalid_token" });
    }
}
