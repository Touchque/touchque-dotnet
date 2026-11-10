using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace TouchQue.AspNetCore;

/// <summary>Registers TouchQue in an ASP.NET Core (or any Microsoft.Extensions.Hosting) app.</summary>
public static class TouchQueServiceCollectionExtensions
{
    /// <summary>The named HttpClient the client uses (IHttpClientFactory).</summary>
    public const string HttpClientName = "TouchQue";

    /// <summary>
    /// Registers <see cref="TouchQueClient"/> as a singleton, its options (from
    /// <paramref name="configure"/>, then the environment: TQ_API_KEY, TQ_API_SECRET,
    /// TQ_API_URL), an in-process <see cref="IWebhookReplayCache"/>, and the named
    /// HttpClient <c>TouchQue</c> (never following redirects; connections recycled every 5
    /// minutes). The returned builder adds handlers (logging, a proxy). Do not add a retry
    /// handler: every request is signed with a one-time nonce, so a replay is refused;
    /// retry <see cref="TouchQueNetworkException"/> at the call site instead.
    /// </summary>
    public static IHttpClientBuilder AddTouchQue(this IServiceCollection services, Action<TouchQueOptions>? configure = null)
    {
        var options = services.AddOptions<TouchQueOptions>();
        if (configure is not null) options.Configure(configure);
        services.TryAddSingleton<IWebhookReplayCache, MemoryReplayCache>();
        services.TryAddSingleton(sp =>
        {
            var o = sp.GetRequiredService<IOptions<TouchQueOptions>>().Value;
            var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient(HttpClientName);
            http.Timeout = Timeout.InfiniteTimeSpan; // the client applies TouchQueOptions.Timeout per request
            return new TouchQueClient(o, http);
        });
        return services.AddHttpClient(HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            });
    }
}

/// <summary>Helpers shared by the ASP.NET Core integrations.</summary>
public static class TouchQueHttpContextExtensions
{
    internal const string ApprovalKey = "TouchQue.Approval";
    internal const string McpClaimsKey = "TouchQue.McpClaims";

    /// <summary>The approval of the current request (set by <c>RequireTouchQue</c>), or null.</summary>
    public static Approval? GetTouchQueApproval(this HttpContext context) =>
        context.Items.TryGetValue(ApprovalKey, out var a) ? a as Approval : null;

    /// <summary>The checked MCP token of the current request (set by <c>RequireTouchQueMcp</c>), or null.</summary>
    public static McpAuthClaims? GetTouchQueMcpClaims(this HttpContext context) =>
        context.Items.TryGetValue(McpClaimsKey, out var c) ? c as McpAuthClaims : null;

    /// <summary>
    /// The signed-in user as TouchQue knows them: the email claim, else the name
    /// identifier (sub), else the name.
    /// </summary>
    public static string? TouchQueUser(this ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true) return null;
        return First(user, "email", ClaimTypes.Email) ?? First(user, "sub", ClaimTypes.NameIdentifier) ?? First(user, "name", ClaimTypes.Name) ?? user.Identity?.Name;
    }

    private static string? First(ClaimsPrincipal user, params string[] types)
    {
        foreach (var t in types)
        {
            var v = user.FindFirst(t)?.Value;
            if (!string.IsNullOrEmpty(v)) return v;
        }
        return null;
    }

    /// <summary>
    /// The END user's IP (IPv4-mapped addresses as IPv4). Behind a proxy, add
    /// <c>app.UseForwardedHeaders()</c> with your proxy as a known proxy first.
    /// </summary>
    public static string? TouchQueClientIp(this HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress;
        if (ip is null) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.ToString();
    }

    internal static string? Header(this HttpRequest request, string name)
    {
        var v = request.Headers[name];
        return v.Count == 0 ? null : v.ToString();
    }
}
