using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Routing;

namespace Touchque.AspNetCore;

/// <summary>
/// An MCP server whose authorization server is Touchque SSO:
/// <code>
/// var mcpAuth = new McpAuth(new() { Issuer = "https://sso.touchque.com/mcp", Resource = "https://mcp.acme.com/mcp",
///     Tools = new Dictionary&lt;string, string&gt; { ["search_tickets"] = "tickets:read" } });
/// app.MapTouchqueMcpMetadata(mcpAuth);                         // RFC 9728 documents
/// app.MapPost("/mcp", handler).RequireTouchqueMcp(mcpAuth);    // 401/403 with WWW-Authenticate
/// // in the handler: mcpAuth.RequireTool(http.GetTouchqueMcpClaims()!, toolName)
/// </code>
/// </summary>
public static class TouchqueMcpExtensions
{
    /// <summary>Serves the protected resource metadata at every path of <see cref="McpAuth.MetadataPaths"/>.</summary>
    public static IEndpointRouteBuilder MapTouchqueMcpMetadata(this IEndpointRouteBuilder endpoints, McpAuth auth)
    {
        foreach (var path in auth.MetadataPaths())
        {
            endpoints.MapGet(path, () => Results.Json(auth.ProtectedResourceMetadata()));
        }
        return endpoints;
    }

    /// <summary>Checks the request's Touchque token (and its DPoP proof); the claims are in <c>HttpContext.GetTouchqueMcpClaims()</c>.</summary>
    public static TBuilder RequireTouchqueMcp<TBuilder>(this TBuilder builder, McpAuth auth, string? tool = null) where TBuilder : IEndpointConventionBuilder
    {
        builder.AddEndpointFilter(async (ctx, next) =>
        {
            var http = ctx.HttpContext;
            try
            {
                var claims = await auth.VerifyAsync(http.Request.Method, http.Request.GetEncodedUrl(), http.Request.Header, http.RequestAborted).ConfigureAwait(false);
                if (tool is not null) auth.RequireTool(claims, tool);
                http.Items[TouchqueHttpContextExtensions.McpClaimsKey] = claims;
            }
            catch (TouchqueMcpAuthException e)
            {
                http.Response.Headers.WWWAuthenticate = e.WwwAuthenticate;
                return Results.Json(new { error = e.Error, error_description = e.Message }, statusCode: e.Status);
            }
            return await next(ctx).ConfigureAwait(false);
        });
        return builder;
    }
}
