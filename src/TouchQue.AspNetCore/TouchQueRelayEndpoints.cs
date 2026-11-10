using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using TouchQue.Relay;

namespace TouchQue.AspNetCore;

/// <summary>
/// Every relay route a frontend (<c>@touchque/web</c>) needs: POST /login, enrollment,
/// offline codes and the passkey ceremonies. See <see cref="RelayHandler{TRequest}"/> for the
/// routes and security rules.
/// <code>
/// app.MapTouchQueRelay("/touchque", new RelayOptions&lt;HttpContext&gt;
/// {
///     GetUserId = http => http.User.TouchQueUser(),
///     GetLoginUser = http => http.Session.GetString("password_verified_user"),
///     OnAuthenticated = async (http, response, info) => { /* sign the user in */ },
///     SilentSignIn = new(),
/// });
/// </code>
/// The client IP is <c>HttpContext.Connection.RemoteIpAddress</c>: behind a load balancer,
/// add <c>app.UseForwardedHeaders()</c> with your proxy as a known proxy first.
/// </summary>
public static class TouchQueRelayEndpoints
{
    private const int MaxBodyBytes = 64 * 1024;

    public static RouteGroupBuilder MapTouchQueRelay(this IEndpointRouteBuilder endpoints, string prefix, RelayOptions<HttpContext>? options = null)
    {
        var client = endpoints.ServiceProvider.GetRequiredService<TouchQueClient>();
        var handler = new RelayHandler<HttpContext>(client, options ?? new RelayOptions<HttpContext> { GetUserId = http => http.User.TouchQueUser() });
        var group = endpoints.MapGroup(prefix);
        // Each route hands the relay its own path: request.Path also holds the prefixes of the
        // groups this one is mapped on (app.MapGroup("/api").MapTouchQueRelay("/touchque")).
        foreach (var path in new[]
        {
            "/enroll/start", "/login", "/offline/challenge", "/offline/verify", "/offline/totp", "/passkey/authenticate/options",
            "/passkey/authenticate/verify", "/passkey/login/options", "/passkey/login/verify", "/passkey/register/options", "/passkey/register/verify",
        })
        {
            group.MapPost(path, http => HandleAsync(handler, path, http));
        }
        group.MapGet("/enroll/status", http => HandleAsync(handler, "/enroll/status", http));
        group.MapGet("/passkey/credentials", http => HandleAsync(handler, "/passkey/credentials", http));
        group.MapDelete("/passkey/credentials/{id}", http => HandleAsync(handler, "/passkey/credentials/" + http.Request.RouteValues["id"], http));
        return group;
    }

    private static async Task HandleAsync(RelayHandler<HttpContext> handler, string path, HttpContext http)
    {
        var request = http.Request;
        var body = new JsonObject();
        if (request.ContentLength is > MaxBodyBytes)
        {
            await WriteAsync(http, new RelayResponse(413, new JsonObject { ["error"] = "body_too_large" })).ConfigureAwait(false);
            return;
        }
        if (HttpMethods.IsPost(request.Method) && request.HasJsonContentType())
        {
            try
            {
                body = await JsonSerializer.DeserializeAsync<JsonNode>(request.Body, cancellationToken: http.RequestAborted).ConfigureAwait(false) as JsonObject ?? new JsonObject();
            }
            catch (JsonException)
            {
                await WriteAsync(http, new RelayResponse(400, new JsonObject { ["error"] = "invalid_json" })).ConfigureAwait(false);
                return;
            }
        }
        var response = await handler.HandleAsync(new RelayRequest<HttpContext>
        {
            Method = request.Method,
            Path = path,
            Body = body,
            Ip = http.TouchQueClientIp() ?? "",
            UserAgent = request.Header("User-Agent"),
            Header = request.Header,
            Native = http,
        }, http.RequestAborted).ConfigureAwait(false);
        await WriteAsync(http, response ?? new RelayResponse(404, new JsonObject { ["error"] = "not_found" })).ConfigureAwait(false);
    }

    internal static async Task WriteAsync(HttpContext http, RelayResponse response)
    {
        http.Response.StatusCode = response.Status;
        foreach (var (name, value) in response.Headers) http.Response.Headers.Append(name, value);
        http.Response.ContentType = "application/json; charset=utf-8";
        await http.Response.WriteAsync(response.Body.ToJsonString(TouchQue.Internal.Json.Options), http.RequestAborted).ConfigureAwait(false);
    }
}
