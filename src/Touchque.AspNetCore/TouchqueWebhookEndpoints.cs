using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Touchque.AspNetCore;

/// <summary>
/// Verified webhooks. <c>MapTouchqueWebhook</c> reads the raw body, checks the signature,
/// the timestamp and the jti (with the registered <see cref="IWebhookReplayCache"/>), then
/// calls your handler with the payload:
/// <list type="bullet">
/// <item>bad signature or too old → 401, your handler is not called;</item>
/// <item>a replay of a delivery already accepted → 200, your handler is not called again;</item>
/// <item>your handler's IResult (default 200 <c>{"received": true}</c>).</item>
/// </list>
/// <code>
/// app.MapTouchqueWebhook("/webhooks/touchque", async (JsonObject e, HttpContext http) =>
/// {
///     if ((string?)e["event"] == WebhookResource.EventApprovalRevoked) await sessions.EndAsync((string)e["requestId"]!);
/// });
/// </code>
/// </summary>
public static class TouchqueWebhookEndpoints
{
    private const int MaxBodyBytes = 1024 * 1024;

    public static RouteHandlerBuilder MapTouchqueWebhook(this IEndpointRouteBuilder endpoints, string pattern, Func<JsonObject, HttpContext, Task> handler) =>
        endpoints.MapTouchqueWebhook(pattern, async (payload, http) =>
        {
            await handler(payload, http).ConfigureAwait(false);
            return null;
        });

    public static RouteHandlerBuilder MapTouchqueWebhook(this IEndpointRouteBuilder endpoints, string pattern, Func<JsonObject, HttpContext, Task<IResult?>> handler) =>
        endpoints.MapPost(pattern, async (HttpContext http) =>
        {
            JsonObject payload;
            try
            {
                payload = await http.Request.ReadTouchqueWebhookAsync().ConfigureAwait(false);
            }
            catch (TouchqueWebhookReplayException)
            {
                return Results.Json(new JsonObject { ["received"] = true, ["duplicate"] = true });
            }
            catch (TouchqueWebhookSignatureException)
            {
                return Results.Json(new JsonObject { ["error"] = "invalid_signature" }, statusCode: 401);
            }
            return await handler(payload, http).ConfigureAwait(false) ?? Results.Json(new JsonObject { ["received"] = true });
        }).DisableAntiforgery();

    /// <summary>
    /// Reads and verifies the webhook in this request: the raw body, the <c>x-signature</c>
    /// header, the timestamp window and (with the registered replay cache) the jti.
    /// </summary>
    /// <exception cref="TouchqueWebhookSignatureException">Not from Touchque, changed, or too old.</exception>
    /// <exception cref="TouchqueWebhookReplayException">Already accepted: answer 200, don't run side effects again.</exception>
    public static async Task<JsonObject> ReadTouchqueWebhookAsync(this HttpRequest request, int toleranceSeconds = WebhookResource.DefaultToleranceSeconds)
    {
        var services = request.HttpContext.RequestServices;
        var client = services.GetRequiredService<TouchqueClient>();
        var cache = services.GetService<IWebhookReplayCache>();
        if (request.ContentLength is > MaxBodyBytes) throw new TouchqueWebhookSignatureException("body too large");
        using var reader = new StreamReader(request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        var raw = await reader.ReadToEndAsync(request.HttpContext.RequestAborted).ConfigureAwait(false);
        if (raw.Length > MaxBodyBytes) throw new TouchqueWebhookSignatureException("body too large");
        return await client.Webhook.VerifyAsync(raw, request.Header("x-signature"), toleranceSeconds, cache, request.HttpContext.RequestAborted).ConfigureAwait(false);
    }
}
