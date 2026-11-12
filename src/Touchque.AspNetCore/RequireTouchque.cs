using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Touchque.Internal;
using HttpJsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;
using MvcJsonOptions = Microsoft.AspNetCore.Mvc.JsonOptions;

namespace Touchque.AspNetCore;

/// <summary>What a guard callback sees: the request and, on a minimal API endpoint, its bound arguments.</summary>
public sealed class TouchqueGuardContext
{
    internal TouchqueGuardContext(HttpContext httpContext, IReadOnlyList<object?> arguments)
    {
        HttpContext = httpContext;
        Arguments = arguments;
    }

    public HttpContext HttpContext { get; }

    /// <summary>The endpoint's bound arguments (minimal APIs) or action arguments (MVC).</summary>
    public IReadOnlyList<object?> Arguments { get; }

    /// <summary>The first bound argument of type <typeparamref name="T"/>, e.g. the request body.</summary>
    public T? Argument<T>() => Arguments.OfType<T>().FirstOrDefault();
}

/// <summary>Options of <c>RequireTouchque</c>.</summary>
public sealed class TouchqueGuardOptions
{
    /// <summary>Who approves (default: the signed-in user's email, else sub, else name). For a login route, return whoever just passed your password check.</summary>
    public Func<TouchqueGuardContext, string?>? User { get; set; }

    /// <summary>Transaction details shown on the phone. Build them from server-side state or validated input.</summary>
    public Func<TouchqueGuardContext, IReadOnlyList<LoginDetail>?>? Details { get; set; }

    public Func<TouchqueGuardContext, string?>? ReferenceId { get; set; }

    /// <summary>For your Touchque Actions only (<c>event.context</c>): roles, plan, amount… Never shown on the phone.</summary>
    public Func<TouchqueGuardContext, IReadOnlyDictionary<string, object?>?>? Context { get; set; }

    /// <summary>
    /// Silent sign-ins (default off): a new attempt whose browser sent its device-bound
    /// key proof (<c>X-Touchque-Browser</c>) first asks Touchque whether anything is new;
    /// if nothing is, the endpoint runs at once with no push.
    /// </summary>
    public SilentSignInOptions? SilentSignIn { get; set; }

    /// <summary>False: never show the first-time linking QR.</summary>
    public bool Enroll { get; set; } = true;

    /// <summary>
    /// Your app's own JSON body for refused answers (status 400 or more: 401, 403, 408, 423,
    /// 429, 500, 503); never called for a 202 step or on approval. What it returns is written
    /// with your app's JSON options (MVC's for <c>[RequireTouchque]</c>). When that gives a JSON
    /// object (an anonymous object, a record, a dictionary, a <c>JsonObject</c>), it is sent with
    /// <c>touchque</c> set to the step, so <c>@touchque/web</c> still sees the state; no token is
    /// added. Anything else (a string, a number, an array, null) is sent as it is. Status and
    /// headers stay the same (<c>Cache-Control: no-store</c>, <c>Retry-After</c>,
    /// <c>X-Touchque-State</c>, <c>X-Touchque-Reason</c>). When it throws, or returns what the
    /// serializer cannot write, the default body is sent and <c>[Touchque] errorBody failed:
    /// &lt;message&gt;</c> is logged. It gets a copy of the step.
    /// </summary>
    public Func<GuardRefusal, object?>? ErrorBody { get; set; }
}

/// <summary>
/// One line per protected endpoint. Until the user approves on their phone this answers
/// <c>202 {"touchque": step, "token": "..."}</c>; your page shows the step in its own
/// design and sends the same request again with header <c>X-Touchque-Token</c>. Once
/// approved the endpoint runs ONCE, with <c>HttpContext.GetTouchqueApproval()</c> set.
/// <code>
/// app.MapPost("/transfer", (Transfer t, HttpContext http) => …)
///    .RequireAuthorization()
///    .RequireTouchque("SEND_MONEY", o => o.Details = c => [("Amount", c.Argument&lt;Transfer&gt;()!.Amount)]);
/// </code>
/// </summary>
public static class RequireTouchqueExtensions
{
    public static TBuilder RequireTouchque<TBuilder>(this TBuilder builder, string action, Action<TouchqueGuardOptions>? configure = null)
        where TBuilder : IEndpointConventionBuilder
    {
        var options = new TouchqueGuardOptions();
        configure?.Invoke(options);
        builder.AddEndpointFilter(async (ctx, next) =>
        {
            var guardContext = new TouchqueGuardContext(ctx.HttpContext, ctx.Arguments.ToList());
            var result = await TouchqueGuardRunner.RunAsync(guardContext, action, options, mvc: false).ConfigureAwait(false);
            return result is null ? await next(ctx).ConfigureAwait(false) : result;
        });
        return builder;
    }
}

/// <summary>
/// The guard for one request. The client is built on the first guarded request and kept (a
/// singleton); while it cannot be built (no API key or secret) the endpoint answers 500
/// <c>misconfigured</c> (401 without a signed-in user) and never runs.
/// </summary>
internal static class TouchqueGuardRunner
{
    /// <summary>Why guarded endpoints answer 500 is logged once per process.</summary>
    private static int _noClientLogged;

    /// <summary>Null: approved, run the endpoint. Otherwise the answer to send. <paramref name="mvc"/>: a controller action.</summary>
    public static async Task<IResult?> RunAsync(TouchqueGuardContext context, string action, TouchqueGuardOptions options, bool mvc)
    {
        var http = context.HttpContext;
        var req = http.Request;
        var input = new GuardInput
        {
            User = options.User is null ? http.User.TouchqueUser() : options.User(context),
            Action = action,
            Details = options.Details?.Invoke(context),
            ReferenceId = options.ReferenceId?.Invoke(context),
            Ip = http.TouchqueClientIp(),
            UserAgent = req.Header("User-Agent"),
            Token = req.Header(Guard.TokenHeader),
            Offline = req.Header(Guard.OfflineHeader) is "1" or "true",
            Code = req.Header(Guard.CodeHeader),
            CodeType = req.Header(Guard.CodeTypeHeader),
            Enroll = options.Enroll,
            BrowserProof = options.SilentSignIn is null ? null : req.Header(Guard.BrowserHeader),
            SilentSignIn = options.SilentSignIn,
            Context = options.Context?.Invoke(context),
        };
        var client = Client(http);
        var result = client is null ? Guard.WithoutClient(input) : await Guard.RunAsync(client, input, http.RequestAborted).ConfigureAwait(false);
        if (result.Approved is not null)
        {
            http.Items[TouchqueHttpContextExtensions.ApprovalKey] = result.Approved;
            return null;
        }
        http.Response.Headers.CacheControl = "no-store";
        if (result.RetryAfter is { } ra) http.Response.Headers.RetryAfter = ra.ToString(System.Globalization.CultureInfo.InvariantCulture);
        foreach (var (name, value) in result.RefusalHeaders) http.Response.Headers[name] = value;
        return Answer(http, result, options.ErrorBody, client, mvc);
    }

    /// <summary>The registered client (built once, then kept). Null while it cannot be built for a setup error (logged once).</summary>
    private static TouchqueClient? Client(HttpContext http)
    {
        try
        {
            return http.RequestServices.GetRequiredService<TouchqueClient>();
        }
        catch (TouchqueConfigException e)
        {
            if (Interlocked.Exchange(ref _noClientLogged, 1) == 0)
            {
                var o = http.RequestServices.GetService<IOptions<TouchqueOptions>>()?.Value ?? new TouchqueOptions();
                Log(http, null).Error(o.KeysMissing()
                    ? "[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured."
                    : "[Touchque] " + e.Message);
            }
            return null;
        }
    }

    /// <summary>The body to send: the guard's, or for a refusal (400 or more) the ErrorBody's when one is set.</summary>
    private static IResult Answer(HttpContext http, GuardResult result, Func<GuardRefusal, object?>? errorBody, TouchqueClient? client, bool mvc)
    {
        var refusal = errorBody is null ? null : GuardRefusal.From(result);
        if (refusal is not null)
        {
            try
            {
                // An object is decided by its JSON encoding with the app's options; what they cannot write falls back below.
                var value = errorBody!(refusal);
                var node = value is null ? null : JsonNode.Parse(JsonSerializer.SerializeToUtf8Bytes(value, value.GetType(), SerializerOptions(http, mvc)));
                if (node is JsonObject o)
                {
                    // The SDK's key wins, so @touchque/web still sees the state: no other spelling of it is left.
                    foreach (var key in o.Select(p => p.Key).Where(k => string.Equals(k, "touchque", StringComparison.OrdinalIgnoreCase)).ToList()) o.Remove(key);
                    o["touchque"] = result.Body!["touchque"]!.DeepClone();
                }
                return node is null ? Results.Text("null", "application/json", Encoding.UTF8, result.Status) : Results.Json(node, statusCode: result.Status);
            }
            catch (Exception e)
            {
                Log(http, client).Error("[Touchque] errorBody failed: " + e.Message);
            }
        }
        return Results.Json(result.Body, statusCode: result.Status);
    }

    /// <summary>The app's JSON options: MVC's for a controller action, else the minimal APIs' ones.</summary>
    private static JsonSerializerOptions SerializerOptions(HttpContext http, bool mvc) =>
        (mvc ? http.RequestServices.GetService<IOptions<MvcJsonOptions>>()?.Value.JsonSerializerOptions : null)
        ?? http.RequestServices.GetService<IOptions<HttpJsonOptions>>()?.Value.SerializerOptions
        ?? new JsonSerializerOptions(JsonSerializerDefaults.Web);

    /// <summary>The SDK's logger: the client's, or without one, the one TouchqueOptions.Logger / Debug set.</summary>
    private static SdkLog Log(HttpContext http, TouchqueClient? client)
    {
        if (client is not null) return client.Log;
        var o = http.RequestServices.GetService<IOptions<TouchqueOptions>>()?.Value;
        return new SdkLog(o?.Logger, o?.Debug ?? false);
    }
}

/// <summary>
/// MVC: <c>[RequireTouchque("SEND_MONEY")]</c> on a controller action. Until the user
/// approves on the phone it answers 202 with the step; once approved the action runs
/// once with <c>HttpContext.GetTouchqueApproval()</c> set. For details, a login user or
/// silent sign-ins, register a named <see cref="TouchqueGuardOptions"/> with
/// <c>services.Configure&lt;TouchqueGuardOptions&gt;("SEND_MONEY", o => …)</c> (the name is the action).
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
public sealed class RequireTouchqueAttribute : Attribute, IAsyncActionFilter
{
    public RequireTouchqueAttribute(string action) => Action = action;

    public string Action { get; }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var options = context.HttpContext.RequestServices.GetService<Microsoft.Extensions.Options.IOptionsMonitor<TouchqueGuardOptions>>()?.Get(Action)
            ?? new TouchqueGuardOptions();
        var guardContext = new TouchqueGuardContext(context.HttpContext, context.ActionArguments.Values.ToList());
        var result = await TouchqueGuardRunner.RunAsync(guardContext, Action, options, mvc: true).ConfigureAwait(false);
        if (result is null)
        {
            await next().ConfigureAwait(false);
            return;
        }
        context.Result = new TouchqueResultAdapter(result);
    }

    private sealed class TouchqueResultAdapter : IActionResult
    {
        private readonly IResult _result;

        public TouchqueResultAdapter(IResult result) => _result = result;

        public Task ExecuteResultAsync(ActionContext context) => _result.ExecuteAsync(context.HttpContext);
    }
}
