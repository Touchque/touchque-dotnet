using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;

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
            var result = await TouchqueGuardRunner.RunAsync(guardContext, action, options).ConfigureAwait(false);
            return result is null ? await next(ctx).ConfigureAwait(false) : result;
        });
        return builder;
    }
}

internal static class TouchqueGuardRunner
{
    /// <summary>Null: approved, run the endpoint. Otherwise the answer to send.</summary>
    public static async Task<IResult?> RunAsync(TouchqueGuardContext context, string action, TouchqueGuardOptions options)
    {
        var http = context.HttpContext;
        var client = http.RequestServices.GetRequiredService<TouchqueClient>();
        var req = http.Request;
        var result = await Guard.RunAsync(client, new GuardInput
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
        }, http.RequestAborted).ConfigureAwait(false);
        if (result.Approved is not null)
        {
            http.Items[TouchqueHttpContextExtensions.ApprovalKey] = result.Approved;
            return null;
        }
        http.Response.Headers.CacheControl = "no-store";
        if (result.RetryAfter is { } ra) http.Response.Headers.RetryAfter = ra.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return Results.Json(result.Body, statusCode: result.Status);
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
        var result = await TouchqueGuardRunner.RunAsync(guardContext, Action, options).ConfigureAwait(false);
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
