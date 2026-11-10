using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;

namespace TouchQue.AspNetCore;

/// <summary>What a guard callback sees: the request and, on a minimal API endpoint, its bound arguments.</summary>
public sealed class TouchQueGuardContext
{
    internal TouchQueGuardContext(HttpContext httpContext, IReadOnlyList<object?> arguments)
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

/// <summary>Options of <c>RequireTouchQue</c>.</summary>
public sealed class TouchQueGuardOptions
{
    /// <summary>Who approves (default: the signed-in user's email, else sub, else name). For a login route, return whoever just passed your password check.</summary>
    public Func<TouchQueGuardContext, string?>? User { get; set; }

    /// <summary>Transaction details shown on the phone. Build them from server-side state or validated input.</summary>
    public Func<TouchQueGuardContext, IReadOnlyList<LoginDetail>?>? Details { get; set; }

    public Func<TouchQueGuardContext, string?>? ReferenceId { get; set; }

    /// <summary>For your TouchQue Actions only (<c>event.context</c>): roles, plan, amount… Never shown on the phone.</summary>
    public Func<TouchQueGuardContext, IReadOnlyDictionary<string, object?>?>? Context { get; set; }

    /// <summary>
    /// Silent sign-ins (default off): a new attempt whose browser sent its device-bound
    /// key proof (<c>X-TouchQue-Browser</c>) first asks TouchQue whether anything is new;
    /// if nothing is, the endpoint runs at once with no push.
    /// </summary>
    public SilentSignInOptions? SilentSignIn { get; set; }

    /// <summary>False: never show the first-time linking QR.</summary>
    public bool Enroll { get; set; } = true;
}

/// <summary>
/// One line per protected endpoint. Until the user approves on their phone this answers
/// <c>202 {"touchque": step, "token": "..."}</c>; your page shows the step in its own
/// design and sends the same request again with header <c>X-TouchQue-Token</c>. Once
/// approved the endpoint runs ONCE, with <c>HttpContext.GetTouchQueApproval()</c> set.
/// <code>
/// app.MapPost("/transfer", (Transfer t, HttpContext http) => …)
///    .RequireAuthorization()
///    .RequireTouchQue("SEND_MONEY", o => o.Details = c => [("Amount", c.Argument&lt;Transfer&gt;()!.Amount)]);
/// </code>
/// </summary>
public static class RequireTouchQueExtensions
{
    public static TBuilder RequireTouchQue<TBuilder>(this TBuilder builder, string action, Action<TouchQueGuardOptions>? configure = null)
        where TBuilder : IEndpointConventionBuilder
    {
        var options = new TouchQueGuardOptions();
        configure?.Invoke(options);
        builder.AddEndpointFilter(async (ctx, next) =>
        {
            var guardContext = new TouchQueGuardContext(ctx.HttpContext, ctx.Arguments.ToList());
            var result = await TouchQueGuardRunner.RunAsync(guardContext, action, options).ConfigureAwait(false);
            return result is null ? await next(ctx).ConfigureAwait(false) : result;
        });
        return builder;
    }
}

internal static class TouchQueGuardRunner
{
    /// <summary>Null: approved, run the endpoint. Otherwise the answer to send.</summary>
    public static async Task<IResult?> RunAsync(TouchQueGuardContext context, string action, TouchQueGuardOptions options)
    {
        var http = context.HttpContext;
        var client = http.RequestServices.GetRequiredService<TouchQueClient>();
        var req = http.Request;
        var result = await Guard.RunAsync(client, new GuardInput
        {
            User = options.User is null ? http.User.TouchQueUser() : options.User(context),
            Action = action,
            Details = options.Details?.Invoke(context),
            ReferenceId = options.ReferenceId?.Invoke(context),
            Ip = http.TouchQueClientIp(),
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
            http.Items[TouchQueHttpContextExtensions.ApprovalKey] = result.Approved;
            return null;
        }
        http.Response.Headers.CacheControl = "no-store";
        if (result.RetryAfter is { } ra) http.Response.Headers.RetryAfter = ra.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return Results.Json(result.Body, statusCode: result.Status);
    }
}

/// <summary>
/// MVC: <c>[RequireTouchQue("SEND_MONEY")]</c> on a controller action. Until the user
/// approves on the phone it answers 202 with the step; once approved the action runs
/// once with <c>HttpContext.GetTouchQueApproval()</c> set. For details, a login user or
/// silent sign-ins, register a named <see cref="TouchQueGuardOptions"/> with
/// <c>services.Configure&lt;TouchQueGuardOptions&gt;("SEND_MONEY", o => …)</c> (the name is the action).
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
public sealed class RequireTouchQueAttribute : Attribute, IAsyncActionFilter
{
    public RequireTouchQueAttribute(string action) => Action = action;

    public string Action { get; }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var options = context.HttpContext.RequestServices.GetService<Microsoft.Extensions.Options.IOptionsMonitor<TouchQueGuardOptions>>()?.Get(Action)
            ?? new TouchQueGuardOptions();
        var guardContext = new TouchQueGuardContext(context.HttpContext, context.ActionArguments.Values.ToList());
        var result = await TouchQueGuardRunner.RunAsync(guardContext, Action, options).ConfigureAwait(false);
        if (result is null)
        {
            await next().ConfigureAwait(false);
            return;
        }
        context.Result = new TouchQueResultAdapter(result);
    }

    private sealed class TouchQueResultAdapter : IActionResult
    {
        private readonly IResult _result;

        public TouchQueResultAdapter(IResult result) => _result = result;

        public Task ExecuteResultAsync(ActionContext context) => _result.ExecuteAsync(context.HttpContext);
    }
}
