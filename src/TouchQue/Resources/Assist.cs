using System.Text.Json.Nodes;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>
/// Help desk: IT working on a person's account in the open.
/// <list type="number">
/// <item>Before your help desk acts on someone's account: <see cref="OpenAsync"/> with the person and the
/// signed-in agent. The person's phone gets a calm notice; while the session is open their
/// "someone says they're from IT" button shows this agent, and with none open it tells them to
/// hang up (webhook ASSIST_CLAIM_UNVERIFIED).</item>
/// <item>Before a sensitive action (a factor or password reset, an activation or recovery link, an
/// unlock, a new phone, removing a passkey): <see cref="VerifyAsync"/>. Show <c>ChallengeCode</c> to the
/// agent only; they read it to the person, who types it on their phone. Default deny.</item>
/// <item>Right before the action: <see cref="SpendAsync"/> (a passed check, for that action, at most ten
/// minutes old, once). <see cref="UnfreezeAsync"/> lifts a freeze the same way.</item>
/// </list>
/// No phone (code <c>no_phone</c>, route <c>never_locked_out</c>): the person moves to a new phone with
/// Never Locked Out; the help desk cannot.
/// </summary>
public sealed class AssistResource
{
    private readonly TouchQueHttp _http;

    internal AssistResource(TouchQueHttp http) => _http = http;

    /// <summary>Starts helping a person. A session of the same agent for the same person is replaced.</summary>
    public Task<AssistSession> OpenAsync(OpenAssistOptions options, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(options.ExternalUsername) || string.IsNullOrEmpty(options.Agent?.Name))
        {
            throw new TouchQueConfigException("Assist.OpenAsync() needs ExternalUsername and Agent.Name");
        }
        var agent = new JsonObject { ["name"] = options.Agent.Name }.Put("title", options.Agent.Title).Put("ref", options.Agent.Ref);
        var body = new JsonObject { ["externalUsername"] = options.ExternalUsername, ["agent"] = agent };
        body.Put("reason", options.Reason).Put("ttlMinutes", options.TtlMinutes);
        if (!options.Notify) body["notify"] = false;
        return _http.PostAsync<AssistSession>("/assist", body, ct);
    }

    /// <summary>The session and its checks. Poll it while a check is pending.</summary>
    public Task<AssistSession> GetAsync(string id, CancellationToken ct = default)
    {
        Require("GetAsync", "the session id", id);
        return _http.GetAsync<AssistSession>(Path(id), null, ct);
    }

    /// <summary>A person's sessions, or every open one, newest first.</summary>
    public async Task<IReadOnlyList<AssistSession>> ListAsync(string? externalUsername = null, bool open = false, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(externalUsername) && !open) throw new TouchQueConfigException("Assist.ListAsync() needs externalUsername or open: true");
        var res = await _http.GetAsync("/assist", new Dictionary<string, string?>
        {
            ["externalUsername"] = string.IsNullOrEmpty(externalUsername) ? null : externalUsername,
            ["open"] = open ? "true" : null,
        }, ct).ConfigureAwait(false);
        return Json.To<List<AssistSession>>(res?["sessions"]) ?? new List<AssistSession>();
    }

    /// <summary>
    /// Asks the person's phone to confirm <paramref name="action"/> (reset_2fa, reset_password,
    /// activation_link, recovery_link, unlock, new_phone, remove_passkey or your own).
    /// <c>ChallengeCode</c> is for the agent only. Throws <see cref="TouchQueApiException"/>
    /// no_phone, assist_not_open or rate_limited.
    /// </summary>
    public Task<AssistCheckStarted> VerifyAsync(string id, string action, string? actionText = null, IReadOnlyList<LoginDetail>? details = null, CancellationToken ct = default)
    {
        Require("VerifyAsync", "the session id and an action", id, action);
        var body = new JsonObject { ["action"] = action }.Put("actionText", actionText);
        if (details is { Count: > 0 }) body["details"] = LoginRequestOptions.DetailsJson(details);
        return _http.PostAsync<AssistCheckStarted>(Path(id, "/verify"), body, ct);
    }

    /// <summary>Uses a passed check for its action, right before you take it; check_required (428) otherwise.</summary>
    public Task<AssistSession> SpendAsync(string id, string requestId, string action, CancellationToken ct = default)
    {
        Require("SpendAsync", "the session id, requestId and action", id, requestId, action);
        return _http.PostAsync<AssistSession>(Path(id, "/spend"), new JsonObject { ["requestId"] = requestId, ["action"] = action }, ct);
    }

    /// <summary>Lifts the person's approval freeze with a passed check for <c>unlock</c>.</summary>
    public Task<AssistUnfreezeResult> UnfreezeAsync(string id, string requestId, CancellationToken ct = default)
    {
        Require("UnfreezeAsync", "the session id and requestId", id, requestId);
        return _http.PostAsync<AssistUnfreezeResult>(Path(id, "/unfreeze"), new JsonObject { ["requestId"] = requestId }, ct);
    }

    /// <summary>Stops helping; checks still waiting on the phone expire.</summary>
    public Task<AssistSession> EndAsync(string id, string? by = null, string? reason = null, CancellationToken ct = default)
    {
        Require("EndAsync", "the session id", id);
        return _http.PostAsync<AssistSession>(Path(id, "/end"), new JsonObject().Put("by", by).Put("reason", reason), ct);
    }

    private static string Path(string id, string rest = "") => "/assist/" + TouchQueHttp.Seg(id) + rest;

    private static void Require(string method, string what, params string?[] values)
    {
        if (values.Any(string.IsNullOrEmpty)) throw new TouchQueConfigException($"Assist.{method}() needs {what}");
    }
}

public sealed record AssistAgent
{
    /// <summary>Your id for the help-desk agent.</summary>
    public string? Ref { get; init; }
    public string Name { get; init; } = "";
    public string? Title { get; init; }
}

public sealed record OpenAssistOptions
{
    public required string ExternalUsername { get; init; }
    public required AssistAgent Agent { get; init; }
    public string? Reason { get; init; }
    /// <summary>5-120 minutes (default 30).</summary>
    public int? TtlMinutes { get; init; }
    /// <summary>False: no notice on the person's phone.</summary>
    public bool Notify { get; init; } = true;
}

public sealed record AssistCheck : TouchQueObject
{
    public string RequestId { get; init; } = "";
    public string Action { get; init; } = "";
    public string? ActionText { get; init; }
    /// <summary>pending, verified, wrong_number, not_me, coached, declined, expired.</summary>
    public string Outcome { get; init; } = "";
    public string? CreatedAt { get; init; }
    public string? SpentAt { get; init; }
    public string? ExpiresAt { get; init; }
}

public sealed record AssistAgentInfo : TouchQueObject
{
    public string? Ref { get; init; }
    public string Name { get; init; } = "";
    public string? Title { get; init; }
}

public sealed record AssistSession : TouchQueObject
{
    public string Id { get; init; } = "";
    public string ExternalUsername { get; init; } = "";
    /// <summary>OPEN until ended, expired or replaced.</summary>
    public string Status { get; init; } = "";
    public AssistAgentInfo? Agent { get; init; }
    public string? Reason { get; init; }
    public bool Notified { get; init; }
    public string? OpenedAt { get; init; }
    public string? ExpiresAt { get; init; }
    public string? EndedAt { get; init; }
    public string? EndedReason { get; init; }
    /// <summary>False: the person has no working TouchQue phone to check on (Never Locked Out).</summary>
    public bool Phone { get; init; }
    public bool Frozen { get; init; }
    public IReadOnlyList<AssistCheck> Checks { get; init; } = Array.Empty<AssistCheck>();

    /// <summary>The check of <paramref name="requestId"/> passed on the person's phone and was not used yet.</summary>
    public bool CheckPassed(string requestId)
    {
        var check = Checks.FirstOrDefault(c => c.RequestId == requestId);
        return check is not null && check.Outcome == "verified" && check.SpentAt is null;
    }
}

/// <summary>The number to show the agent only.</summary>
public sealed record AssistCheckStarted : TouchQueObject
{
    public string RequestId { get; init; } = "";
    public string ChallengeCode { get; init; } = "";
    public string? ExpiresAt { get; init; }
    public string? Action { get; init; }
}

public sealed record AssistUnfreezeResult : TouchQueObject
{
    public bool Unfrozen { get; init; }
    public AssistSession? Session { get; init; }
}
