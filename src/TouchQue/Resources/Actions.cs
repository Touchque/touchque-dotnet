using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>
/// TouchQue Actions: your own code at points of the approval pipeline (before the
/// push is sent, the silent sign-in decision, after an approval, fraud reports,
/// device and recovery events). TouchQue runs it in a sandbox; this resource
/// deploys, tests, replays and observes it.
/// <code>
/// await tq.Actions.DeployAsync("night-alert", new DeployActionOptions
/// {
///     Trigger = "approval.decided",
///     Template = ActionTemplateRef.Of("alert", new { channel = "slack", when = new { countries = new[] { "TR" } } }),
/// });
/// </code>
/// Action code itself is JavaScript (<c>exports.onExecute = async (event, api) => {...}</c>),
/// whatever language your server is written in.
/// </summary>
public sealed partial class ActionsResource
{
    private readonly TouchQueHttp _http;

    internal ActionsResource(TouchQueHttp http)
    {
        _http = http;
        Secrets = new ActionSecretsResource(http);
    }

    /// <summary>Secrets your Actions read (<c>event.secrets.NAME</c>) or notify with.</summary>
    public ActionSecretsResource Secrets { get; }

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{1,62}$")]
    private static partial Regex SlugRe();

    [GeneratedRegex("^[a-z_]{1,64}$")]
    private static partial Regex TemplateRe();

    /// <summary>
    /// Creates the Action or adds a version and makes it live (idempotent: the same
    /// code and settings change nothing). A version asking for a loosening capability
    /// (skip_number_match, override_block, allow_silent) waits for an admin's phone
    /// approval: then <c>Deployed</c> is false and <c>Approval.Required</c> true.
    /// </summary>
    public Task<ActionDeployResult> DeployAsync(string slug, DeployActionOptions options, CancellationToken ct = default)
    {
        var path = SlugPath(slug);
        if (string.IsNullOrEmpty(options.Code) && options.Template is null)
        {
            throw new TouchQueConfigException("Actions.DeployAsync() needs Code or Template");
        }
        var body = new JsonObject();
        body.Put("trigger", options.Trigger).Put("code", options.Code);
        if (options.Template is not null) body["template"] = options.Template.ToJson();
        body.Put("name", options.Name);
        PutList(body, "secrets", options.Secrets);
        PutList(body, "allowedHosts", options.AllowedHosts);
        PutList(body, "capabilities", options.Capabilities);
        body.Put("onFailure", options.OnFailure).Put("order", options.Order).Put("enabled", options.Enabled).Put("activate", options.Activate);
        return _http.PutAsync<ActionDeployResult>(path, body, ct);
    }

    public async Task<IReadOnlyList<ActionSummary>> ListAsync(CancellationToken ct = default)
    {
        var res = await _http.GetAsync("/actions", null, ct).ConfigureAwait(false);
        return Json.To<List<ActionSummary>>(res?["actions"]) ?? new List<ActionSummary>();
    }

    /// <summary>The Action, the active version's code and its versions.</summary>
    public Task<ActionDetail> GetAsync(string slug, CancellationToken ct = default) =>
        _http.GetAsync<ActionDetail>(SlugPath(slug), null, ct);

    /// <summary>One version, with its code.</summary>
    public async Task<ActionVersion> VersionAsync(string slug, int number, CancellationToken ct = default)
    {
        var res = await _http.GetAsync(SlugPath(slug) + "/versions/" + number.ToString(CultureInfo.InvariantCulture), null, ct).ConfigureAwait(false);
        return Json.To<ActionVersion>(res?["version"] ?? res);
    }

    /// <summary>Rename, turn on or off, reorder, change OnFailure.</summary>
    public async Task<ActionSummary> UpdateAsync(string slug, UpdateActionOptions changes, CancellationToken ct = default)
    {
        var body = new JsonObject();
        body.Put("name", changes.Name).Put("enabled", changes.Enabled).Put("order", changes.Order).Put("onFailure", changes.OnFailure);
        var res = await _http.PatchAsync(SlugPath(slug), body, ct).ConfigureAwait(false);
        return Json.To<ActionSummary>(res?["action"] ?? res);
    }

    public async Task DeleteAsync(string slug, CancellationToken ct = default) =>
        await _http.DeleteAsync(SlugPath(slug), ct).ConfigureAwait(false);

    /// <summary>Back to <paramref name="version"/>, or to the newest runnable version before the active one. Takes effect at once.</summary>
    public Task<ActionRollbackResult> RollbackAsync(string slug, int? version = null, CancellationToken ct = default) =>
        _http.PostAsync<ActionRollbackResult>(SlugPath(slug) + "/rollback", new JsonObject().Put("version", version), ct);

    /// <summary>Runs a draft (or the deployed Action <c>Slug</c>) once on a recorded event, your own event or the trigger's sample. Sends nothing.</summary>
    public Task<ActionTestResult> TestAsync(TestActionOptions options, CancellationToken ct = default)
    {
        var body = DraftJson(options);
        body.Put("eventId", options.EventId);
        if (options.Event is not null) body["event"] = Json.ToNode(options.Event);
        body.Put("network", options.Network);
        return _http.PostAsync<ActionTestResult>("/actions/test", body, ct);
    }

    /// <summary>
    /// Replays a draft against recent real decisions: how many it would have changed
    /// (<c>Changed</c>, <c>Transitions</c> such as <c>push→number_match: 12</c>),
    /// notifications it would have sent, errors and timing. <c>Replaces</c>: the
    /// deployed Action it would replace.
    /// </summary>
    public Task<ActionDryRunResult> DryRunAsync(DryRunActionOptions options, CancellationToken ct = default)
    {
        var body = DraftJson(options);
        body.Put("replaces", options.Replaces).Put("onFailure", options.OnFailure).Put("limit", options.Limit);
        if (options.Since is { } since) body["since"] = since.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        return _http.PostAsync<ActionDryRunResult>("/actions/dry-run", body, ct);
    }

    /// <summary>Recorded events (newest first, kept 30 days); use an id with <see cref="TestAsync"/>.</summary>
    public async Task<IReadOnlyList<RecordedActionEvent>> EventsAsync(string? trigger = null, int? limit = null, CancellationToken ct = default)
    {
        var res = await _http.GetAsync("/actions/events", new Dictionary<string, string?>
        {
            ["trigger"] = trigger,
            ["limit"] = limit?.ToString(CultureInfo.InvariantCulture),
        }, ct).ConfigureAwait(false);
        return Json.To<List<RecordedActionEvent>>(res?["events"]) ?? new List<RecordedActionEvent>();
    }

    /// <summary>Live runs: decision, notifications, console output, errors.</summary>
    public async Task<IReadOnlyList<ActionRun>> LogsAsync(string slug, int? limit = null, DateTimeOffset? before = null, CancellationToken ct = default)
    {
        var res = await _http.GetAsync(SlugPath(slug) + "/logs", new Dictionary<string, string?>
        {
            ["limit"] = limit?.ToString(CultureInfo.InvariantCulture),
            ["before"] = before?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
        }, ct).ConfigureAwait(false);
        return Json.To<List<ActionRun>>(res?["logs"]) ?? new List<ActionRun>();
    }

    /// <summary><paramref name="window"/>: 1h, 24h (default), 7d or 30d.</summary>
    public Task<ActionMetrics> MetricsAsync(string slug, string? window = null, CancellationToken ct = default) =>
        _http.GetAsync<ActionMetrics>(SlugPath(slug) + "/metrics", new Dictionary<string, string?> { ["window"] = window }, ct);

    /// <summary>Every trigger with its decisions, capabilities, notification types and a sample event.</summary>
    public Task<JsonObject> TriggersAsync(CancellationToken ct = default) =>
        _http.GetAsync<JsonObject>("/actions/triggers", null, ct);

    public async Task<IReadOnlyList<ActionTemplateInfo>> TemplatesAsync(CancellationToken ct = default)
    {
        var res = await _http.GetAsync("/actions/templates", null, ct).ConfigureAwait(false);
        return Json.To<List<ActionTemplateInfo>>(res?["templates"]) ?? new List<ActionTemplateInfo>();
    }

    /// <summary>A template as plain code (to read, or to start a code Action from).</summary>
    public Task<RenderedTemplate> RenderTemplateAsync(string id, string trigger, object? parameters = null, CancellationToken ct = default)
    {
        if (!TemplateRe().IsMatch(id)) throw new TouchQueConfigException("Unknown template id");
        var body = new JsonObject { ["trigger"] = trigger, ["params"] = parameters is null ? new JsonObject() : Json.ToNode(parameters) };
        return _http.PostAsync<RenderedTemplate>("/actions/templates/" + id + "/render", body, ct);
    }

    private static string SlugPath(string slug)
    {
        if (!SlugRe().IsMatch(slug))
        {
            throw new TouchQueConfigException("An Action slug is 2-63 lowercase letters, digits or - (e.g. \"night-alert\")");
        }
        return "/actions/" + slug;
    }

    private static JsonObject DraftJson(ActionDraft d)
    {
        var body = new JsonObject();
        body.Put("trigger", d.Trigger).Put("slug", d.Slug).Put("code", d.Code);
        if (d.Template is not null) body["template"] = d.Template.ToJson();
        PutList(body, "secrets", d.Secrets);
        PutList(body, "allowedHosts", d.AllowedHosts);
        PutList(body, "capabilities", d.Capabilities);
        return body;
    }

    private static void PutList(JsonObject body, string key, IEnumerable<string>? values)
    {
        if (values is not null) body[key] = new JsonArray(values.Select(v => (JsonNode)v).ToArray());
    }
}

/// <summary>Secrets your Actions read or notify with. A value is encrypted and never readable again.</summary>
public sealed partial class ActionSecretsResource
{
    private readonly TouchQueHttp _http;

    internal ActionSecretsResource(TouchQueHttp http) => _http = http;

    [GeneratedRegex("^[A-Z][A-Z0-9_]{0,63}$")]
    private static partial Regex NameRe();

    public Task<ActionSecretInfo> SetAsync(string name, string value, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(value)) throw new TouchQueConfigException("A secret value is a non-empty string");
        return SetCoreAsync(Path(name), value, ct);
    }

    private async Task<ActionSecretInfo> SetCoreAsync(string path, string value, CancellationToken ct)
    {
        var res = await _http.PutAsync(path, new JsonObject { ["value"] = value }, ct).ConfigureAwait(false);
        return Json.To<ActionSecretInfo>(res?["secret"] ?? res);
    }

    /// <summary>Names only.</summary>
    public async Task<IReadOnlyList<ActionSecretInfo>> ListAsync(CancellationToken ct = default)
    {
        var res = await _http.GetAsync("/actions/secrets", null, ct).ConfigureAwait(false);
        return Json.To<List<ActionSecretInfo>>(res?["secrets"]) ?? new List<ActionSecretInfo>();
    }

    public async Task DeleteAsync(string name, CancellationToken ct = default) =>
        await _http.DeleteAsync(Path(name), ct).ConfigureAwait(false);

    private static string Path(string name)
    {
        if (!NameRe().IsMatch(name))
        {
            throw new TouchQueConfigException("A secret name is capital letters, digits or _ (e.g. SLACK_WEBHOOK_URL)");
        }
        return "/actions/secrets/" + name;
    }
}

/// <summary>A no-code template and its parameters.</summary>
public sealed record ActionTemplateRef : TouchQueObject
{
    public string Id { get; init; } = "";
    public JsonObject? Params { get; init; }

    /// <summary>A template reference; <paramref name="parameters"/> is any object (anonymous, dictionary, JsonObject).</summary>
    public static ActionTemplateRef Of(string id, object? parameters = null) =>
        new() { Id = id, Params = parameters is null ? null : Json.ToNode(parameters) as JsonObject };

    internal JsonObject ToJson()
    {
        var o = new JsonObject { ["id"] = Id };
        if (Params is not null) o["params"] = Params.DeepClone();
        return o;
    }
}

/// <summary>Code to deploy, test or replay: Code or Template (with Trigger), or Slug for a deployed Action.</summary>
public abstract record ActionDraft
{
    public string? Trigger { get; init; }
    public string? Code { get; init; }
    public ActionTemplateRef? Template { get; init; }
    public string? Slug { get; init; }
    public IReadOnlyList<string>? Secrets { get; init; }
    public IReadOnlyList<string>? AllowedHosts { get; init; }
    /// <summary>Loosening powers (skip_number_match, override_block, allow_silent); each needs an admin's phone approval.</summary>
    public IReadOnlyList<string>? Capabilities { get; init; }
}

/// <summary>Trigger is required for a new Action and cannot change later; Code or Template is required.</summary>
public sealed record DeployActionOptions
{
    public string? Trigger { get; init; }
    public string? Name { get; init; }
    public string? Code { get; init; }
    public ActionTemplateRef? Template { get; init; }
    public IReadOnlyList<string>? Secrets { get; init; }
    public IReadOnlyList<string>? AllowedHosts { get; init; }
    public IReadOnlyList<string>? Capabilities { get; init; }
    /// <summary>Pre triggers: <c>continue</c> (default, never blocks), <c>step_up</c> or <c>deny</c>.</summary>
    public string? OnFailure { get; init; }
    public int? Order { get; init; }
    public bool? Enabled { get; init; }
    /// <summary>False saves the version without making it live.</summary>
    public bool? Activate { get; init; }
}

/// <summary>Null fields are left as they are.</summary>
public sealed record UpdateActionOptions
{
    public string? Name { get; init; }
    public bool? Enabled { get; init; }
    public int? Order { get; init; }
    public string? OnFailure { get; init; }
}

public sealed record TestActionOptions : ActionDraft
{
    /// <summary>A recorded event (<see cref="ActionsResource.EventsAsync"/>).</summary>
    public string? EventId { get; init; }
    /// <summary>Your own event, merged over the trigger's sample.</summary>
    public object? Event { get; init; }
    /// <summary>False turns <c>api.fetch</c> off.</summary>
    public bool? Network { get; init; }
}

public sealed record DryRunActionOptions : ActionDraft
{
    /// <summary>The deployed Action this draft would replace.</summary>
    public string? Replaces { get; init; }
    public string? OnFailure { get; init; }
    /// <summary>How many recent events (1-1000; the API's default is 500).</summary>
    public int? Limit { get; init; }
    public DateTimeOffset? Since { get; init; }
}

public sealed record ActionSummary : TouchQueObject
{
    public string Slug { get; init; } = "";
    public string? Name { get; init; }
    public string? Trigger { get; init; }
    public bool Enabled { get; init; }
    public int Order { get; init; }
    public string? OnFailure { get; init; }
    public int? ActiveVersion { get; init; }
    public int? PendingApproval { get; init; }
    public string? CreatedAt { get; init; }
    public string? UpdatedAt { get; init; }
}

public sealed record ActionVersion : TouchQueObject
{
    public int Number { get; init; }
    /// <summary>ready, pending_approval or rejected.</summary>
    public string Status { get; init; } = "";
    public bool Active { get; init; }
    public IReadOnlyList<string>? Capabilities { get; init; }
    public IReadOnlyList<string>? ApprovedCapabilities { get; init; }
    public IReadOnlyList<string>? AllowedHosts { get; init; }
    public IReadOnlyList<string>? Secrets { get; init; }
    public ActionTemplateRef? Template { get; init; }
    public string? CodeHash { get; init; }
    public string? Code { get; init; }
    public string? CreatedAt { get; init; }
    public string? CreatedBy { get; init; }
    public string? ApprovedAt { get; init; }
}

/// <summary>Set when a version loosens security and waits for an admin's phone approval.</summary>
public sealed record ActionApproval : TouchQueObject
{
    public bool Required { get; init; }
    public IReadOnlyList<string>? Capabilities { get; init; }
    public string? Message { get; init; }
}

public sealed record ActionDeployResult : TouchQueObject
{
    public ActionSummary Action { get; init; } = new();
    public ActionVersion Version { get; init; } = new();
    /// <summary>This version runs now.</summary>
    public bool Deployed { get; init; }
    public ActionApproval? Approval { get; init; }
    public IReadOnlyList<string>? Warnings { get; init; }
}

public sealed record ActionDetail : TouchQueObject
{
    public ActionSummary Action { get; init; } = new();
    public string? Code { get; init; }
    public IReadOnlyList<ActionVersion> Versions { get; init; } = Array.Empty<ActionVersion>();
}

public sealed record ActionRollbackResult : TouchQueObject
{
    public ActionSummary Action { get; init; } = new();
    public ActionVersion Version { get; init; } = new();
}

/// <summary>One decision call an Action made (deny, stepUp…).</summary>
public sealed record ActionCall : TouchQueObject
{
    public string Kind { get; init; } = "";
    public string? Reason { get; init; }
}

public sealed record ActionLogLine : TouchQueObject
{
    public string Level { get; init; } = "";
    public string Message { get; init; } = "";
    public long At { get; init; }
}

public sealed record ActionTestResult : TouchQueObject
{
    /// <summary>ok, error or timeout.</summary>
    public string Outcome { get; init; } = "";
    public string? Error { get; init; }
    public int DurationMs { get; init; }
    public double CpuMs { get; init; }
    public IReadOnlyList<ActionCall>? Calls { get; init; }
    public JsonArray? Notifications { get; init; }
    public IReadOnlyList<ActionLogLine>? Logs { get; init; }
    public IReadOnlyList<RiskReason>? Reasons { get; init; }
    public JsonObject? WouldBe { get; init; }
    public string? EventId { get; init; }
    public JsonObject? Event { get; init; }
    public IReadOnlyList<string>? AssumedCapabilities { get; init; }
}

public sealed record ActionDryRunResult : TouchQueObject
{
    public string? Trigger { get; init; }
    public int Evaluated { get; init; }
    public string? From { get; init; }
    public string? To { get; init; }
    public int Matched { get; init; }
    public int? Changed { get; init; }
    public Dictionary<string, int>? Transitions { get; init; }
    public Dictionary<string, int>? Notifications { get; init; }
    public int Errors { get; init; }
    public int Timeouts { get; init; }
    public JsonArray? ErrorSamples { get; init; }
    public int P50Ms { get; init; }
    public int P95Ms { get; init; }
    public JsonArray? Samples { get; init; }
    public IReadOnlyList<string>? AssumedCapabilities { get; init; }
}

public sealed record RecordedActionEvent : TouchQueObject
{
    public string Id { get; init; } = "";
    public string? Trigger { get; init; }
    public string? Time { get; init; }
    public string? User { get; init; }
    public string? RequestId { get; init; }
    public JsonObject? Outcome { get; init; }
    public JsonObject? Event { get; init; }
}

public sealed record ActionRun : TouchQueObject
{
    public string Id { get; init; } = "";
    public string? Time { get; init; }
    public int? Version { get; init; }
    public string? EventId { get; init; }
    public string? RequestId { get; init; }
    public string? Outcome { get; init; }
    public string? Decision { get; init; }
    public IReadOnlyList<ActionCall>? Calls { get; init; }
    public JsonArray? Notifications { get; init; }
    public IReadOnlyList<ActionLogLine>? Logs { get; init; }
    public string? Error { get; init; }
    public int DurationMs { get; init; }
}

public sealed record ActionMetrics : TouchQueObject
{
    public string? Window { get; init; }
    public int Runs { get; init; }
    public int Errors { get; init; }
    public int Timeouts { get; init; }
    public double ErrorRate { get; init; }
    public int P50Ms { get; init; }
    public int P95Ms { get; init; }
    public Dictionary<string, int>? Decisions { get; init; }
    public Dictionary<string, int>? Notifications { get; init; }
}

public sealed record ActionTemplateInfo : TouchQueObject
{
    public string Id { get; init; } = "";
    public string? Name { get; init; }
    public string? Description { get; init; }
    public IReadOnlyList<string>? Triggers { get; init; }
    public JsonObject? Params { get; init; }
}

public sealed record RenderedTemplate : TouchQueObject
{
    public string Code { get; init; } = "";
    public IReadOnlyList<string>? Secrets { get; init; }
    public IReadOnlyList<string>? AllowedHosts { get; init; }
    public IReadOnlyList<string>? Capabilities { get; init; }
}

public sealed record ActionSecretInfo : TouchQueObject
{
    public string Name { get; init; } = "";
    public string? CreatedAt { get; init; }
    public string? UpdatedAt { get; init; }
}
