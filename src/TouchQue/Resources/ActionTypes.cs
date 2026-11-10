using System.Text.Json.Nodes;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>
/// Action types (LOGIN, SEND_MONEY…): what a user is asked to approve. Define them
/// from code at start-up instead of clicking them into the dashboard.
/// </summary>
public sealed class ActionTypesResource
{
    /// <summary>The Second Thought questions an action type can ask (at most two).</summary>
    public static readonly IReadOnlyList<string> SecondThoughtQuestions = new[]
    {
        "someone_guiding", "safe_account", "remote_access", "asked_for_code", "support_call",
        "met_online", "promised_return", "know_recipient", "sim_in_hand",
    };

    private readonly TouchQueHttp _http;

    internal ActionTypesResource(TouchQueHttp http) => _http = http;

    /// <summary>
    /// Creates the action type, or updates its name, description, critical flag and
    /// Second Thought questions. Safe on every start-up: it never re-enables a type an
    /// admin disabled. <paramref name="secondThought"/>: at most two of
    /// <see cref="SecondThoughtQuestions"/>, asked on the phone before Approve (a
    /// risky answer makes the approval provisional); an empty list turns them off,
    /// null keeps what the dashboard has.
    /// </summary>
    public Task<ActionTypeInfo> DefineAsync(string type, string? name = null, string? description = null, bool? critical = null, SecondThought? secondThought = null, CancellationToken ct = default)
    {
        var body = new JsonObject { ["type"] = type, ["name"] = name ?? type };
        if (description is not null) body["description"] = description;
        body.Put("critical", critical);
        if (secondThought is not null) body["secondThought"] = Json.ToNode(secondThought);
        return _http.PostAsync<ActionTypeInfo>("/action-types", body, ct);
    }

    public Task<List<ActionTypeInfo>> ListAsync(CancellationToken ct = default) =>
        _http.GetAsync<List<ActionTypeInfo>>("/action-types", null, ct);
}

/// <summary>Second Thought questions of an action type.</summary>
public sealed record SecondThought
{
    public IReadOnlyList<string> Questions { get; init; } = Array.Empty<string>();
    /// <summary><c>tr</c> or <c>en</c>.</summary>
    public string? Locale { get; init; }
}

public sealed record ActionTypeInfo : TouchQueObject
{
    public string? Id { get; init; }
    public string Type { get; init; } = "";
    public string? Name { get; init; }
    public string? Description { get; init; }
    public bool Critical { get; init; }
    public bool? Active { get; init; }
    public SecondThought? SecondThought { get; init; }
}
