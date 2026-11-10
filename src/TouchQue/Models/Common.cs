using System.Text.Json;
using System.Text.Json.Serialization;

namespace TouchQue;

/// <summary>
/// Base of the SDK's answer types. Fields TouchQue adds later (and fields this
/// type does not name) are kept in <see cref="Extra"/>.
/// </summary>
public abstract record TouchQueObject
{
    /// <summary>Fields of the answer that this type does not name.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>
/// One line of transaction context on the approval screen, e.g. <c>("Amount", "1,250.00 USD")</c>.
/// Shown in order. At most 8 lines, labels up to 40 and values up to 120
/// characters; the API rejects (never truncates) anything longer. Build them
/// from server-side state, never from browser input.
/// </summary>
public sealed record LoginDetail(string Label, string Value)
{
    public static implicit operator LoginDetail((string Label, string Value) pair) => new(pair.Label, pair.Value);

    /// <summary>Lines from a dictionary, in its enumeration order.</summary>
    public static IReadOnlyList<LoginDetail> From(IEnumerable<KeyValuePair<string, string>> pairs) =>
        pairs.Select(p => new LoginDetail(p.Key, p.Value)).ToList();
}

/// <summary>A reason code and its English text (number matching, silent sign-ins, "Why?").</summary>
public sealed record RiskReason : TouchQueObject
{
    public string Code { get; init; } = "";
    public string Text { get; init; } = "";
    /// <summary>What to do about it, when TouchQue says.</summary>
    public string? Action { get; init; }
}

/// <summary>How strongly an approval was made.</summary>
public sealed record Assurance : TouchQueObject
{
    /// <summary>True for a passkey.</summary>
    public bool PhishingResistant { get; init; }

    /// <summary><c>push</c>, <c>passkey</c>, <c>offline_code</c>, <c>offline_totp</c> or <c>silent</c>.</summary>
    public string Method { get; init; } = "";
}

/// <summary>Mirror Alarm: a tiny image your sign-in page loads, so a phishing proxy in front of your site gets the approval refused.</summary>
public sealed record Canary : TouchQueObject
{
    public string Url { get; init; } = "";
}

/// <summary>Where an action sends money or value; the phone shows it in full, grouped by four.</summary>
public sealed record Destination
{
    /// <summary><c>iban</c>, <c>account</c>, <c>wallet</c>, <c>address</c> or <c>payee</c>.</summary>
    public required string Kind { get; init; }
    public required string Value { get; init; }
    /// <summary>Destinations this user used before: a look-alike of one is flagged on the phone.</summary>
    public IReadOnlyList<string>? Known { get; init; }
}

public sealed record DestinationLookalike : TouchQueObject
{
    public string Field { get; init; } = "";
    public string Reason { get; init; } = "";
    public string? SimilarTo { get; init; }
}

/// <summary>What TouchQue made of a <see cref="Destination"/>.</summary>
public sealed record DestinationCheck : TouchQueObject
{
    public bool Known { get; init; }
    public IReadOnlyList<DestinationLookalike> Lookalike { get; init; } = Array.Empty<DestinationLookalike>();
}

/// <summary>When the user's sign-in security last changed in your system (access rules read <c>minutesSince.*</c>).</summary>
public sealed record SecurityChanges
{
    public DateTimeOffset? Password { get; init; }
    public DateTimeOffset? Mfa { get; init; }
    public DateTimeOffset? Device { get; init; }
    public DateTimeOffset? Email { get; init; }
    public DateTimeOffset? Phone { get; init; }

    internal System.Text.Json.Nodes.JsonObject? ToJson()
    {
        var o = new System.Text.Json.Nodes.JsonObject();
        void Add(string key, DateTimeOffset? at)
        {
            if (at is { } v) o[key] = v.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture);
        }
        Add("password", Password);
        Add("mfa", Mfa);
        Add("device", Device);
        Add("email", Email);
        Add("phone", Phone);
        return o.Count == 0 ? null : o;
    }
}
