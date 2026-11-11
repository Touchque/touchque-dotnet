using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>
/// An A2A agent card that did not verify. <see cref="Error"/> is unsigned, malformed,
/// untrusted_key, invalid_signature or keys_unavailable.
/// </summary>
public class TouchqueAgentCardException : TouchqueException
{
    public TouchqueAgentCardException(string error, string message) : base(message) => Error = error;

    public string Error { get; }
}

/// <summary>Settings of <see cref="AgentCard.VerifyAsync"/>.</summary>
public sealed record AgentCardVerifyOptions
{
    /// <summary>Where the card was fetched from: its host is the one jku may point at.</summary>
    public string? CardUrl { get; init; }
    /// <summary>JWKs you trust for this agent; checked before any jku.</summary>
    public IReadOnlyList<JsonObject>? Keys { get; init; }
    /// <summary>Other hosts a jku may point at (e.g. the publisher's key host).</summary>
    public IReadOnlyList<string>? TrustedJkuHosts { get; init; }
    /// <summary>For tests: how JSON documents are fetched.</summary>
    public Func<string, CancellationToken, Task<JsonObject>>? Fetch { get; init; }
}

/// <summary>The signature that verified; KeySource is "keys" or "jku".</summary>
public sealed record AgentCardVerification(string Kid, string Alg, string KeySource);

/// <summary>
/// A2A agent card signatures (A2A 1.0 §8.4): before your agent trusts another agent's
/// card (its name, URL, skills), check that whoever controls its keys signed exactly
/// this card. Each entry of <c>signatures</c> is a JWS (RFC 7515) over the card in RFC
/// 8785 canonical form without <c>signatures</c>; the protected header names alg, kid
/// and optionally jku (where the keys are). Keys come from <c>Keys</c> or from the
/// header's jku, but jku is only followed on the card's own host (or a host in
/// <c>TrustedJkuHosts</c>): a card that points at keys on a host of its choosing proves
/// nothing. Signers must leave out fields at their default values (A2A §8.4.1); the
/// card is checked as received.
/// <code>
/// var json = await http.GetStringAsync("https://agent.example/.well-known/agent-card.json");
/// await AgentCard.VerifyAsync(json, new() { CardUrl = "https://agent.example/.well-known/agent-card.json" });
/// </code>
/// </summary>
public static class AgentCard
{
    private static readonly string[] Algs = { "RS256", "ES256", "EdDSA" };

    /// <summary>A number as ECMAScript's Number::toString writes it (RFC 8785 §3.2.2.3).</summary>
    public static string EsNumber(double value)
    {
        if (double.IsNaN(value) || double.IsInfinity(value)) throw new TouchqueAgentCardException("malformed", "a number is not finite");
        if (value == 0) return "0";
        var sign = value < 0 ? "-" : "";
        var text = Math.Abs(value).ToString("R", CultureInfo.InvariantCulture);
        var e = text.IndexOfAny(new[] { 'E', 'e' });
        var mantissa = e < 0 ? text : text[..e];
        var exp = e < 0 ? 0 : int.Parse(text[(e + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
        var dot = mantissa.IndexOf('.');
        var intPart = dot < 0 ? mantissa : mantissa[..dot];
        var digits = intPart + (dot < 0 ? "" : mantissa[(dot + 1)..]);
        var n = intPart.Length + exp;
        var trimmed = digits.TrimStart('0');
        n -= digits.Length - trimmed.Length;
        digits = trimmed.TrimEnd('0');
        var k = digits.Length;
        string outText;
        if (k <= n && n <= 21) outText = digits + new string('0', n - k);
        else if (0 < n && n <= 21) outText = digits[..n] + "." + digits[n..];
        else if (-6 < n && n <= 0) outText = "0." + new string('0', -n) + digits;
        else
        {
            var x = n - 1;
            outText = digits[..1] + (k > 1 ? "." + digits[1..] : "") + "e" + (x >= 0 ? "+" : "-") + Math.Abs(x).ToString(CultureInfo.InvariantCulture);
        }
        return sign + outText;
    }

    private static void WriteString(StringBuilder b, string s)
    {
        b.Append('"');
        foreach (var ch in s)
        {
            switch (ch)
            {
                case '"': b.Append("\\\""); break;
                case '\\': b.Append("\\\\"); break;
                case '\b': b.Append("\\b"); break;
                case '\f': b.Append("\\f"); break;
                case '\n': b.Append("\\n"); break;
                case '\r': b.Append("\\r"); break;
                case '\t': b.Append("\\t"); break;
                default:
                    if (ch < 0x20) b.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                    else b.Append(ch);
                    break;
            }
        }
        b.Append('"');
    }

    private static void Write(StringBuilder b, JsonNode? node)
    {
        switch (node)
        {
            case null:
                b.Append("null");
                break;
            case JsonObject o:
                b.Append('{');
                var first = true;
                foreach (var key in o.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal))
                {
                    if (!first) b.Append(',');
                    first = false;
                    WriteString(b, key);
                    b.Append(':');
                    Write(b, o[key]);
                }
                b.Append('}');
                break;
            case JsonArray a:
                b.Append('[');
                for (var i = 0; i < a.Count; i++)
                {
                    if (i > 0) b.Append(',');
                    Write(b, a[i]);
                }
                b.Append(']');
                break;
            default:
                switch (node.GetValueKind())
                {
                    case JsonValueKind.String: WriteString(b, node.GetValue<string>()); break;
                    case JsonValueKind.True: b.Append("true"); break;
                    case JsonValueKind.False: b.Append("false"); break;
                    case JsonValueKind.Null: b.Append("null"); break;
                    case JsonValueKind.Number:
                        b.Append(EsNumber(double.Parse(node.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture)));
                        break;
                    default: throw new TouchqueAgentCardException("malformed", "cannot canonicalize this value");
                }
                break;
        }
    }

    /// <summary>RFC 8785 (JSON Canonicalization Scheme): sorted keys (UTF-16 order), no whitespace, ECMAScript numbers.</summary>
    public static string CanonicalJson(JsonNode? node)
    {
        var b = new StringBuilder();
        Write(b, node);
        return b.ToString();
    }

    private static JsonObject Decode(string cardJson)
    {
        try
        {
            return JsonNode.Parse(cardJson) as JsonObject ?? throw new TouchqueAgentCardException("malformed", "the card is not a JSON object");
        }
        catch (JsonException)
        {
            throw new TouchqueAgentCardException("malformed", "the card is not JSON");
        }
    }

    private static string Payload(JsonObject card)
    {
        var rest = new JsonObject();
        foreach (var (k, v) in card)
        {
            if (k != "signatures") rest[k] = v?.DeepClone();
        }
        return Base64Url.Encode(CanonicalJson(rest));
    }

    private static string? HostOf(string? url) =>
        CrossAppAccess.SafeUrl(url) ? new Uri(url!).Authority : null;

    /// <summary>Checks the card's signatures (pass the raw JSON you received): the one that verified, or <see cref="TouchqueAgentCardException"/>.</summary>
    public static async Task<AgentCardVerification> VerifyAsync(string cardJson, AgentCardVerifyOptions? options = null, CancellationToken ct = default)
    {
        options ??= new AgentCardVerifyOptions();
        var c = Decode(cardJson);
        if (c["signatures"] is not JsonArray sigs || sigs.Count == 0) throw new TouchqueAgentCardException("unsigned", "the card has no signatures");
        var fetch = options.Fetch ?? CrossAppAccess.GetJsonAsync;
        var cardHost = HostOf(options.CardUrl);
        var payload = Payload(c);
        var last = new TouchqueAgentCardException("invalid_signature", "no signature verifies");
        foreach (var s in sigs.OfType<JsonObject>())
        {
            var prot = Json.Str(s, "protected");
            var sigText = Json.Str(s, "signature");
            if (string.IsNullOrEmpty(prot) || string.IsNullOrEmpty(sigText)) continue;
            JsonObject? head;
            try
            {
                head = JsonNode.Parse(Encoding.UTF8.GetString(Base64Url.Decode(prot))) as JsonObject;
            }
            catch (Exception e) when (e is FormatException or JsonException)
            {
                continue;
            }
            if (head is null) continue;
            var alg = Json.Str(head, "alg");
            var kid = Json.Str(head, "kid");
            if (alg is null || !Algs.Contains(alg) || string.IsNullOrEmpty(kid) || head.ContainsKey("crit")) continue;
            if (head.ContainsKey("typ") && Json.Str(head, "typ") != "JOSE") continue;
            var jwk = options.Keys?.FirstOrDefault(k => Json.Str(k, "kid") == kid);
            var source = "keys";
            var jku = Json.Str(head, "jku");
            if (jwk is null && jku is not null)
            {
                var jkuHost = HostOf(jku);
                if (jkuHost is null || (jkuHost != cardHost && !(options.TrustedJkuHosts ?? Array.Empty<string>()).Contains(jkuHost)))
                {
                    last = new TouchqueAgentCardException("untrusted_key", $"jku {jku} is not on the card's host");
                    continue;
                }
                try
                {
                    jwk = ((await fetch(jku, ct).ConfigureAwait(false))["keys"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault(k => Json.Str(k, "kid") == kid);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    last = new TouchqueAgentCardException("keys_unavailable", $"the keys at {jku} could not be read: {e.Message}");
                    continue;
                }
                source = "jku";
            }
            if (jwk is null)
            {
                if (last.Error == "invalid_signature") last = new TouchqueAgentCardException("untrusted_key", $"no trusted key {kid}");
                continue;
            }
            byte[] sig;
            try
            {
                sig = Base64Url.Decode(sigText);
            }
            catch (FormatException)
            {
                continue;
            }
            if (JwsVerify.Verify(alg, jwk, Encoding.ASCII.GetBytes(prot + "." + payload), sig)) return new AgentCardVerification(kid, alg, source);
            last = new TouchqueAgentCardException("invalid_signature", "the signature does not match the card");
        }
        throw last;
    }

    /// <summary>
    /// Signs a card you publish: the card JSON with one more entry in <c>signatures</c>.
    /// The key is an ES256 or EdDSA private JWK (JsonObject or its JSON) or an EC P-256 PEM.
    /// </summary>
    public static string Sign(string cardJson, object privateKey, string kid, string? jku = null)
    {
        var c = Decode(cardJson);
        using var key = SigningKey.Load(privateKey, "AgentCard.Sign");
        var header = new JsonObject { ["alg"] = key.Alg, ["typ"] = "JOSE", ["kid"] = kid };
        if (jku is not null) header["jku"] = jku;
        var prot = Base64Url.Encode(Json.Serialize(header));
        var sig = key.Sign(Encoding.ASCII.GetBytes(prot + "." + Payload(c)));
        var entry = new JsonObject { ["protected"] = prot, ["signature"] = Base64Url.Encode(sig) };
        if (c["signatures"] is JsonArray list) list.Add(entry);
        else c["signatures"] = new JsonArray(entry);
        return c.ToJsonString(new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }
}
