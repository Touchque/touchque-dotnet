using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using TouchQue.Internal;

namespace TouchQue;

// Shared Signals (OpenID Shared Signals Framework 1.0): Security Event Tokens
// (SETs, RFC 8417) an identity provider sends when something happens to a
// person's account after sign-in: CAEP session-revoked, credential-change,
// device-compliance-change; RISC account-disabled, credential-compromise.
// TouchQue SSO sends them for an organization's members to the receivers its
// admin adds (Organization > Continuous access). Your app ends the person's
// sessions or asks them to sign in again.
//
// Push delivery (RFC 8935), the SET is the request body (application/secevent+jwt):
//
//   var verifier = new SecurityEventVerifier(new() { Issuer = "https://sso.touchque.com", Audience = "https://app.example.com" });
//   app.MapPost("/ssf", async (HttpRequest req) =>
//   {
//       try
//       {
//           var ev = await verifier.VerifyAsync(await new StreamReader(req.Body).ReadToEndAsync());
//           if (ev.Name == "session-revoked") await EndSessionsOf(Json.Str(ev.Subject, "email"));
//           return Results.StatusCode(202);
//       }
//       catch (TouchQueSecurityEventException e) { return Results.Json(new { err = e.Error, description = e.Message }, statusCode: 400); }
//   });
//
// Poll delivery (RFC 8936): SecurityEvents.PollAsync(new() { Url = ..., Token = ..., Ack = ... }).
//
// A SET does not expire: it says what happened. Keep the jtis you handled
// and skip a repeat.

/// <summary>
/// A refused SET. <see cref="Error"/> is the RFC 8935 error to answer with (HTTP 400 <c>{"err": Error}</c>):
/// invalid_request, invalid_key, invalid_issuer or invalid_audience; temporarily_unavailable when the
/// issuer's keys could not be read (answer 503: the transmitter tries again).
/// </summary>
public class TouchQueSecurityEventException : TouchQueException
{
    public TouchQueSecurityEventException(string error, string message) : base(message) => Error = error;

    public string Error { get; }
}

/// <summary>A verified SET.</summary>
public sealed record SecurityEvent
{
    public required string Jti { get; init; }
    public required string Issuer { get; init; }
    public required IReadOnlyList<string> Audience { get; init; }
    /// <summary>Seconds since the epoch.</summary>
    public long IssuedAt { get; init; }
    /// <summary>The case code of TouchQue's decision ("Why?" in the dashboard), or null.</summary>
    public string? Txn { get; init; }
    /// <summary>sub_id as sent: <c>{"format": "email", "email": ...}</c> for a person.</summary>
    public required JsonObject Subject { get; init; }
    /// <summary>The event type URI.</summary>
    public required string Type { get; init; }
    /// <summary>Its short name (session-revoked …) for CAEP, RISC and SSF types; null for others.</summary>
    public string? Name { get; init; }
    /// <summary>The event's own claims (event_timestamp, reason_admin, credential_type …).</summary>
    public required JsonObject Claims { get; init; }
}

/// <summary>What <see cref="SecurityEventVerifier"/> needs.</summary>
public sealed record SecurityEventVerifierOptions
{
    /// <summary>The transmitter's issuer, e.g. https://sso.touchque.com.</summary>
    public required string Issuer { get; init; }
    /// <summary>Your stream's audience (aud), as the dashboard shows it.</summary>
    public required string Audience { get; init; }
    /// <summary>Its JWKS, when not found from the issuer's /.well-known/ssf-configuration.</summary>
    public string? JwksUri { get; init; }
    /// <summary>Fixed keys instead (tests, or keys you pin): <c>{"keys": [...]}</c>.</summary>
    public JsonObject? Jwks { get; init; }
    /// <summary>Clock skew allowed for iat (default 300 s).</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(300);
    /// <summary>Reads a JSON document (tests).</summary>
    public Func<string, CancellationToken, Task<JsonObject>>? Fetch { get; init; }
}

/// <summary>Checks SETs: signature (RS256, the issuer's keys), typ, issuer, audience, one event.</summary>
public sealed partial class SecurityEventVerifier
{
    [GeneratedRegex(@"^https://schemas\.openid\.net/secevent/(caep|risc|ssf)/event-type/([a-z0-9-]+)$")]
    private static partial Regex Namespace();

    private readonly SecurityEventVerifierOptions _o;
    private readonly Func<string, CancellationToken, Task<JsonObject>> _fetch;
    private readonly SemaphoreSlim _keysLock = new(1, 1);
    private Dictionary<string, JsonObject> _keys = new();
    private string? _jwksUri;
    private DateTimeOffset _keysAt;
    private DateTimeOffset _triedAt;

    public SecurityEventVerifier(SecurityEventVerifierOptions options)
    {
        if (string.IsNullOrEmpty(options?.Issuer) || string.IsNullOrEmpty(options.Audience))
        {
            throw new TouchQueConfigException("SecurityEventVerifier needs Issuer (the transmitter) and Audience (your stream's aud)");
        }
        _o = options;
        _jwksUri = options.JwksUri;
        _fetch = options.Fetch ?? CrossAppAccess.GetJsonAsync;
        if (options.Jwks is not null) SetKeys(options.Jwks);
    }

    private void SetKeys(JsonObject jwks)
    {
        var keys = new Dictionary<string, JsonObject>();
        if (jwks["keys"] is JsonArray list)
        {
            foreach (var k in list.OfType<JsonObject>())
            {
                var kid = Json.Str(k, "kid");
                if (!string.IsNullOrEmpty(kid)) keys[kid] = k;
            }
        }
        _keys = keys;
        _keysAt = DateTimeOffset.UtcNow;
    }

    private async Task LoadKeysAsync(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(_jwksUri))
        {
            var meta = await _fetch(_o.Issuer.TrimEnd('/') + "/.well-known/ssf-configuration", ct).ConfigureAwait(false);
            if (Json.Str(meta, "issuer") != _o.Issuer || Json.Str(meta, "jwks_uri") is not { } uri)
            {
                throw new InvalidOperationException("the transmitter's metadata does not match its issuer");
            }
            _jwksUri = uri;
        }
        if (!CrossAppAccess.SafeUrl(_jwksUri)) throw new InvalidOperationException($"{_jwksUri} must be an https URL");
        SetKeys(await _fetch(_jwksUri, ct).ConfigureAwait(false));
    }

    private async Task<JsonObject?> KeyForAsync(string kid, CancellationToken ct)
    {
        if (_o.Jwks is not null) return _keys.GetValueOrDefault(kid);
        await _keysLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_keysAt == default || DateTimeOffset.UtcNow - _keysAt > TimeSpan.FromHours(1)) await LoadKeysAsync(ct).ConfigureAwait(false);
            if (!_keys.ContainsKey(kid) && DateTimeOffset.UtcNow - _triedAt > TimeSpan.FromMinutes(5))
            {
                _triedAt = DateTimeOffset.UtcNow;
                await LoadKeysAsync(ct).ConfigureAwait(false);
            }
            return _keys.GetValueOrDefault(kid);
        }
        finally
        {
            _keysLock.Release();
        }
    }

    /// <summary>The SET, checked; throws <see cref="TouchQueSecurityEventException"/>.</summary>
    public async Task<SecurityEvent> VerifyAsync(string token, CancellationToken ct = default)
    {
        static TouchQueSecurityEventException Bad(string m) => new("invalid_request", m);
        var parts = JwsVerify.Split((token ?? "").Trim()) ?? throw Bad("not a JWT");
        var (header, c, input, sig) = parts;
        if (!string.Equals(Json.Str(header, "typ"), "secevent+jwt", StringComparison.OrdinalIgnoreCase))
        {
            throw Bad("not a Security Event Token (typ secevent+jwt)");
        }
        var kid = Json.Str(header, "kid");
        if (Json.Str(header, "alg") != "RS256" || string.IsNullOrEmpty(kid)) throw new TouchQueSecurityEventException("invalid_key", "unsupported signature");
        JsonObject? jwk;
        try
        {
            jwk = await KeyForAsync(kid, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            throw new TouchQueSecurityEventException("temporarily_unavailable", "the transmitter's keys could not be read: " + e.Message);
        }
        if (jwk is null || !JwsVerify.Verify("RS256", jwk, input, sig)) throw new TouchQueSecurityEventException("invalid_key", "signature does not verify");
        if (Json.Str(c, "iss") != _o.Issuer) throw new TouchQueSecurityEventException("invalid_issuer", "another issuer");
        var audience = c["aud"] switch
        {
            JsonArray list => list.Select(a => a is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).OfType<string>().ToList(),
            JsonValue v when v.TryGetValue<string>(out var s) => new List<string> { s },
            _ => new List<string>(),
        };
        if (!audience.Contains(_o.Audience)) throw new TouchQueSecurityEventException("invalid_audience", "not for this receiver");
        var jti = Json.Str(c, "jti");
        var iatNode = c["iat"] as JsonValue;
        if (jti is null || iatNode is null || iatNode.GetValueKind() != JsonValueKind.Number || !long.TryParse(iatNode.ToJsonString(), out var iat))
        {
            throw Bad("jti and iat are required");
        }
        if (iat - (long)_o.ClockSkew.TotalSeconds > DateTimeOffset.UtcNow.ToUnixTimeSeconds()) throw Bad("issued in the future");
        if (c["events"] is not JsonObject events || events.Count != 1) throw Bad("a SET carries exactly one event");
        var (type, claims) = events.First();
        var m = Namespace().Match(type);
        return new SecurityEvent
        {
            Jti = jti, Issuer = _o.Issuer, Audience = audience, IssuedAt = iat, Txn = Json.Str(c, "txn"),
            Subject = (c["sub_id"] as JsonObject)?.DeepClone() as JsonObject ?? new JsonObject(),
            Type = type, Name = m.Success ? m.Groups[2].Value : null,
            Claims = claims?.DeepClone() as JsonObject ?? new JsonObject(),
        };
    }
}

/// <summary>One poll (RFC 8936).</summary>
public sealed record PollSecurityEventsOptions
{
    /// <summary>The stream's poll endpoint (its delivery.endpoint_url).</summary>
    public required string Url { get; init; }
    /// <summary>The stream's token.</summary>
    public required string Token { get; init; }
    /// <summary>jtis you handled since the last poll.</summary>
    public IReadOnlyList<string>? Ack { get; init; }
    /// <summary>jtis you could not handle: <c>{jti: {"err": ..., "description": ...}}</c>.</summary>
    public JsonObject? SetErrs { get; init; }
    public int? MaxEvents { get; init; }
    public bool? ReturnImmediately { get; init; }
}

/// <summary>Shared Signals helpers that are not tied to one verifier.</summary>
public static class SecurityEvents
{
    /// <summary>The event types TouchQue sends, by their short name.</summary>
    public static readonly IReadOnlyDictionary<string, string> Types = new Dictionary<string, string>
    {
        ["session-revoked"] = "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        ["credential-change"] = "https://schemas.openid.net/secevent/caep/event-type/credential-change",
        ["device-compliance-change"] = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change",
        ["account-disabled"] = "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
        ["credential-compromise"] = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise",
        ["verification"] = "https://schemas.openid.net/secevent/ssf/event-type/verification",
        ["stream-updated"] = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated",
    };

    private static readonly Lazy<HttpClient> Client = new(() => new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) });

    /// <summary>Acknowledges what you handled and returns the waiting SETs (jti → token) and whether more wait.</summary>
    public static async Task<(IReadOnlyDictionary<string, string> Sets, bool MoreAvailable)> PollAsync(PollSecurityEventsOptions o, CancellationToken ct = default)
    {
        if (!CrossAppAccess.SafeUrl(o.Url)) throw new TouchQueConfigException($"{o.Url} must be an https URL");
        if (string.IsNullOrEmpty(o.Token)) throw new TouchQueConfigException("PollAsync needs the stream's token");
        var body = new JsonObject();
        if (o.Ack is not null) body["ack"] = new JsonArray(o.Ack.Select(a => (JsonNode)JsonValue.Create(a)!).ToArray());
        if (o.SetErrs is not null) body["setErrs"] = o.SetErrs.DeepClone();
        if (o.MaxEvents is { } max) body["maxEvents"] = max;
        if (o.ReturnImmediately is { } now) body["returnImmediately"] = now;
        using var req = new HttpRequestMessage(HttpMethod.Post, o.Url) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };
        req.Headers.Accept.ParseAdd("application/json");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", o.Token);
        using var res = await Client.Value.SendAsync(req, ct).ConfigureAwait(false);
        var data = Json.ParseObject(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        if ((int)res.StatusCode != 200) throw new TouchQueSecurityEventException(Json.Str(data, "error") ?? "server_error", $"{o.Url} answered {(int)res.StatusCode}");
        var sets = new Dictionary<string, string>();
        if (data["sets"] is JsonObject s)
        {
            foreach (var (jti, t) in s) if (t is JsonValue v && v.TryGetValue<string>(out var token)) sets[jti] = token;
        }
        return (sets, Json.Bool(data, "moreAvailable"));
    }
}
