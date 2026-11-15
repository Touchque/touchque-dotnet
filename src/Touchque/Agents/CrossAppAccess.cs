using System.Collections.Concurrent;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>
/// A refused ID-JAG or exchange (Cross App Access). <see cref="Error"/> is the OAuth error:
/// <c>invalid_grant</c> for a bad ID-JAG. From a token endpoint: the <c>error</c> its non-2xx answer
/// names (an RFC 6749 error code of at most 128 characters), else <c>server_error</c>;
/// <c>invalid_response</c> for a 2xx answer that is not a JSON object (or, from
/// <see cref="CrossAppAccess.RequestIdJagAsync"/>, not an ID-JAG); <c>temporarily_unavailable</c> when
/// the token endpoint could not be reached or its answer read (no <see cref="Status"/>; the cause is
/// the <see cref="Exception.InnerException"/>).
/// </summary>
public class TouchqueIdJagException : TouchqueException
{
    public TouchqueIdJagException(string error, string message, int? status = null) : base(message)
    {
        Error = error;
        Status = status;
    }

    /// <summary>The same, with the exception that caused it as <see cref="Exception.InnerException"/>.</summary>
    public TouchqueIdJagException(string error, string message, int? status, Exception? innerException) : base(message, innerException)
    {
        Error = error;
        Status = status;
    }

    public string Error { get; }

    /// <summary>
    /// The HTTP status of the token endpoint answer that gave the error: a non-2xx answer, or a 2xx that is not
    /// a JSON object. Null otherwise: no answer (<c>temporarily_unavailable</c>), a JSON object that is not an
    /// ID-JAG, or an <see cref="IdJagVerifier"/> error.
    /// </summary>
    public int? Status { get; }

    /// <summary>
    /// The latest valid <c>DPoP-Nonce</c> the token endpoint sent during the call (RFC 9449 section 8), in
    /// any of its answers, a 2xx included: the nonce retry's answer's when it had one, else the first
    /// answer's. Every error <see cref="CrossAppAccess.RequestIdJagAsync"/> and
    /// <see cref="CrossAppAccess.RedeemIdJagAsync"/> throw carries it (<c>invalid_response</c> and
    /// <c>temporarily_unavailable</c> too). Only a valid nonce (1*NQCHAR: printable ASCII except space,
    /// <c>"</c> and <c>\</c>, the same value each time the header repeats); otherwise null. A request you
    /// send again yourself carries it in a new proof (<c>CrossAppAccess.IdJagDpopProof(key, url, nonce: e.DpopNonce)</c>).
    /// </summary>
    public string? DpopNonce { get; init; }
}

/// <summary>What <see cref="CrossAppAccess.RequestIdJagAsync"/> needs.</summary>
public sealed record RequestIdJagOptions
{
    /// <summary>The identity provider's issuer (its token endpoint is discovered), or give <see cref="TokenEndpoint"/>.</summary>
    public string? Issuer { get; init; }
    public string? TokenEndpoint { get; init; }
    /// <summary>Your app at the identity provider (tqapp_… at Touchque SSO) and its secret.</summary>
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    /// <summary>The member's ID token the identity provider issued to your app.</summary>
    public required string IdToken { get; init; }
    /// <summary>The other service's authorization server (its issuer).</summary>
    public required string Audience { get; init; }
    public string? Resource { get; init; }
    public string? Scope { get; init; }
    /// <summary>
    /// Binds the ID-JAG to this key (DPoP, RFC 9449); redeem it with the same key. A server that asks
    /// for a DPoP nonce (<c>use_dpop_nonce</c> with a valid <c>DPoP-Nonce</c>) gets the request once more,
    /// with a proof that carries it.
    /// </summary>
    public IdJagDpopKey? DpopKey { get; init; }
}

/// <summary>An ID-JAG the identity provider issued.</summary>
public sealed record IdJagGrant(string Assertion, int? ExpiresIn, string? Scope)
{
    /// <summary>
    /// With a <see cref="RequestIdJagOptions.DpopKey"/>: whether the returned ID-JAG carries that key's
    /// thumbprint (cnf.jkt); an identity provider without DPoP support ignores the proof. Null without one.
    /// </summary>
    public bool? DpopBound { get; init; }
}

/// <summary>
/// A DPoP key (RFC 9449, P-256) that binds an ID-JAG, and the access token redeemed with it, to its
/// holder; keep it in this process. Make one with <see cref="CrossAppAccess.CreateIdJagDpopKey"/>.
/// </summary>
public sealed class IdJagDpopKey : IDisposable
{
    internal IdJagDpopKey(SigningKey key)
    {
        Key = key;
        Thumbprint = AgentKeys.Thumbprint(key.PublicJwk);
    }

    internal SigningKey Key { get; }

    /// <summary>kty, crv, x, y: the public key only.</summary>
    public JsonObject PublicJwk => (JsonObject)Key.PublicJwk.DeepClone();

    /// <summary>RFC 7638 thumbprint: the ID-JAG's cnf.jkt.</summary>
    public string Thumbprint { get; }

    public void Dispose() => Key.Dispose();
}

/// <summary>What <see cref="CrossAppAccess.RedeemIdJagAsync"/> needs.</summary>
public sealed record RedeemIdJagOptions
{
    public required string TokenEndpoint { get; init; }
    public required string ClientId { get; init; }
    public string? ClientSecret { get; init; }
    public required string Assertion { get; init; }
    public string? Resource { get; init; }
    public string? Scope { get; init; }
    /// <summary>
    /// The key the ID-JAG is bound to: a DPoP proof goes along, and the access token is then DPoP-bound
    /// too (each call with it needs a proof: <see cref="CrossAppAccess.IdJagDpopProof"/> with the method and
    /// the token). A server that asks for a DPoP nonce (with a valid <c>DPoP-Nonce</c>) gets the request once
    /// more, with a proof that carries it.
    /// </summary>
    public IdJagDpopKey? DpopKey { get; init; }
}

/// <summary>
/// Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
/// draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An
/// organization's identity provider (Touchque SSO) decides which of its apps may
/// reach which other service for its members; the app trades a member's ID token
/// for an ID-JAG there, then the ID-JAG for an access token at the other
/// service's authorization server, with no consent screen per member. Your own
/// authorization server takes them with <see cref="IdJagVerifier"/>.
/// <code>
/// var jag = await CrossAppAccess.RequestIdJagAsync(new() { Issuer = "https://sso.touchque.com", ClientId = id, ClientSecret = secret,
///     IdToken = idToken, Audience = "https://auth.files.example" });
/// var tokens = await CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = "https://auth.files.example/token", ClientId = "acme",
///     ClientSecret = filesSecret, Assertion = jag.Assertion });
/// </code>
/// Sender-constrained with DPoP (RFC 9449), optional: give the same key to both calls. The ID-JAG is
/// then bound to it (cnf.jkt) and is useless to anyone who copies it without the key.
/// <code>
/// using var dpopKey = CrossAppAccess.CreateIdJagDpopKey();
/// var jag = await CrossAppAccess.RequestIdJagAsync(new() { /* as above */ DpopKey = dpopKey });   // jag.DpopBound
/// var tokens = await CrossAppAccess.RedeemIdJagAsync(new() { /* as above */ Assertion = jag.Assertion, DpopKey = dpopKey });
/// // A call with the DPoP-bound access token: a proof for the exact URI and method it sends.
/// using var call = new HttpRequestMessage(HttpMethod.Get, "https://api.files.example/v1/files");
/// call.Headers.Authorization = new AuthenticationHeaderValue("DPoP", (string)tokens["access_token"]!);
/// call.Headers.Add("DPoP", CrossAppAccess.IdJagDpopProof(dpopKey, call.RequestUri!.AbsoluteUri, call.Method.Method, (string)tokens["access_token"]!));
/// </code>
/// </summary>
public static class CrossAppAccess
{
    public const string IdJagTokenType = "urn:ietf:params:oauth:token-type:id-jag";
    public const string IdTokenType = "urn:ietf:params:oauth:token-type:id_token";
    public const string TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
    public const string JwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    /// <summary>
    /// Reads up to 256 KB of response headers (SocketsHttpHandler's default is 64 KB): a token endpoint's
    /// long <c>WWW-Authenticate</c> or <c>DPoP-Nonce</c> header still gives its answer or a <see cref="TouchqueIdJagException"/>
    /// (more is <c>temporarily_unavailable</c>). Never follows a redirect; a request takes at most 10 s.
    /// </summary>
    private static readonly Lazy<HttpClient> SharedClient = new(() => TouchqueHttp.CreateClient(TimeSpan.FromSeconds(10), maxResponseHeadersKb: 256));
    private static readonly char[] C0OrSpace = Enumerable.Range(0, 0x21).Select(c => (char)c).ToArray();

    /// <summary>
    /// What a proof's method is trimmed of: ASCII whitespace (space, tab, LF, VT, FF, CR). Not string.Trim()'s
    /// Unicode whitespace (U+0085, U+00A0, U+2000…), and not NUL: those are not RFC 9110 token characters.
    /// </summary>
    private static readonly char[] AsciiWhitespace = { ' ', '\t', '\n', '\v', '\f', '\r' };

    /// <summary>Makes a fresh DPoP key for <see cref="RequestIdJagAsync"/> and <see cref="RedeemIdJagAsync"/>.</summary>
    public static IdJagDpopKey CreateIdJagDpopKey() => new(SigningKey.NewEs256());

    /// <summary>
    /// A DPoP proof (RFC 9449) with <paramref name="key"/> for one request: by default a POST to a token
    /// endpoint. For a call with the DPoP-bound access token, give the call's method and the token (the
    /// proof carries its hash, ath) and send <c>Authorization: DPoP &lt;token&gt;</c> with
    /// <c>DPoP: &lt;proof&gt;</c>. <paramref name="nonce"/>: the server's <c>DPoP-Nonce</c>, when it asked
    /// for one; it goes in as given, unchecked. A null or empty <paramref name="accessToken"/> or
    /// <paramref name="nonce"/> is left out (no ath, no nonce). Each proof has a fresh jti and iat, and its
    /// jwk is the key's public part only (kty, crv, x, y).
    /// <para>
    /// htm is <paramref name="method"/> without leading and trailing ASCII whitespace (space, tab, CR, LF, VT,
    /// FF; not NUL or U+00A0), POST when that leaves nothing, uppercased; a method with anything but RFC 9110
    /// token characters throws <see cref="TouchqueConfigException"/>.
    /// </para>
    /// <para>
    /// htu is <paramref name="url"/> as System.Uri parses it (it must be an absolute http or https URL, else
    /// <see cref="TouchqueConfigException"/>): scheme and host lowercased (an IDN host in punycode), user info
    /// and the default port dropped, "/" for an empty path, no query or fragment. The path is kept as given,
    /// percent-escapes included, except that "\" counts as "/", "." and ".." segments are resolved, and a
    /// character a URL path cannot hold as it is (a space, non-ASCII, <c>" &lt; &gt; ^ ` { }</c>) is
    /// percent-encoded as UTF-8. HttpClient sends a URL in System.Uri's form (%7E as ~, | as %7C): make the
    /// proof from the exact URI you send, <c>request.RequestUri.AbsoluteUri</c>, so that htu matches.
    /// </para>
    /// </summary>
    public static string IdJagDpopProof(IdJagDpopKey key, string url, string method = "POST", string? accessToken = null, string? nonce = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        var claims = new JsonObject
        {
            ["htm"] = DpopHtm(method), ["htu"] = DpopHtu(url), ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["jti"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
        };
        claims.Put("ath", string.IsNullOrEmpty(accessToken) ? null : AgentKeys.AccessTokenHash(accessToken)).Put("nonce", nonce);
        // The jwk is rebuilt for each proof from the key's public point: exactly kty, crv, x and y.
        var pub = key.Key.PublicJwk;
        var jwk = new JsonObject { ["kty"] = Json.Str(pub, "kty"), ["crv"] = Json.Str(pub, "crv"), ["x"] = Json.Str(pub, "x"), ["y"] = Json.Str(pub, "y") };
        return key.Key.Jws(new JsonObject { ["typ"] = "dpop+jwt", ["jwk"] = jwk }, claims);
    }

    /// <summary>
    /// A proof's htm: <paramref name="method"/> trimmed of ASCII whitespace, POST when empty, uppercased. An
    /// HTTP method is an RFC 9110 token, checked before uppercasing (ToUpperInvariant turns "poſt" into POST).
    /// </summary>
    internal static string DpopHtm(string? method)
    {
        var m = (method ?? "").Trim(AsciiWhitespace);
        if (m.Length == 0) return "POST";
        foreach (var c in m)
        {
            if (!IsTchar(c)) throw new TouchqueConfigException($"IdJagDpopProof: \"{method}\" is not an HTTP method (RFC 9110 token characters only)");
        }
        return m.ToUpperInvariant();
    }

    /// <summary>An RFC 9110 tchar: an ASCII letter or digit, or one of !#$%&amp;'*+-.^_`|~.</summary>
    private static bool IsTchar(char c) =>
        c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9')
            or '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~';

    /// <summary>
    /// A proof's htu: scheme://host[:port]/path of <paramref name="url"/> as System.Uri parses it, without
    /// user info, query or fragment: scheme and host lowercased (an IDN host in punycode), no default port,
    /// "/" for an empty path. The path keeps its own percent-escapes as given (<see cref="Uri"/> would decode
    /// %7E and the like); only "\" (as "/"), "." and ".." segments (also as %2e), and characters a path
    /// cannot hold as they are (percent-encoded as UTF-8) change.
    /// </summary>
    internal static string DpopHtu(string url)
    {
        // No leading or trailing C0 control or space, no tab or newline anywhere.
        var s = (url ?? "").Trim(C0OrSpace).Replace("\t", "").Replace("\n", "").Replace("\r", "");
        if (!Uri.TryCreate(s, UriKind.Absolute, out var u) || u.Scheme is not ("https" or "http") || u.Host.Length == 0)
        {
            throw new TouchqueConfigException($"{url} must be an absolute https or http URL");
        }
        var host = (u.HostNameType == UriHostNameType.Dns ? u.IdnHost : u.Host).ToLowerInvariant();
        // The path as written: after the scheme, the slashes and the authority, up to the query or fragment.
        var at = s.IndexOf(':') + 1;
        while (at < s.Length && s[at] is '/' or '\\') at++;
        var start = s.IndexOfAny(new[] { '/', '\\', '?', '#' }, at);
        start = start < 0 ? s.Length : start;
        var end = s.IndexOfAny(new[] { '?', '#' }, start);
        var path = s[start..(end < 0 ? s.Length : end)];
        // Segment by segment: \ is /, "." and ".." segments (also as %2e) go, other code points are kept or
        // UTF-8 percent-encoded (space, controls, non-ASCII and " # < > ? ^ ` { }), and a % stays as written.
        var segments = new List<string>();
        var segment = new StringBuilder();
        Span<byte> utf8 = stackalloc byte[4];
        var i = path.Length > 0 && path[0] is '/' or '\\' ? 1 : 0;
        while (true)
        {
            if (i < path.Length && path[i] is not ('/' or '\\'))
            {
                Rune.DecodeFromUtf16(path.AsSpan(i), out var rune, out var used);
                i += used;
                if (rune.Value is > 0x20 and < 0x7F and not ('"' or '#' or '<' or '>' or '?' or '^' or '`' or '{' or '}'))
                {
                    segment.Append((char)rune.Value);
                    continue;
                }
                var n = rune.EncodeToUtf8(utf8);
                for (var k = 0; k < n; k++) segment.Append('%').Append(utf8[k].ToString("X2", CultureInfo.InvariantCulture));
                continue;
            }
            var last = i >= path.Length;
            var text = segment.ToString();
            var dots = text.Replace("%2e", ".", StringComparison.OrdinalIgnoreCase);
            if (dots == "..")
            {
                if (segments.Count > 0) segments.RemoveAt(segments.Count - 1);
                if (last) segments.Add("");
            }
            else if (dots == ".")
            {
                if (last) segments.Add("");
            }
            else
            {
                segments.Add(text);
            }
            if (last) break;
            segment.Clear();
            i++;
        }
        return u.Scheme + "://" + host + (u.IsDefaultPort ? "" : ":" + u.Port.ToString(CultureInfo.InvariantCulture)) + "/" + string.Join('/', segments);
    }

    /// <summary>https, or http on this machine (tests).</summary>
    internal static bool SafeUrl(string? url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) && (u.Scheme == "https" || (u.Scheme == "http" && u.IsLoopback));

    internal static async Task<JsonObject> GetJsonAsync(string url, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.ParseAdd("application/json");
        using var res = await SharedClient.Value.SendAsync(req, ct).ConfigureAwait(false);
        if ((int)res.StatusCode >= 400) throw new InvalidOperationException($"{url} answered {(int)res.StatusCode}");
        return Json.ParseObject(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
    }

    /// <summary>The identity provider's OpenID configuration, checked against its issuer.</summary>
    internal static async Task<JsonObject> DiscoverAsync(string issuer, Func<string, CancellationToken, Task<JsonObject>> fetch, CancellationToken ct)
    {
        var meta = await fetch(issuer.TrimEnd('/') + "/.well-known/openid-configuration", ct).ConfigureAwait(false);
        if (Json.Str(meta, "issuer") != issuer) throw new TouchqueConfigException("the identity provider's metadata does not match its issuer");
        return meta;
    }

    /// <summary>
    /// Whether a DPoP challenge in <c>WWW-Authenticate</c> asks for a nonce: its own <c>error</c> parameter is
    /// exactly <c>use_dpop_nonce</c> (RFC 9449 section 9). It only decides the nonce retry, never the error.
    /// One pass over each header value, linear in its length, that never throws (RFC 9110 section 11.6.1): a
    /// token followed by "=" is an auth-param of the current challenge, any other token starts a new one;
    /// scheme and parameter names are case-insensitive. A value is a token or a quoted-string: a comma inside
    /// quotes does not split, a quoted-pair (\ and a character) is that character, and a quoted-string without
    /// its closing quote has no value (the rest of the field value is inside it).
    /// </summary>
    internal static bool DpopChallengeAsksForNonce(IEnumerable<string> wwwAuthenticate)
    {
        foreach (var v in wwwAuthenticate)
        {
            var dpop = false;
            var i = 0;
            while (i < v.Length)
            {
                if (!IsTchar(v[i]))
                {
                    i++; // "," or a space between elements, or a stray character
                    continue;
                }
                var start = i;
                while (i < v.Length && IsTchar(v[i])) i++;
                var name = v.AsSpan(start, i - start);
                var j = i;
                while (j < v.Length && v[j] is ' ' or '\t') j++;
                if (j == v.Length || v[j] != '=')
                {
                    // An auth-scheme (or a token68 after one, which no DPoP challenge has).
                    dpop = name.Equals("DPoP", StringComparison.OrdinalIgnoreCase);
                    i = j;
                    continue;
                }
                j++;
                while (j < v.Length && v[j] is ' ' or '\t') j++;
                var wanted = dpop && name.Equals("error", StringComparison.OrdinalIgnoreCase);
                string? value = null;
                if (j < v.Length && v[j] == '"')
                {
                    var text = wanted ? new StringBuilder() : null;
                    var closed = false;
                    for (j++; j < v.Length; j++)
                    {
                        if (v[j] == '"')
                        {
                            closed = true;
                            break;
                        }
                        if (v[j] == '\\' && j + 1 < v.Length) j++;
                        text?.Append(v[j]);
                    }
                    if (!closed) break;
                    j++; // the closing quote
                    value = text?.ToString();
                }
                else
                {
                    var from = j;
                    while (j < v.Length && IsTchar(v[j])) j++;
                    if (wanted) value = v[from..j];
                }
                i = j;
                if (value == "use_dpop_nonce") return true;
            }
        }
        return false;
    }

    /// <summary>
    /// <paramref name="error"/> when it is an OAuth error code as RFC 6749 section 5.2 writes one
    /// (%x20-21 / %x23-5B / %x5D-7E: printable ASCII or space, but no <c>"</c> or <c>\</c>), 1 to 128
    /// characters; otherwise null.
    /// </summary>
    internal static string? OAuthErrorCode(string? error)
    {
        if (error is not { Length: > 0 and <= 128 }) return null;
        foreach (var c in error)
        {
            if (c is not ('\x20' or '\x21' or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E'))) return null;
        }
        return error;
    }

    /// <summary>
    /// The <c>DPoP-Nonce</c> of an answer when it is one valid nonce (RFC 9449: 1*NQCHAR, printable ASCII
    /// except space, " and \); null when the header is missing, empty or invalid, or repeats with another value.
    /// </summary>
    internal static string? ValidDpopNonce(IEnumerable<string> values)
    {
        string? nonce = null;
        foreach (var v in values)
        {
            if (v.Length == 0 || (nonce is not null && v != nonce)) return null;
            foreach (var c in v)
            {
                if (c is not ('\x21' or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E'))) return null;
            }
            nonce = v;
        }
        return nonce;
    }

    /// <summary>
    /// No answer to read: the token endpoint was not reached, reset the connection or timed out (the shared
    /// client's 10 s), or HttpClient refused its answer (a malformed or oversized header section, a body it
    /// could not read). A cancellation the caller asked for with <paramref name="ct"/> is not one: it stays
    /// an OperationCanceledException.
    /// </summary>
    private static bool NoAnswer(Exception e, CancellationToken ct) =>
        (e is HttpRequestException or IOException or OperationCanceledException) && !ct.IsCancellationRequested;

    private static TouchqueIdJagException Unavailable(string url, Exception e, string? latestNonce) =>
        new("temporarily_unavailable", $"{url} could not be reached or read: {e.Message}", null, e) { DpopNonce = latestNonce };

    /// <summary>
    /// POSTs a form to a token endpoint: a 2xx answer that is a JSON object, and the latest valid
    /// <c>DPoP-Nonce</c> the server sent during the call. Anything else is a <see cref="TouchqueIdJagException"/>
    /// that carries that nonce: another status (a redirect too: none is followed) gives its status and the
    /// body's OAuth error, else server_error; a 2xx without a JSON object, invalid_response; no answer,
    /// temporarily_unavailable (<see cref="NoAnswer"/>), with its cause as the InnerException.
    /// </summary>
    private static async Task<(JsonObject Data, string? DpopNonce)> PostFormAsync(string url, Dictionary<string, string?> form, (string Id, string Secret)? basic, IdJagDpopKey? dpopKey, CancellationToken ct)
    {
        if (!SafeUrl(url)) throw new TouchqueConfigException($"{url} must be an https URL");
        // The proof names the URL as HttpClient sends it (System.Uri's form: %7E as ~, | as %7C).
        var sent = new Uri(url).AbsoluteUri;
        string? nonce = null;
        // The latest valid DPoP-Nonce the server sent during this call, in any answer: every error carries it.
        string? latestNonce = null;
        while (true)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new FormUrlEncodedContent(form.Where(kv => kv.Value is not null).Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value!))),
            };
            req.Headers.Accept.ParseAdd("application/json");
            // A fresh proof (jti, iat) for each request; the second one carries the server's nonce.
            if (dpopKey is not null) req.Headers.TryAddWithoutValidation("DPoP", IdJagDpopProof(dpopKey, sent, nonce: nonce));
            if (basic is { } b)
            {
                var raw = Uri.EscapeDataString(b.Id) + ":" + Uri.EscapeDataString(b.Secret);
                req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(raw)));
            }
            HttpResponseMessage answer;
            try
            {
                answer = await SharedClient.Value.SendAsync(req, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (NoAnswer(e, ct))
            {
                throw Unavailable(url, e, latestNonce);
            }
            using var res = answer;
            var answerNonce = res.Headers.NonValidated.TryGetValues("DPoP-Nonce", out var nonces) ? ValidDpopNonce(nonces) : null;
            latestNonce = answerNonce ?? latestNonce;
            string text;
            try
            {
                // JSON is UTF-8 (RFC 8259): a charset in Content-Type, even one .NET does not know, changes nothing.
                text = Encoding.UTF8.GetString(await res.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false));
            }
            catch (Exception e) when (NoAnswer(e, ct))
            {
                throw Unavailable(url, e, latestNonce);
            }
            if (text.StartsWith('\uFEFF')) text = text[1..];
            var status = (int)res.StatusCode;
            // JSON that repeats a member name or holds a lone surrogate would throw ArgumentException or
            // InvalidOperationException on its first read: it is not read at all.
            var json = Json.Parse(text);
            var data = json is JsonObject o && Json.IsIJson(text) ? o : null;
            if (status is >= 200 and <= 299)
            {
                if (data is not null) return (data, latestNonce);
                var why = json is JsonObject ? "JSON that repeats a member name or holds a lone surrogate" : "something other than a JSON object";
                throw new TouchqueIdJagException("invalid_response", $"{url} answered {status} with {why}", status) { DpopNonce = latestNonce };
            }
            // Any other status is a refusal. Its error is the body's (RFC 6749 section 5.2), never WWW-Authenticate's.
            var error = OAuthErrorCode(Json.Str(data, "error"));
            // RFC 9449 section 8: the server wants its nonce in the proof, in the body or, for a 401, in a DPoP
            // challenge. Once per call (nonce is still null), never in a loop.
            if (dpopKey is not null && nonce is null && answerNonce is not null && status is 400 or 401
                && (error == "use_dpop_nonce" || (status == 401 && res.Headers.NonValidated.TryGetValues("WWW-Authenticate", out var www) && DpopChallengeAsksForNonce(www))))
            {
                nonce = answerNonce;
                continue;
            }
            throw new TouchqueIdJagException(error ?? "server_error", Json.Str(data, "error_description") ?? $"{url} answered {status}", status)
            {
                DpopNonce = latestNonce,
            };
        }
    }

    /// <summary>
    /// Trades a member's ID token for an ID-JAG at the identity provider (token exchange, client_secret_basic).
    /// A refusal, an answer that is not an ID-JAG, or a token endpoint that cannot be reached or read throws
    /// <see cref="TouchqueIdJagException"/>.
    /// </summary>
    public static async Task<IdJagGrant> RequestIdJagAsync(RequestIdJagOptions o, CancellationToken ct = default)
    {
        var endpoint = o.TokenEndpoint;
        if (string.IsNullOrEmpty(endpoint))
        {
            if (string.IsNullOrEmpty(o.Issuer)) throw new TouchqueConfigException("RequestIdJagAsync needs Issuer or TokenEndpoint");
            endpoint = Json.Str(await DiscoverAsync(o.Issuer, GetJsonAsync, ct).ConfigureAwait(false), "token_endpoint")
                ?? throw new TouchqueConfigException("the identity provider names no token_endpoint");
        }
        var (data, nonce) = await PostFormAsync(endpoint, new()
        {
            ["grant_type"] = TokenExchangeGrant, ["requested_token_type"] = IdJagTokenType, ["subject_token"] = o.IdToken,
            ["subject_token_type"] = IdTokenType, ["audience"] = o.Audience, ["resource"] = o.Resource, ["scope"] = o.Scope,
        }, (o.ClientId, o.ClientSecret), o.DpopKey, ct).ConfigureAwait(false);
        var assertion = Json.Str(data, "access_token");
        if (Json.Str(data, "issued_token_type") != IdJagTokenType || string.IsNullOrEmpty(assertion))
        {
            throw new TouchqueIdJagException("invalid_response", "the identity provider did not answer with an ID-JAG") { DpopNonce = nonce };
        }
        bool? dpopBound = null;
        if (o.DpopKey is not null)
        {
            // An identity provider without DPoP support ignores the proof: say so instead of guessing.
            var claims = JwsVerify.Split(assertion)?.Claims;
            dpopBound = claims?["cnf"] is JsonObject cnf && Json.Str(cnf, "jkt") is { } jkt && jkt == o.DpopKey.Thumbprint;
        }
        return new IdJagGrant(assertion, (int?)Json.Long(data, "expires_in"), Json.Str(data, "scope")) { DpopBound = dpopBound };
    }

    /// <summary>
    /// Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer): its 2xx
    /// answer, a JSON object. A refusal, any other answer, or a token endpoint that cannot be reached or read
    /// throws <see cref="TouchqueIdJagException"/>.
    /// </summary>
    public static async Task<JsonObject> RedeemIdJagAsync(RedeemIdJagOptions o, CancellationToken ct = default) =>
        (await PostFormAsync(o.TokenEndpoint, new()
        {
            ["grant_type"] = JwtBearerGrant, ["assertion"] = o.Assertion, ["resource"] = o.Resource, ["scope"] = o.Scope,
            ["client_id"] = string.IsNullOrEmpty(o.ClientSecret) ? o.ClientId : null,
        }, string.IsNullOrEmpty(o.ClientSecret) ? null : (o.ClientId, o.ClientSecret), o.DpopKey, ct).ConfigureAwait(false)).Data;
}

/// <summary>Settings of <see cref="IdJagVerifier"/>.</summary>
public sealed record IdJagVerifierOptions
{
    /// <summary>The identity provider, e.g. https://sso.touchque.com.</summary>
    public required string Issuer { get; init; }
    /// <summary>Your authorization server's issuer identifier (the ID-JAG's aud).</summary>
    public required string Audience { get; init; }
    /// <summary>Its JWKS, when not found from the issuer's /.well-known/openid-configuration.</summary>
    public string? JwksUri { get; init; }
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(60);
    /// <summary>
    /// Records an ID-JAG's jti and says whether it is new (each is used once). Defaults to memory
    /// in this process; give a shared store (Redis SET NX) when several processes take ID-JAGs.
    /// </summary>
    public Func<string, long, bool>? FirstUse { get; init; }
    /// <summary>For tests: how JSON documents are fetched.</summary>
    public Func<string, CancellationToken, Task<JsonObject>>? Fetch { get; init; }
}

/// <summary>A checked ID-JAG.</summary>
public sealed record IdJagClaims
{
    public string Iss { get; init; } = "";
    /// <summary>The member at the identity provider.</summary>
    public string Sub { get; init; } = "";
    public string Aud { get; init; } = "";
    /// <summary>Your client_id of the app that presented it.</summary>
    public string ClientId { get; init; } = "";
    public string Jti { get; init; } = "";
    public long IssuedAt { get; init; }
    public long ExpiresAt { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = Array.Empty<string>();
    public string? Resource { get; init; }
    public string? Tenant { get; init; }
    public string? Email { get; init; }
    public long? AuthTime { get; init; }
    public IReadOnlyList<string> Amr { get; init; } = Array.Empty<string>();
    /// <summary>The DPoP key thumbprint the ID-JAG is bound to (cnf.jkt), when it is.</summary>
    public string? CnfJkt { get; init; }
    public JsonObject Claims { get; init; } = new();
}

/// <summary>
/// Your authorization server, taking ID-JAGs from an organization's identity provider:
/// checks the one an authenticated client presents (jwt-bearer grant) and uses it once.
/// Build one and keep it (a singleton): its used-once jti store and key cache live in the instance.
/// <code>
/// var verifier = new IdJagVerifier(new() { Issuer = "https://sso.touchque.com", Audience = "https://auth.files.example" });
/// // Per token request:
/// var claims = await verifier.VerifyAsync(form["assertion"], authenticatedClientId);
/// // An authorization server that checks DPoP proofs passes the proof key's thumbprint:
/// var bound = await verifier.VerifyAsync(form["assertion"], authenticatedClientId, dpopJkt);
/// </code>
/// </summary>
public sealed class IdJagVerifier
{
    private readonly IdJagVerifierOptions _o;
    private readonly Func<string, CancellationToken, Task<JsonObject>> _fetch;
    private readonly SemaphoreSlim _keysLock = new(1, 1);
    private readonly ConcurrentDictionary<string, long> _seen = new();
    private Dictionary<string, JsonObject> _keys = new();
    private string? _jwksUri;
    private DateTimeOffset _keysAt;
    private DateTimeOffset _triedAt;

    public IdJagVerifier(IdJagVerifierOptions options)
    {
        if (string.IsNullOrEmpty(options.Issuer) || string.IsNullOrEmpty(options.Audience))
        {
            throw new TouchqueConfigException("IdJagVerifier needs Issuer (the identity provider) and Audience (your authorization server's issuer)");
        }
        _o = options;
        _jwksUri = options.JwksUri;
        _fetch = options.Fetch ?? CrossAppAccess.GetJsonAsync;
    }

    private bool RememberOnce(string jti, long exp)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        foreach (var (k, until) in _seen)
        {
            if (until < now) _seen.TryRemove(k, out _);
        }
        return _seen.TryAdd(jti, exp + (long)_o.ClockSkew.TotalSeconds);
    }

    private async Task LoadKeysAsync(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(_jwksUri))
        {
            _jwksUri = Json.Str(await CrossAppAccess.DiscoverAsync(_o.Issuer, _fetch, ct).ConfigureAwait(false), "jwks_uri")
                ?? throw new InvalidOperationException("the identity provider names no jwks_uri");
        }
        var keys = new Dictionary<string, JsonObject>();
        if ((await _fetch(_jwksUri, ct).ConfigureAwait(false))["keys"] is JsonArray list)
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

    private async Task<JsonObject?> KeyForAsync(string kid, CancellationToken ct)
    {
        await _keysLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_keysAt == default || DateTimeOffset.UtcNow - _keysAt > TimeSpan.FromMinutes(10)) await LoadKeysAsync(ct).ConfigureAwait(false);
            if (!_keys.ContainsKey(kid) && DateTimeOffset.UtcNow - _triedAt > TimeSpan.FromMinutes(1))
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

    /// <summary>
    /// The ID-JAG, checked and used once; throws <see cref="TouchqueIdJagException"/> (Error invalid_grant).
    /// An ID-JAG bound to a DPoP key (cnf.jkt) is refused: pass the proof's thumbprint for those.
    /// </summary>
    public Task<IdJagClaims> VerifyAsync(string assertion, string clientId, CancellationToken ct = default) =>
        VerifyAsync(assertion, clientId, null, ct);

    /// <summary>
    /// The ID-JAG, checked and used once. <paramref name="dpopJkt"/>: the thumbprint of the key of the DPoP
    /// proof you verified on this request (<see cref="AgentKeys.Thumbprint"/> of its jwk), if any; an ID-JAG
    /// bound to a key (cnf.jkt) is refused without a matching one. The proof itself (typ, its signature
    /// with its jwk, htm, htu, iat, each jti once) is yours to check.
    /// </summary>
    public async Task<IdJagClaims> VerifyAsync(string assertion, string clientId, string? dpopJkt, CancellationToken ct = default)
    {
        static TouchqueIdJagException Bad(string m) => new("invalid_grant", m);
        var parts = JwsVerify.Split(assertion ?? "") ?? throw Bad("assertion is not a JWT");
        var (head, c, input, sig) = parts;
        if (Json.Str(head, "typ") != "oauth-id-jag+jwt") throw Bad("not an ID-JAG (typ oauth-id-jag+jwt)");
        var alg = Json.Str(head, "alg");
        var kid = Json.Str(head, "kid");
        if (alg is not ("RS256" or "ES256" or "EdDSA") || string.IsNullOrEmpty(kid)) throw Bad("unsupported signature");
        JsonObject? key;
        try
        {
            key = await KeyForAsync(kid, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            throw new TouchqueIdJagException("temporarily_unavailable", "the identity provider's keys could not be read: " + e.Message);
        }
        if (key is null || !JwsVerify.Verify(alg, key, input, sig)) throw Bad("signature does not verify");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var skew = (long)_o.ClockSkew.TotalSeconds;
        var auds = c["aud"] is JsonArray a ? a.Select(x => x?.GetValueKind() == System.Text.Json.JsonValueKind.String ? x.GetValue<string>() : null).ToList() : new List<string?> { Json.Str(c, "aud") };
        var exp = Json.Long(c, "exp");
        var iat = Json.Long(c, "iat");
        var sub = Json.Str(c, "sub");
        var jti = Json.Str(c, "jti");
        if (Json.Str(c, "iss") != _o.Issuer) throw Bad("another issuer");
        if (auds.Count != 1 || auds[0] != _o.Audience) throw Bad("not for this authorization server");
        if (string.IsNullOrEmpty(clientId) || Json.Str(c, "client_id") != clientId) throw Bad("issued to another client");
        if (exp is null || exp.Value + skew < now) throw Bad("expired");
        if (iat is null || iat.Value - skew > now) throw Bad("issued in the future");
        if (string.IsNullOrEmpty(sub) || string.IsNullOrEmpty(jti)) throw Bad("sub and jti are required");
        // Before the jti is spent: a copy without the key cannot use the ID-JAG up.
        string? cnfJkt = null;
        if (c.ContainsKey("cnf"))
        {
            if (c["cnf"] is not JsonObject cnf || Json.Str(cnf, "jkt") is not { } jkt) throw Bad("unsupported confirmation method (only DPoP cnf.jkt)");
            if (string.IsNullOrEmpty(dpopJkt)) throw Bad("bound to a DPoP key: a DPoP proof with that key is required");
            if (dpopJkt != jkt) throw Bad("the DPoP proof was made with another key");
            cnfJkt = jkt;
        }
        if (!(_o.FirstUse ?? RememberOnce)(jti, exp.Value)) throw Bad("already used");
        var scope = Json.Str(c, "scope");
        return new IdJagClaims
        {
            Iss = _o.Issuer, Sub = sub, Aud = _o.Audience, ClientId = clientId, Jti = jti, IssuedAt = iat.Value, ExpiresAt = exp.Value,
            Scopes = string.IsNullOrEmpty(scope) ? Array.Empty<string>() : scope.Split(' '),
            Resource = Json.Str(c, "resource"), Tenant = Json.Str(c, "tenant"), Email = Json.Str(c, "email"), AuthTime = Json.Long(c, "auth_time"),
            Amr = c["amr"] is JsonArray amr ? amr.Select(x => x?.ToString() ?? "").ToList() : Array.Empty<string>(),
            CnfJkt = cnfJkt,
            Claims = c,
        };
    }
}
