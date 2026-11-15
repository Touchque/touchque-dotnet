using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Touchque.Internal;
using Xunit;

namespace Touchque.Tests;

/// <summary>
/// The DPoP proofs of an ID-JAG key (RFC 9449): the method, the access token's hash (ath) and a
/// server's nonce; htu; and the token endpoint's one retry when the server asks for a valid nonce
/// (section 8), against a token endpoint on 127.0.0.1.
/// </summary>
public class IdJagDpopTests
{
    private static (JsonObject Header, JsonObject Claims, byte[] Input, byte[] Signature) Parse(string proof) =>
        JwsVerify.Split(proof) ?? throw new InvalidOperationException("not a JWS: " + proof);

    private static string B64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [Fact]
    public void AProofCarriesTheMethodTheTokenHashAndTheNonce()
    {
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // The two-argument call: a POST to a token endpoint, without ath or nonce.
        var post = Parse(CrossAppAccess.IdJagDpopProof(key, "https://sso.touchque.com/sso/token?x=1#f"));
        Assert.Equal(("POST", "https://sso.touchque.com/sso/token"), (Json.Str(post.Claims, "htm"), Json.Str(post.Claims, "htu")));
        Assert.Equal(new[] { "htm", "htu", "iat", "jti" }, post.Claims.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(("dpop+jwt", "ES256"), (Json.Str(post.Header, "typ"), Json.Str(post.Header, "alg")));
        var jwk = (JsonObject)post.Header["jwk"]!;
        Assert.Equal(new[] { "crv", "kty", "x", "y" }, jwk.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(("EC", "P-256", 32, 32), (Json.Str(jwk, "kty"), Json.Str(jwk, "crv"), Base64Url.Decode(Json.Str(jwk, "x")!).Length, Base64Url.Decode(Json.Str(jwk, "y")!).Length));
        Assert.Equal(key.Thumbprint, AgentKeys.Thumbprint(jwk));
        Assert.Equal(64, post.Signature.Length);
        Assert.True(JwsVerify.Verify("ES256", jwk, post.Input, post.Signature));
        Assert.Matches("\"iat\":[0-9]+[,}]", Encoding.UTF8.GetString(Base64Url.Decode(Encoding.ASCII.GetString(post.Input).Split('.')[1])));
        Assert.InRange(Json.Long(post.Claims, "iat")!.Value, now - 5, now + 5);
        Assert.Matches("^[0-9a-f]{32}$", Json.Str(post.Claims, "jti"));

        // A call with the DPoP-bound access token: its method (sent uppercase), ath over the token's ASCII bytes.
        const string token = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZGEifQ.c2ln-_~+/";
        var get = Parse(CrossAppAccess.IdJagDpopProof(key, "https://API.Example.com:443/v1/files?x=1", "get", token));
        Assert.Equal(("GET", "https://api.example.com/v1/files"), (Json.Str(get.Claims, "htm"), Json.Str(get.Claims, "htu")));
        Assert.Equal(B64Url(SHA256.HashData(Encoding.ASCII.GetBytes(token))), Json.Str(get.Claims, "ath"));
        Assert.False(get.Claims.ContainsKey("nonce"));
        Assert.True(JwsVerify.Verify("ES256", key.PublicJwk, get.Input, get.Signature));

        // A server's nonce, with or without a token; every proof has its own jti.
        var both = Parse(CrossAppAccess.IdJagDpopProof(key, "https://api.example.com/v1/files", "DELETE", token, "n-1"));
        Assert.Equal(("DELETE", "n-1", Json.Str(get.Claims, "ath")), (Json.Str(both.Claims, "htm"), Json.Str(both.Claims, "nonce"), Json.Str(both.Claims, "ath")));
        var nonceOnly = Parse(CrossAppAccess.IdJagDpopProof(key, "https://sso.touchque.com/sso/token", nonce: "eyJ7Ijp9.n"));
        Assert.Equal(("POST", "eyJ7Ijp9.n"), (Json.Str(nonceOnly.Claims, "htm"), Json.Str(nonceOnly.Claims, "nonce")));
        Assert.False(nonceOnly.Claims.ContainsKey("ath"));
        Assert.Equal(4, new[] { post, get, both, nonceOnly }.Select(p => Json.Str(p.Claims, "jti")).Distinct().Count());

        // The jwk is the key's public part only, whatever is done to the copy PublicJwk hands out.
        var copy = key.PublicJwk;
        copy["d"] = "not-a-private-key";
        copy["kid"] = "k1";
        var after = (JsonObject)Parse(CrossAppAccess.IdJagDpopProof(key, "https://sso.touchque.com/sso/token")).Header["jwk"]!;
        Assert.Equal(new[] { "crv", "kty", "x", "y" }, after.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(key.Thumbprint, AgentKeys.Thumbprint(after));

        // Not an absolute http(s) URL: a setup mistake.
        foreach (var url in new[] { "/sso/token", "ftp://example.com/token", "mailto:a@example.com", "", "https://" })
        {
            Assert.Throws<TouchqueConfigException>(() => CrossAppAccess.IdJagDpopProof(key, url));
        }
    }

    /// <summary>htm: the method trimmed and uppercased, POST when empty.</summary>
    [Theory]
    [InlineData("GET", "GET")]
    [InlineData("get", "GET")]
    [InlineData(" patch\t", "PATCH")]
    [InlineData("\r\nDelete\n", "DELETE")]
    [InlineData("m-search", "M-SEARCH")]
    [InlineData("!#$%&'*+-.^_`|~09az", "!#$%&'*+-.^_`|~09AZ")]
    [InlineData("", "POST")]
    [InlineData("   ", "POST")]
    [InlineData(null, "POST")]
    public void HtmIsTheMethodTrimmedAndUppercased(string? method, string htm)
    {
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        Assert.Equal(htm, Json.Str(Parse(CrossAppAccess.IdJagDpopProof(key, "https://example.com/t", method!)).Claims, "htm"));
    }

    /// <summary>A method is an RFC 9110 token: anything else is a setup mistake (also "poſt", which ToUpperInvariant makes POST).</summary>
    [Theory]
    [InlineData("GE T")]
    [InlineData("GET,POST")]
    [InlineData("GET;")]
    [InlineData("(GET)")]
    [InlineData("G\"ET")]
    [InlineData("GET/1")]
    [InlineData("GET\\")]
    [InlineData("GET\u0000")]
    [InlineData("G\u007FET")]
    [InlineData("GÉT")]
    [InlineData("gıt")]
    [InlineData("poſt")]
    [InlineData("GET\U0001F600")]
    public void AMethodThatIsNotATokenIsASetupMistake(string method)
    {
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        Assert.Throws<TouchqueConfigException>(() => CrossAppAccess.IdJagDpopProof(key, "https://example.com/t", method));
    }

    /// <summary>For these URLs, the expected values are what Node's URL (WHATWG) writes as protocol//host + pathname.</summary>
    [Theory]
    [InlineData("https://sso.touchque.com/sso/token?x=1#f", "https://sso.touchque.com/sso/token")]
    [InlineData("https://API.Example.com:443/v1/files?x=1", "https://api.example.com/v1/files")]
    [InlineData("HTTPS://Host.Example.COM:8443/a/b?q#f", "https://host.example.com:8443/a/b")]
    [InlineData("http://example.com:80", "http://example.com/")]
    [InlineData("http://example.com:443/p", "http://example.com:443/p")]
    [InlineData("https://example.com:0443/p", "https://example.com/p")]
    [InlineData("https://example.com", "https://example.com/")]
    [InlineData("https://example.com?x", "https://example.com/")]
    [InlineData("https://example.com#f", "https://example.com/")]
    [InlineData("http://localhost:5001/sso/token", "http://localhost:5001/sso/token")]
    [InlineData("https://example.com/a%7Eb/%7e/%41/%2F/%2f", "https://example.com/a%7Eb/%7e/%41/%2F/%2f")]
    [InlineData("https://example.com/a%zz/a%", "https://example.com/a%zz/a%")]
    [InlineData("https://example.com/a/./b/../c", "https://example.com/a/c")]
    [InlineData("https://example.com/a/%2e/b/%2E%2E/c", "https://example.com/a/c")]
    [InlineData("https://example.com/.%2e/x", "https://example.com/x")]
    [InlineData("https://example.com/a%2e%2E/x", "https://example.com/a%2e%2E/x")]
    [InlineData("https://example.com/a/b/%2e%2e", "https://example.com/a/")]
    [InlineData("https://example.com/a/.", "https://example.com/a/")]
    [InlineData("https://example.com/..", "https://example.com/")]
    [InlineData("https://example.com//a//b/", "https://example.com//a//b/")]
    [InlineData("https://example.com/a\\b", "https://example.com/a/b")]
    [InlineData("https://example.com/a b\"c<d>e`f^g{h}|~", "https://example.com/a%20b%22c%3Cd%3Ee%60f%5Eg%7Bh%7D|~")]
    [InlineData("https://example.com/café/\U0001F600", "https://example.com/caf%C3%A9/%F0%9F%98%80")]
    [InlineData("https://example.com/a;b=c,d!e$f&g'h(i)j*k+l:m@n", "https://example.com/a;b=c,d!e$f&g'h(i)j*k+l:m@n")]
    [InlineData("https://user:pass@example.com/p", "https://example.com/p")]
    [InlineData("https://bücher.example/p", "https://xn--bcher-kva.example/p")]
    [InlineData("https://[0:0::1]:8443/p", "https://[::1]:8443/p")]
    [InlineData("http://0x7f.0.0.1/p", "http://127.0.0.1/p")]
    [InlineData(" https://ex\tample.com/p\na ", "https://example.com/pa")]
    public void HtuIsWhatNodesUrlWritesForTheseUrls(string url, string htu)
    {
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        Assert.Equal(htu, Json.Str(Parse(CrossAppAccess.IdJagDpopProof(key, url)).Claims, "htu"));
    }

    /// <summary>Not a full WHATWG URL normalization: System.Uri must accept the URL, and its host is written as System.Uri reads it.</summary>
    [Fact]
    public void HtuTakesTheUrlAsSystemUriParsesIt()
    {
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        // Node's URL writes https://[::ffff:102:304]/p, and accepts the next two as https://example.com/p.
        Assert.Equal("https://[::ffff:1.2.3.4]/p", Json.Str(Parse(CrossAppAccess.IdJagDpopProof(key, "https://[::ffff:1.2.3.4]/p")).Claims, "htu"));
        Assert.Throws<TouchqueConfigException>(() => CrossAppAccess.IdJagDpopProof(key, "https:example.com/p"));
        Assert.Throws<TouchqueConfigException>(() => CrossAppAccess.IdJagDpopProof(key, "https://ex%41mple.com/p"));
    }

    private const string UseDpopNonce = "{\"error\":\"use_dpop_nonce\",\"error_description\":\"Authorization server requires nonce in DPoP proof\"}";

    private sealed record Seen(string Path, string RawTarget, string? Dpop, string? Authorization, string Body)
    {
        public JsonObject Proof => Parse(Dpop ?? throw new InvalidOperationException("no DPoP header")).Claims;
    }

    private sealed record Answer(int Status, string? Body, params (string Name, string Value)[] Headers);

    /// <summary>A token endpoint on 127.0.0.1: records every request and answers with <see cref="Reply"/>.</summary>
    private sealed class TokenEndpoint : IAsyncDisposable
    {
        private WebApplication _app = null!;
        private readonly List<Seen> _seen = new();

        public string Url { get; private set; } = "";
        public Func<int, Seen, Answer> Reply { get; set; } = (_, _) => new Answer(200, "{}");

        public IReadOnlyList<Seen> Requests
        {
            get
            {
                lock (_seen) return _seen.ToList();
            }
        }

        public void Clear()
        {
            lock (_seen) _seen.Clear();
        }

        public static async Task<TokenEndpoint> StartAsync()
        {
            var endpoint = new TokenEndpoint();
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            endpoint._app = builder.Build();
            endpoint._app.Run(async http =>
            {
                var seen = new Seen(http.Request.Path + http.Request.QueryString, http.Features.Get<IHttpRequestFeature>()!.RawTarget,
                    http.Request.Headers["DPoP"].FirstOrDefault(), http.Request.Headers.Authorization.FirstOrDefault(), await new StreamReader(http.Request.Body).ReadToEndAsync());
                int n;
                lock (endpoint._seen)
                {
                    endpoint._seen.Add(seen);
                    n = endpoint._seen.Count;
                }
                var answer = endpoint.Reply(n, seen);
                http.Response.StatusCode = answer.Status;
                foreach (var (name, value) in answer.Headers) http.Response.Headers.Append(name, value);
                if (answer.Body is not null)
                {
                    http.Response.ContentType = "application/json";
                    await http.Response.WriteAsync(answer.Body);
                }
            });
            await endpoint._app.StartAsync();
            endpoint.Url = endpoint._app.Urls.First().TrimEnd('/');
            return endpoint;
        }

        public async ValueTask DisposeAsync() => await _app.DisposeAsync();
    }

    private static string IdJagAnswer(string header, JsonObject claims) => new JsonObject
    {
        ["access_token"] = Base64Url.Encode(header) + "." + Base64Url.Encode(claims.ToJsonString()) + ".c2ln",
        ["issued_token_type"] = CrossAppAccess.IdJagTokenType, ["token_type"] = "N_A",
    }.ToJsonString();

    [Fact]
    public async Task RedeemSendsTheSameRequestOnceMoreWithTheServersNonce()
    {
        await using var server = await TokenEndpoint.StartAsync();
        server.Reply = (_, r) => Json.Str(r.Proof, "nonce") == "n1"
            ? new Answer(200, "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}")
            : new Answer(400, UseDpopNonce, ("DPoP-Nonce", "n1"));
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        var tokens = await CrossAppAccess.RedeemIdJagAsync(new()
        {
            TokenEndpoint = server.Url + "/token?x=1", ClientId = "acme-at-rs", ClientSecret = "s3cret", Assertion = "the-id-jag",
            Resource = "https://rs.example/files", Scope = "files:read", DpopKey = key,
        });
        Assert.Equal("DPoP", Json.Str(tokens, "token_type"));
        var seen = server.Requests;
        Assert.Equal(2, seen.Count);
        // The same request (path, form body, client authentication), with a new proof that carries the nonce.
        Assert.Equal((seen[0].Path, seen[0].Body, seen[0].Authorization), (seen[1].Path, seen[1].Body, seen[1].Authorization));
        Assert.Equal("/token?x=1", seen[1].Path);
        Assert.StartsWith("Basic ", seen[1].Authorization);
        Assert.Contains("assertion=the-id-jag", seen[1].Body);
        Assert.False(seen[0].Proof.ContainsKey("nonce"));
        Assert.Equal(("n1", "POST", server.Url + "/token"), (Json.Str(seen[1].Proof, "nonce"), Json.Str(seen[1].Proof, "htm"), Json.Str(seen[1].Proof, "htu")));
        Assert.NotEqual(Json.Str(seen[0].Proof, "jti"), Json.Str(seen[1].Proof, "jti"));
        Assert.NotEqual(seen[0].Dpop, seen[1].Dpop);
        Assert.True(Json.Long(seen[1].Proof, "iat") >= Json.Long(seen[0].Proof, "iat"));
    }

    [Fact]
    public async Task TheTokenEndpointProofNamesTheUrlHttpClientSends()
    {
        // System.Uri decodes %7E and %41, removes dot segments and escapes | on the wire: the proof names that URL.
        await using var server = await TokenEndpoint.StartAsync();
        server.Reply = (_, _) => new Answer(200, "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}");
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        await CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = server.Url + "/a%7Eb/./c|d/%41?x=1#f", ClientId = "acme", Assertion = "jag", DpopKey = key });
        var seen = Assert.Single(server.Requests);
        Assert.Equal("/a~b/c%7Cd/A?x=1", seen.RawTarget);
        Assert.Equal(server.Url + "/a~b/c%7Cd/A", Json.Str(seen.Proof, "htu"));
    }

    [Fact]
    public async Task RequestRetriesOnUseDpopNonceInTheBodyOrInA401Challenge()
    {
        await using var server = await TokenEndpoint.StartAsync();
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        var bound = IdJagAnswer("{\"typ\":\"oauth-id-jag+jwt\",\"alg\":\"RS256\"}", new JsonObject { ["cnf"] = new JsonObject { ["jkt"] = key.Thumbprint } });
        foreach (var askForNonce in new[]
        {
            new Answer(401, null, ("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\", error_description=\"Authorization server requires nonce in DPoP proof\""), ("DPoP-Nonce", "n-401")),
            new Answer(401, "{\"error\":\"use_dpop_nonce\"}", ("DPoP-Nonce", "n-401")),
            new Answer(400, UseDpopNonce, ("DPoP-Nonce", "n-401")),
        })
        {
            server.Clear();
            server.Reply = (_, r) => Json.Str(r.Proof, "nonce") == "n-401" ? new Answer(200, bound) : askForNonce;
            var got = await CrossAppAccess.RequestIdJagAsync(new()
            {
                TokenEndpoint = server.Url + "/idp/token", ClientId = "tqapp_test", ClientSecret = "tqs_test", IdToken = "idtoken:ada", Audience = "https://rs.example", DpopKey = key,
            });
            Assert.True(got.DpopBound);
            var seen = server.Requests;
            Assert.Equal(2, seen.Count);
            Assert.Equal((seen[0].Body, seen[0].Authorization), (seen[1].Body, seen[1].Authorization));
            Assert.Contains("subject_token=idtoken%3Aada", seen[1].Body);
            Assert.Equal((null, "n-401"), (Json.Str(seen[0].Proof, "nonce"), Json.Str(seen[1].Proof, "nonce")));
            Assert.NotEqual(Json.Str(seen[0].Proof, "jti"), Json.Str(seen[1].Proof, "jti"));
        }
    }

    [Fact]
    public async Task NoRetryWithoutAKeyAndNeverASecondOne()
    {
        await using var server = await TokenEndpoint.StartAsync();
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        Task<JsonObject> Redeem(IdJagDpopKey? dpopKey) => CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = server.Url + "/token", ClientId = "acme", Assertion = "jag", DpopKey = dpopKey });

        // Without a key: as before, one request without a DPoP header; the error carries the nonce.
        server.Reply = (_, _) => new Answer(400, UseDpopNonce, ("DPoP-Nonce", "n1"));
        var e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => Redeem(null));
        Assert.Equal(("use_dpop_nonce", (int?)400, "n1", "Authorization server requires nonce in DPoP proof"), (e.Error, e.Status, e.DpopNonce, e.Message));
        Assert.Single(server.Requests);
        Assert.Null(server.Requests[0].Dpop);
        Assert.Contains("client_id=acme", server.Requests[0].Body);

        // A server that asks again (a new nonce each time): two requests, then the usual error with the last nonce.
        server.Clear();
        server.Reply = (n, _) => new Answer(400, UseDpopNonce, ("DPoP-Nonce", "n" + n));
        e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => Redeem(key));
        Assert.Equal(("use_dpop_nonce", (int?)400, "n2"), (e.Error, e.Status, e.DpopNonce));
        Assert.Equal(2, server.Requests.Count);
        Assert.Equal("n1", Json.Str(server.Requests[1].Proof, "nonce"));
        Assert.Equal(server.Requests[0].Body, server.Requests[1].Body);

        // Not a nonce request: another error, no DPoP-Nonce header, another status. One request each.
        foreach (var (answer, error, nonce) in new[]
        {
            (new Answer(400, "{\"error\":\"invalid_grant\"}", ("DPoP-Nonce", "n1")), "invalid_grant", "n1"),
            (new Answer(400, UseDpopNonce), "use_dpop_nonce", null),
            (new Answer(403, UseDpopNonce, ("DPoP-Nonce", "n1")), "use_dpop_nonce", "n1"),
            (new Answer(500, null, ("DPoP-Nonce", "n1")), "server_error", "n1"),
            (new Answer(401, null, ("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\""), ("DPoP-Nonce", "n1")), "invalid_dpop_proof", "n1"),
            (new Answer(401, null, ("WWW-Authenticate", "Bearer error=\"use_dpop_nonce\""), ("DPoP-Nonce", "n1")), "server_error", "n1"),
        })
        {
            server.Clear();
            server.Reply = (_, _) => answer;
            e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => Redeem(key));
            Assert.Equal((error, (int?)answer.Status, nonce), (e.Error, e.Status, e.DpopNonce));
            Assert.Single(server.Requests);
        }
    }

    [Fact]
    public async Task AnIdJagThatRepeatsAMemberIsNotBound()
    {
        // JwsVerify.Split refuses it, so DpopBound is false instead of an ArgumentException from System.Text.Json.
        await using var server = await TokenEndpoint.StartAsync();
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        foreach (var (header, claims) in new[]
        {
            ("{\"typ\":\"oauth-id-jag+jwt\",\"typ\":\"oauth-id-jag+jwt\",\"alg\":\"RS256\"}", new JsonObject { ["cnf"] = new JsonObject { ["jkt"] = key.Thumbprint } }),
            ("{\"typ\":\"oauth-id-jag+jwt\",\"alg\":\"RS256\"}", null),
        })
        {
            var body = claims is null
                ? new JsonObject
                {
                    ["access_token"] = Base64Url.Encode(header) + "." + Base64Url.Encode("{\"cnf\":{\"jkt\":\"" + key.Thumbprint + "\",\"jkt\":\"" + key.Thumbprint + "\"}}") + ".c2ln",
                    ["issued_token_type"] = CrossAppAccess.IdJagTokenType,
                }.ToJsonString()
                : IdJagAnswer(header, claims);
            server.Reply = (_, _) => new Answer(200, body);
            var got = await CrossAppAccess.RequestIdJagAsync(new()
            {
                TokenEndpoint = server.Url + "/idp/token", ClientId = "tqapp_test", ClientSecret = "tqs_test", IdToken = "idtoken:ada", Audience = "https://rs.example", DpopKey = key,
            });
            Assert.False(got.DpopBound);
        }
    }

    /// <summary>
    /// A token endpoint on 127.0.0.1 that writes its answers byte for byte (Kestrel refuses control and
    /// non-ASCII characters in a header value): one request per connection, answered by <see cref="Reply"/>.
    /// </summary>
    private sealed class RawEndpoint : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly List<string?> _proofs = new();

        public RawEndpoint()
        {
            _listener.Start();
            Url = $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/token";
            _ = Task.Run(AcceptAsync);
        }

        public string Url { get; }

        /// <summary>The answer to the n-th request (from 1): raw HTTP/1.1, sent as Latin-1.</summary>
        public Func<int, string> Reply { get; set; } = _ => Answer(200, "{}");

        /// <summary>The DPoP header of each request so far.</summary>
        public IReadOnlyList<string?> Proofs
        {
            get
            {
                lock (_proofs) return _proofs.ToList();
            }
        }

        public void Clear()
        {
            lock (_proofs) _proofs.Clear();
        }

        public static string Answer(int status, string body, params string[] headers) =>
            $"HTTP/1.1 {status} Answer\r\nContent-Type: application/json\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n"
            + string.Concat(headers.Select(h => h + "\r\n")) + "\r\n" + body;

        private async Task AcceptAsync()
        {
            while (true)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync();
                }
                catch (Exception e) when (e is SocketException or ObjectDisposedException or InvalidOperationException)
                {
                    return;
                }
                _ = Task.Run(() => ServeAsync(client));
            }
        }

        private async Task ServeAsync(TcpClient client)
        {
            using var connection = client;
            var stream = client.GetStream();
            var buffer = new byte[16384];
            var request = new StringBuilder();
            int end;
            while ((end = request.ToString().IndexOf("\r\n\r\n", StringComparison.Ordinal)) < 0)
            {
                var n = await stream.ReadAsync(buffer);
                if (n == 0) return;
                request.Append(Encoding.Latin1.GetString(buffer, 0, n));
            }
            var lines = request.ToString(0, end).Split("\r\n");
            var length = lines.Where(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                .Select(l => int.Parse(l[15..].Trim(), CultureInfo.InvariantCulture)).FirstOrDefault();
            for (var have = request.Length - end - 4; have < length;)
            {
                var n = await stream.ReadAsync(buffer);
                if (n == 0) break;
                have += n;
            }
            int count;
            lock (_proofs)
            {
                _proofs.Add(lines.FirstOrDefault(l => l.StartsWith("DPoP:", StringComparison.OrdinalIgnoreCase))?[5..].Trim());
                count = _proofs.Count;
            }
            try
            {
                await stream.WriteAsync(Encoding.Latin1.GetBytes(Reply(count)));
            }
            catch (IOException)
            {
                // The client stopped reading (an answer over its header limit).
            }
        }

        public void Dispose() => _listener.Stop();
    }

    private const string NonceAsked = "{\"error\":\"use_dpop_nonce\"}";
    private const string Tokens = "{\"access_token\":\"at\",\"token_type\":\"DPoP\"}";
    private const string EveryNqchar = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~";

    /// <summary>RFC 9449: nonce = 1*NQCHAR, NQCHAR = %x21 / %x23-5B / %x5D-7E; a header that repeats must repeat the same value.</summary>
    [Fact]
    public void OnlyAValidNonceCounts()
    {
        Assert.Equal(EveryNqchar, CrossAppAccess.ValidDpopNonce(new[] { EveryNqchar }));
        Assert.Equal("n1", CrossAppAccess.ValidDpopNonce(new[] { "n1", "n1" }));
        Assert.Equal("!", CrossAppAccess.ValidDpopNonce(new[] { "!" }));
        foreach (var values in new[]
        {
            Array.Empty<string>(), new[] { "" }, new[] { "n1", "n2" }, new[] { "", "n1" }, new[] { "n1", "" }, new[] { "a b" }, new[] { "a\"b" },
            new[] { "a\\b" }, new[] { "a\u00E9b" }, new[] { "a\u0001b" }, new[] { "a\u007Fb" }, new[] { "a\u0000b" }, new[] { "a\tb" }, new[] { " n1" },
            new[] { "n\U0001F600" }, new[] { "n1", "n1 " }, new[] { "n1", "n1", "n2" },
        })
        {
            Assert.Null(CrossAppAccess.ValidDpopNonce(values));
        }
    }

    [Fact]
    public async Task AWeirdNonceGetsNoRetryAndStaysOffTheError()
    {
        using var server = new RawEndpoint();
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        Task<JsonObject> Redeem(IdJagDpopKey? dpopKey) => CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = server.Url, ClientId = "acme", Assertion = "jag", DpopKey = dpopKey });

        // Missing, empty, two values, or not 1*NQCHAR (also a control, DEL, NUL, Latin-1, a bare CR, a folded line):
        // the usual error, one request, and no DpopNonce. Never another exception type.
        foreach (var headers in new[]
        {
            Array.Empty<string>(), new[] { "DPoP-Nonce: " }, new[] { "DPoP-Nonce: n1", "DPoP-Nonce: n2" }, new[] { "DPoP-Nonce: ", "DPoP-Nonce: n1" },
            new[] { "DPoP-Nonce: a b" }, new[] { "DPoP-Nonce: a\"b" }, new[] { "DPoP-Nonce: a\\b" }, new[] { "DPoP-Nonce: a\u00E9b" },
            new[] { "DPoP-Nonce: a\u0001b" }, new[] { "DPoP-Nonce: a\u007Fb" }, new[] { "DPoP-Nonce: a\u0000b" }, new[] { "DPoP-Nonce: a\tb" },
            new[] { "DPoP-Nonce: a\rb" }, new[] { "DPoP-Nonce: a\r\n b" },
        })
        {
            foreach (var answer in new[] { RawEndpoint.Answer(400, NonceAsked, headers), RawEndpoint.Answer(401, "", headers.Append("WWW-Authenticate: DPoP error=\"use_dpop_nonce\"").ToArray()) })
            {
                foreach (var dpopKey in new[] { key, null })
                {
                    server.Clear();
                    server.Reply = n => n == 1 ? answer : RawEndpoint.Answer(200, Tokens);
                    var e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => Redeem(dpopKey));
                    Assert.Equal(("use_dpop_nonce", (string?)null), (e.Error, e.DpopNonce));
                    Assert.Single(server.Proofs);
                }
            }
        }

        // Valid: the same value twice, padding the HTTP parser strips, a comma, every NQCHAR. The retry's proof carries it as sent.
        foreach (var (headers, nonce) in new[]
        {
            (new[] { "DPoP-Nonce: n1", "DPoP-Nonce: n1" }, "n1"), (new[] { "DPoP-Nonce:   n1 \t" }, "n1"), (new[] { "DPoP-Nonce: a,b" }, "a,b"),
            (new[] { "DPoP-Nonce: " + EveryNqchar }, EveryNqchar),
        })
        {
            server.Clear();
            server.Reply = n => n == 1 ? RawEndpoint.Answer(400, NonceAsked, headers) : RawEndpoint.Answer(200, Tokens);
            Assert.Equal("at", Json.Str(await Redeem(key), "access_token"));
            var proofs = server.Proofs;
            Assert.Equal((null, nonce), (Json.Str(Parse(proofs[0]!).Claims, "nonce"), Json.Str(Parse(proofs[1]!).Claims, "nonce")));
        }
    }

    [Fact]
    public async Task TheErrorCarriesTheLatestValidNonceOfTheCall()
    {
        using var server = new RawEndpoint();
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        var first = RawEndpoint.Answer(400, NonceAsked, "DPoP-Nonce: n1");
        foreach (var (retried, error, nonce) in new[]
        {
            (RawEndpoint.Answer(400, NonceAsked, "DPoP-Nonce: n2"), "use_dpop_nonce", "n2"),
            (RawEndpoint.Answer(400, "{\"error\":\"invalid_grant\"}"), "invalid_grant", "n1"),
            (RawEndpoint.Answer(401, "", "WWW-Authenticate: DPoP error=\"invalid_dpop_proof\"", "DPoP-Nonce: not valid"), "invalid_dpop_proof", "n1"),
            (RawEndpoint.Answer(500, "oops", "DPoP-Nonce: n2", "DPoP-Nonce: n3"), "server_error", "n1"),
        })
        {
            server.Clear();
            server.Reply = n => n == 1 ? first : retried;
            var e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = server.Url, ClientId = "acme", Assertion = "jag", DpopKey = key }));
            Assert.Equal((error, nonce), (e.Error, e.DpopNonce));
            Assert.Equal(2, server.Proofs.Count);
        }
    }

    /// <summary>The challenge's error param of a DPoP challenge only (RFC 9110 section 11.6.1); quoted strings are values, never params.</summary>
    [Theory]
    [InlineData("DPoP error=\"use_dpop_nonce\"", "use_dpop_nonce")]
    [InlineData("DPoP error=use_dpop_nonce", "use_dpop_nonce")]
    [InlineData("dpop ERROR = \"use_dpop_nonce\"", "use_dpop_nonce")]
    [InlineData("DPoP algs=\"ES256 PS256\", error=\"invalid_token\"", "invalid_token")]
    [InlineData("DPoP error_description=\"x, error=use_dpop_nonce\", error=\"invalid_token\"", "invalid_token")]
    [InlineData("DPoP error_description=\"say \\\"error=use_dpop_nonce\\\"\", error=\"invalid_dpop_proof\"", "invalid_dpop_proof")]
    [InlineData("DPoP error=\"a\\\"b\"", "a\"b")]
    [InlineData("Bearer error=\"use_dpop_nonce\"", null)]
    [InlineData("Bearer error=\"invalid_token\", DPoP error=\"use_dpop_nonce\"", "use_dpop_nonce")]
    [InlineData("DPoP realm=\"x\", Bearer error=\"use_dpop_nonce\"", null)]
    [InlineData("Basic realm=\"x\", DPoP algs=\"ES256\", error=\"use_dpop_nonce\"", "use_dpop_nonce")]
    [InlineData("DPoP error=\"\"", null)]
    [InlineData("DPoP error=", null)]
    [InlineData("DPoP error=\"\", error=\"invalid_token\"", "invalid_token")]
    [InlineData("DPoP", null)]
    [InlineData("", null)]
    [InlineData("DPoP error=\"unterminated", "unterminated")]
    public void TheChallengeErrorIsTheErrorParamOfADpopChallenge(string header, string? error)
    {
        Assert.Equal(error, CrossAppAccess.DpopChallengeError(new[] { header }));
        // A challenge per WWW-Authenticate field.
        Assert.Equal(error, CrossAppAccess.DpopChallengeError(new[] { "Bearer realm=\"api\"", header }));
    }

    [Fact]
    public async Task AnEmptyErrorIsNotTheError()
    {
        using var server = new RawEndpoint();
        foreach (var (answer, error) in new[]
        {
            (RawEndpoint.Answer(401, "", "WWW-Authenticate: DPoP error=\"\""), "server_error"),
            (RawEndpoint.Answer(401, "", "WWW-Authenticate: DPoP error="), "server_error"),
            (RawEndpoint.Answer(401, "", "WWW-Authenticate: DPoP error=\"\", error_description=\"x\""), "server_error"),
            (RawEndpoint.Answer(401, "{\"error\":\"invalid_client\"}", "WWW-Authenticate: DPoP error=\"\""), "invalid_client"),
            (RawEndpoint.Answer(400, "{\"error\":\"\"}"), "server_error"),
            (RawEndpoint.Answer(401, "{\"error\":\"\"}", "WWW-Authenticate: DPoP error=\"invalid_token\""), "invalid_token"),
        })
        {
            server.Reply = _ => answer;
            var e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = server.Url, ClientId = "acme", Assertion = "jag" }));
            Assert.Equal(error, e.Error);
        }
    }

    /// <summary>
    /// 64 KB headers: WWW-Authenticate and DPoP-Nonce are read in one linear pass that never throws, so a 200
    /// still gives its answer and a 401 its ID-JAG error, each well under a second.
    /// </summary>
    [Fact]
    public async Task LongHeadersGiveTheAnswerOrTheErrorFast()
    {
        var quoted = "DPoP x=\"" + new string('q', 65536) + "\"";
        var commas = "DPoP " + string.Concat(Enumerable.Repeat("a,", 30000));

        // The parsers alone, on shapes that are slow for a backtracking or quadratic scanner.
        foreach (var header in new[]
        {
            quoted, commas, "DPoP " + string.Concat(Enumerable.Repeat("a=,", 21845)), "DPoP " + new string('"', 65536),
            "DPoP x=\"" + new string('\\', 65536), "," + new string(' ', 65536) + "x", "DPoP " + string.Concat(Enumerable.Repeat("a ", 32768)),
            "DPoP error=" + new string('=', 65536), "DPoP " + string.Concat(Enumerable.Repeat("error=\"\",", 7000)),
            "DPoP " + string.Concat(Enumerable.Repeat("x=\"\\\"\",", 9000)), new string('n', 65535) + " ",
        })
        {
            var watch = Stopwatch.StartNew();
            Assert.Null(CrossAppAccess.DpopChallengeError(new[] { header }));
            Assert.Null(CrossAppAccess.DpopChallengeError(Enumerable.Repeat(header[..640], 100)));
            Assert.Null(CrossAppAccess.ValidDpopNonce(new[] { header }));
            Assert.InRange(watch.ElapsedMilliseconds, 0, 500);
        }
        var nonceWatch = Stopwatch.StartNew();
        Assert.Equal(65536, CrossAppAccess.ValidDpopNonce(new[] { new string('n', 65536) })!.Length);
        Assert.Equal("n1", CrossAppAccess.ValidDpopNonce(Enumerable.Repeat("n1", 30000)));
        Assert.Null(CrossAppAccess.ValidDpopNonce(Enumerable.Repeat("n1", 30000).Append("n2")));
        Assert.InRange(nonceWatch.ElapsedMilliseconds, 0, 500);

        // Through the token endpoint call.
        using var server = new RawEndpoint();
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        Task<JsonObject> Redeem(IdJagDpopKey? dpopKey) => CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = server.Url, ClientId = "acme", Assertion = "jag", DpopKey = dpopKey });
        server.Reply = _ => RawEndpoint.Answer(200, Tokens);
        await Redeem(key);
        foreach (var (header, retried) in new[] { (quoted, quoted + ", error=\"use_dpop_nonce\""), (commas, commas + "DPoP error=\"use_dpop_nonce\"") })
        {
            // A 200 without a key: the answer.
            server.Clear();
            server.Reply = _ => RawEndpoint.Answer(200, Tokens, "WWW-Authenticate: " + header);
            var watch = Stopwatch.StartNew();
            Assert.Equal("at", Json.Str(await Redeem(null), "access_token"));
            Assert.InRange(watch.ElapsedMilliseconds, 0, 999);

            // A 401 with a key and a nonce: the usual error (no DPoP error here, so no retry), with the nonce.
            server.Clear();
            server.Reply = _ => RawEndpoint.Answer(401, "", "WWW-Authenticate: " + header, "DPoP-Nonce: n1");
            watch.Restart();
            var e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => Redeem(key));
            Assert.InRange(watch.ElapsedMilliseconds, 0, 999);
            Assert.Equal(("server_error", (int?)401, "n1"), (e.Error, e.Status, e.DpopNonce));
            Assert.Single(server.Proofs);

            // A DPoP error after the long part still counts: the one retry, then the answer.
            server.Clear();
            server.Reply = n => n == 1 ? RawEndpoint.Answer(401, "", "WWW-Authenticate: " + retried, "DPoP-Nonce: n1") : RawEndpoint.Answer(200, Tokens);
            watch.Restart();
            Assert.Equal("at", Json.Str(await Redeem(key), "access_token"));
            Assert.InRange(watch.ElapsedMilliseconds, 0, 999);
            Assert.Equal(2, server.Proofs.Count);
        }

        // Over 256 KB of headers HttpClient reads no answer: still a TouchqueIdJagException, not an HttpRequestException.
        server.Clear();
        server.Reply = _ => RawEndpoint.Answer(400, NonceAsked, "DPoP-Nonce: " + new string('n', 300_000));
        var big = await Assert.ThrowsAsync<TouchqueIdJagException>(() => Redeem(key));
        Assert.Equal(("invalid_response", (int?)null, (string?)null), (big.Error, big.Status, big.DpopNonce));
    }

    [Fact]
    public async Task ATokenEndpointAnswerThatRepeatsAMemberIsAnIdJagError()
    {
        using var server = new RawEndpoint();
        using var key = CrossAppAccess.CreateIdJagDpopKey();
        const string jag = CrossAppAccess.IdJagTokenType;

        // 2xx: refused before any read (each threw ArgumentException or InvalidOperationException on its first read).
        foreach (var body in new[]
        {
            "{\"access_token\":\"a\",\"access_token\":\"b\"}", "{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"x\":{\"k\":1,\"k\":2}}",
            "{\"access_token\":\"a\",\"t\\u006fken_type\":\"DPoP\",\"token_type\":\"N_A\"}", "{\"access_token\":\"\\ud800\"}",
            $"{{\"access_token\":\"a\",\"issued_token_type\":\"{jag}\",\"issued_token_type\":\"{jag}\"}}",
        })
        {
            server.Reply = _ => RawEndpoint.Answer(200, body);
            var e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = server.Url, ClientId = "acme", Assertion = "jag" }));
            Assert.Equal(("invalid_response", (int?)200), (e.Error, e.Status));
            e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => CrossAppAccess.RequestIdJagAsync(new()
            {
                TokenEndpoint = server.Url, ClientId = "tqapp_test", ClientSecret = "tqs_test", IdToken = "idtoken:ada", Audience = "https://rs.example", DpopKey = key,
            }));
            Assert.Equal(("invalid_response", (int?)200), (e.Error, e.Status));
        }
        // A 2xx answer that is not JSON is read as before: an empty object.
        server.Reply = _ => RawEndpoint.Answer(200, "not json");
        Assert.Empty(await CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = server.Url, ClientId = "acme", Assertion = "jag" }));

        // An error answer: its body is not read, so the error is the DPoP challenge's or server_error.
        foreach (var (answer, error) in new[]
        {
            (RawEndpoint.Answer(400, "{\"error\":\"invalid_grant\",\"error\":\"invalid_client\"}"), "server_error"),
            (RawEndpoint.Answer(400, "{\"error\":\"\\udc00\"}"), "server_error"),
            (RawEndpoint.Answer(400, "{\"error\":\"use_dpop_nonce\",\"error\":\"use_dpop_nonce\"}", "DPoP-Nonce: n1"), "server_error"),
            (RawEndpoint.Answer(401, "{\"error\":\"x\",\"error\":\"y\"}", "WWW-Authenticate: DPoP error=\"invalid_dpop_proof\""), "invalid_dpop_proof"),
        })
        {
            server.Clear();
            server.Reply = _ => answer;
            var e = await Assert.ThrowsAsync<TouchqueIdJagException>(() => CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = server.Url, ClientId = "acme", Assertion = "jag", DpopKey = key }));
            Assert.Equal(error, e.Error);
            Assert.Single(server.Proofs);
        }
        // A DPoP challenge that asks for the nonce still gets the retry.
        server.Clear();
        server.Reply = n => n == 1
            ? RawEndpoint.Answer(401, "{\"error\":\"x\",\"error\":\"y\"}", "WWW-Authenticate: DPoP error=\"use_dpop_nonce\"", "DPoP-Nonce: n1")
            : RawEndpoint.Answer(200, Tokens);
        Assert.Equal("at", Json.Str(await CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = server.Url, ClientId = "acme", Assertion = "jag", DpopKey = key }), "access_token"));
        Assert.Equal(2, server.Proofs.Count);
    }
}
