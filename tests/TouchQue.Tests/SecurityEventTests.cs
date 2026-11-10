using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using TouchQue.Internal;
using Xunit;

namespace TouchQue.Tests;

/// <summary>
/// Shared Signals SETs: the cross-SDK vectors (fixtures/security-event-vectors.json),
/// discovery through /.well-known/ssf-configuration, and a poll (RFC 8936).
/// </summary>
public class SecurityEventTests
{
    private static JsonObject Vectors() => Paths.Fixture("security-event-vectors.json");

    private static SecurityEventVerifier Verifier(JsonObject v) => new(new SecurityEventVerifierOptions
    {
        Issuer = Json.Str(v, "issuer")!, Audience = Json.Str(v, "audience")!, Jwks = (JsonObject)v["jwks"]!,
    });

    [Fact]
    public async Task ReadsEveryValidVector()
    {
        var v = Vectors();
        foreach (var c in ((JsonArray)v["valid"]!).OfType<JsonObject>())
        {
            var e = await Verifier(v).VerifyAsync(Json.Str(c, "token")!);
            var x = (JsonObject)c["expect"]!;
            var got = new JsonObject
            {
                ["jti"] = e.Jti, ["issuer"] = e.Issuer, ["audience"] = new JsonArray(e.Audience.Select(a => (JsonNode)JsonValue.Create(a)!).ToArray()),
                ["issuedAt"] = e.IssuedAt, ["txn"] = e.Txn, ["subject"] = e.Subject.DeepClone(), ["type"] = e.Type, ["name"] = e.Name, ["claims"] = e.Claims.DeepClone(),
            };
            Assert.True(JsonNode.DeepEquals(x, got), $"{Json.Str(c, "name")}: {got.ToJsonString()}");
        }
    }

    [Fact]
    public async Task RefusesEveryInvalidVector()
    {
        var v = Vectors();
        foreach (var c in ((JsonArray)v["invalid"]!).OfType<JsonObject>())
        {
            var e = await Assert.ThrowsAsync<TouchQueSecurityEventException>(() => Verifier(v).VerifyAsync(Json.Str(c, "token")!));
            Assert.True(e.Error == Json.Str(c, "error"), $"{Json.Str(c, "name")}: {e.Error}");
        }
    }

    [Fact]
    public void ShortNames() =>
        Assert.EndsWith("/caep/event-type/session-revoked", SecurityEvents.Types["session-revoked"]);

    /// <summary>A transmitter on this machine (the shared fake API has no SSF routes): its metadata, its keys and a poll endpoint.</summary>
    private sealed class Transmitter : IAsyncDisposable
    {
        private WebApplication _app = null!;

        public string Base { get; private set; } = "";
        public string? PolledAuth { get; private set; }
        public JsonNode? PolledBody { get; private set; }

        public static async Task<Transmitter> StartAsync(JsonObject v)
        {
            var t = new Transmitter();
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            t._app = builder.Build();
            t._app.Run(async http =>
            {
                var body = await new StreamReader(http.Request.Body, Encoding.UTF8).ReadToEndAsync();
                http.Response.ContentType = "application/json";
                if (http.Request.Path.Value!.EndsWith("/.well-known/ssf-configuration", StringComparison.Ordinal))
                {
                    await http.Response.WriteAsync(new JsonObject { ["issuer"] = t.Base, ["jwks_uri"] = t.Base + "/jwks" }.ToJsonString());
                    return;
                }
                if (http.Request.Path == "/jwks")
                {
                    await http.Response.WriteAsync(v["jwks"]!.ToJsonString());
                    return;
                }
                t.PolledAuth = http.Request.Headers.Authorization.ToString();
                t.PolledBody = JsonNode.Parse(body.Length > 0 ? body : "{}");
                var first = (JsonObject)v["valid"]![0]!;
                var sets = new JsonObject { [Json.Str(first["expect"], "jti")!] = Json.Str(first, "token") };
                await http.Response.WriteAsync(new JsonObject { ["sets"] = sets, ["moreAvailable"] = false }.ToJsonString());
            });
            await t._app.StartAsync();
            t.Base = t._app.Urls.First().TrimEnd('/');
            return t;
        }

        public async ValueTask DisposeAsync() => await _app.DisposeAsync();
    }

    [Fact]
    public async Task DiscoversTheJwksAndChecksTheIssuerTheSetNames()
    {
        var v = Vectors();
        var first = (JsonObject)v["valid"]![0]!;
        await using var server = await Transmitter.StartAsync(v);
        var verifier = new SecurityEventVerifier(new SecurityEventVerifierOptions { Issuer = server.Base, Audience = Json.Str(v, "audience")! });
        // The vectors' issuer is not this one: the signature verifies with the discovered keys, the issuer does not.
        var e = await Assert.ThrowsAsync<TouchQueSecurityEventException>(() => verifier.VerifyAsync(Json.Str(first, "token")!));
        Assert.Equal("invalid_issuer", e.Error);
    }

    [Fact]
    public async Task RefusesMetadataThatNamesAnotherIssuer()
    {
        var v = Vectors();
        await using var server = await Transmitter.StartAsync(v);
        // The metadata under /other names the server's base as its issuer: no keys are trusted from it.
        var verifier = new SecurityEventVerifier(new SecurityEventVerifierOptions { Issuer = server.Base + "/other", Audience = Json.Str(v, "audience")! });
        var e = await Assert.ThrowsAsync<TouchQueSecurityEventException>(() => verifier.VerifyAsync(Json.Str((JsonObject)v["valid"]![0]!, "token")!));
        Assert.Equal("temporarily_unavailable", e.Error);
    }

    [Fact]
    public async Task PollsAcknowledgesAndReadsTheWaitingSets()
    {
        var v = Vectors();
        var first = (JsonObject)v["valid"]![0]!;
        await using var server = await Transmitter.StartAsync(v);
        var (sets, more) = await SecurityEvents.PollAsync(new PollSecurityEventsOptions { Url = server.Base + "/ssf/poll/s1", Token = "tqssf_x", Ack = ["a"], MaxEvents = 5 });
        Assert.Equal(Json.Str(first, "token"), sets[Json.Str(first["expect"], "jti")!]);
        Assert.False(more);
        Assert.Equal("Bearer tqssf_x", server.PolledAuth);
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["ack"] = new JsonArray("a"), ["maxEvents"] = 5 }, server.PolledBody), server.PolledBody?.ToJsonString());
        await Assert.ThrowsAsync<TouchQueConfigException>(() => SecurityEvents.PollAsync(new PollSecurityEventsOptions { Url = "http://sso.example/ssf/poll/s1", Token = "tqssf_x" }));
    }
}
