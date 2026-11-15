using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Touchque.AspNetCore;
using Touchque.Relay;
using Xunit;

namespace Touchque.Tests;

/// <summary>Never in parallel with another collection: these tests set TQ_API_KEY, TQ_API_SECRET and TQ_API_URL for the whole process.</summary>
[CollectionDefinition("environment", DisableParallelization = true)]
public sealed class EnvironmentCollection : ICollectionFixture<FakeApi>
{
}

/// <summary>Guard.RunAsync(null, …) and Guard.IsStatusPoll(null, …): the default client, built from the environment.</summary>
[Collection("environment")]
public class DefaultClientTests
{
    private static readonly string[] Names = { "TQ_API_KEY", "TQ_API_SECRET", "TQ_API_URL" };
    private readonly FakeApi _api;

    public DefaultClientTests(FakeApi api) => _api = api;

    private static GuardInput G(string? user, string? token = null) => new() { User = user, Action = "LOGIN", Token = token };

    [Fact]
    public async Task TheNullClientAnswers401Or500WithoutKeysAndIsBuiltOnceTheyAreSet()
    {
        var saved = Names.ToDictionary(n => n, Environment.GetEnvironmentVariable);
        try
        {
            foreach (var n in Names) Environment.SetEnvironmentVariable(n, null);
            // No keys: 401 without a user, else 500 misconfigured, never a throw; not a status poll.
            Assert.Equal(401, (await Guard.RunAsync(null, G(null))).Status);
            var noKeys = await Guard.RunAsync(null, G("env@acme.com"));
            Assert.Equal(500, noKeys.Status);
            JsonAssert.Equal(new
            {
                touchque = new { state = "blocked", reason = "misconfigured" },
                error = new { code = "misconfigured", message = "Two-factor approval is not configured correctly." },
            }, noKeys.Body);
            Assert.False(Guard.IsStatusPoll(null, G("env@acme.com", "v1.x.y")));
            Assert.Throws<TouchqueConfigException>(() => Guard.DefaultClient());

            // The keys arrive: a failed build was not kept, so the next request builds it, once for every thread.
            await _api.ResetAsync();
            await _api.LinkAsync("env@acme.com");
            Environment.SetEnvironmentVariable("TQ_API_KEY", "tq_test_key");
            Environment.SetEnvironmentVariable("TQ_API_SECRET", "test_secret");
            Environment.SetEnvironmentVariable("TQ_API_URL", _api.BaseUrl);
            var clients = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() => Guard.DefaultClient())));
            Assert.Single(clients.Distinct());
            var first = await Guard.RunAsync(null, G("env@acme.com"));
            Assert.Equal((202, "waiting"), (first.Status, (string?)first.Body!["touchque"]!["state"]));
            var token = (string)first.Body["token"]!;
            Assert.True(Guard.IsStatusPoll(null, G("env@acme.com", token)));
            Assert.Equal(202, (await Guard.RunAsync(null, G("env@acme.com", token))).Status);
            await _api.ApproveAsync();
            Assert.Equal("DEVICE", (await Guard.RunAsync(null, G("env@acme.com", token))).Approved?.ConfirmedVia);
            Assert.Same(clients[0], Guard.DefaultClient());
        }
        finally
        {
            foreach (var (n, v) in saved) Environment.SetEnvironmentVariable(n, v);
            Guard.SetDefaultClient(null);
        }
    }

    [Fact]
    public async Task SetDefaultClientReplacesTheNullClientAndNullForgetsIt()
    {
        var saved = Names.ToDictionary(n => n, Environment.GetEnvironmentVariable);
        try
        {
            foreach (var n in Names) Environment.SetEnvironmentVariable(n, null);
            await _api.ResetAsync();
            await _api.LinkAsync("set@acme.com");
            var logger = new ContractTests.ListLogger();
            var mine = new TouchqueClient(new TouchqueOptions { ApiKey = "tq_test_key", ApiSecret = "test_secret", BaseUrl = _api.BaseUrl, Logger = logger });
            Guard.SetDefaultClient(mine);
            Assert.Same(mine, Guard.DefaultClient());
            var first = await Guard.RunAsync(null, G("set@acme.com"));
            Assert.Equal(202, first.Status);
            Assert.True(Guard.IsStatusPoll(null, G("set@acme.com", (string)first.Body!["token"]!)));
            // A client built with a logger gives the null-client path its lines.
            Assert.Equal(500, (await Guard.RunAsync(null, new GuardInput { User = "set@acme.com", Action = "NOT_DEFINED" })).Status);
            var line = Assert.Single(logger.Lines);
            Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Error, line.Level);
            Assert.Contains("Unknown action \"NOT_DEFINED\"", line.Message, StringComparison.Ordinal);

            // Null forgets it: the next call builds one from the environment again (none here, so it names the problem).
            Guard.SetDefaultClient(null);
            var e = Assert.Throws<TouchqueConfigException>(() => Guard.DefaultClient());
            Assert.Contains("TQ_API_KEY", e.Message, StringComparison.Ordinal);
            Assert.Equal(500, (await Guard.RunAsync(null, G("set@acme.com"))).Status);
        }
        finally
        {
            foreach (var (n, v) in saved) Environment.SetEnvironmentVariable(n, v);
            Guard.SetDefaultClient(null);
        }
    }

    /// <summary>
    /// The README's test note: RequireTouchque and MapTouchqueRelay take the TouchqueClient AddTouchque
    /// registered, never Guard.SetDefaultClient's, so a test replaces that registration with ConfigureTestServices
    /// (on a generic host, as WebApplicationFactory builds it).
    /// </summary>
    [Fact]
    public async Task TheAdaptersTakeTheRegisteredClientWhichConfigureTestServicesReplaces()
    {
        await _api.ResetAsync();
        await _api.LinkAsync("ada@acme.com");
        var fake = new TouchqueClient(new TouchqueOptions { ApiKey = "tq_test_key", ApiSecret = "test_secret", BaseUrl = _api.BaseUrl });
        async Task<IHost> HostAsync(Action<IServiceCollection>? testServices, bool relay) => await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                // The app's own registration, without keys: the client it registers cannot be built.
                web.ConfigureServices(s => s.AddRouting().AddTouchque(o =>
                {
                    o.ApiKey = "";
                    o.ApiSecret = "";
                }));
                web.Configure(app =>
                {
                    app.Use((http, next) =>
                    {
                        http.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Email, "ada@acme.com") }, "test"));
                        return next(http);
                    });
                    app.UseRouting();
                    app.UseEndpoints(e =>
                    {
                        e.MapPost("/pay", () => Results.Ok()).RequireTouchque("SEND_MONEY");
                        if (relay) e.MapTouchqueRelay("/touchque", new RelayOptions<HttpContext> { GetUserId = http => http.User.TouchqueUser(), GetLoginUser = http => http.User.TouchqueUser() });
                    });
                });
                if (testServices is not null) web.ConfigureTestServices(testServices);
            })
            .StartAsync();
        async Task<(int Pay, int Login)> AnswersAsync(IHost host)
        {
            var client = host.GetTestClient();
            var pay = await client.PostAsync("/pay", null);
            var login = await client.PostAsync("/touchque/login", JsonContent.Create(new { }));
            return ((int)pay.StatusCode, (int)login.StatusCode);
        }

        try
        {
            // Guard.SetDefaultClient does not reach them: still 500 misconfigured, and the relay cannot be mapped.
            Guard.SetDefaultClient(fake);
            using (var host = await HostAsync(null, relay: false))
            {
                Assert.Equal(500, (int)(await host.GetTestClient().PostAsync("/pay", null)).StatusCode);
            }
            await Assert.ThrowsAsync<TouchqueConfigException>(() => HostAsync(null, relay: true));
            Guard.SetDefaultClient(null);

            // AddSingleton after the app's registration wins: both answer from the fake API.
            using (var host = await HostAsync(s => s.AddSingleton(fake), relay: true))
            {
                Assert.Equal((202, 202), await AnswersAsync(host));
            }
            // TryAddSingleton keeps the registered client.
            using (var host = await HostAsync(s => s.TryAddSingleton(fake), relay: false))
            {
                Assert.Equal(500, (int)(await host.GetTestClient().PostAsync("/pay", null)).StatusCode);
            }
            // Or keep the registered client: test keys in its options, and the fake as its BaseUrl or behind its named HttpClient.
            using (var host = await HostAsync(s => s.Configure<TouchqueOptions>(o =>
            {
                o.ApiKey = "tq_test_key";
                o.ApiSecret = "test_secret";
                o.BaseUrl = _api.BaseUrl;
            }), relay: true))
            {
                Assert.Equal((202, 202), await AnswersAsync(host));
            }
            using (var host = await HostAsync(s =>
            {
                s.Configure<TouchqueOptions>(o =>
                {
                    o.ApiKey = "tq_test_key";
                    o.ApiSecret = "test_secret";
                });
                s.AddHttpClient(TouchqueServiceCollectionExtensions.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => new ToFakeApi(_api.BaseUrl));
            }, relay: true))
            {
                Assert.Equal((202, 202), await AnswersAsync(host));
            }
        }
        finally
        {
            Guard.SetDefaultClient(null);
        }
    }

    /// <summary>A primary handler for the named HttpClient: every request goes to the fake API instead.</summary>
    private sealed class ToFakeApi : DelegatingHandler
    {
        private readonly Uri _base;

        public ToFakeApi(string baseUrl) : base(new SocketsHttpHandler()) => _base = new Uri(baseUrl);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.RequestUri = new Uri(_base, request.RequestUri!.PathAndQuery);
            return base.SendAsync(request, cancellationToken);
        }
    }
}
