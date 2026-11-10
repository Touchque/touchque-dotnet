using System.Diagnostics;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace TouchQue.Tests;

/// <summary>Where the shared fixtures and the fake API live (fixtures/ and testing/, next to the package).</summary>
public static class Paths
{
    public static string SharedRoot { get; } = Find();

    private static string Find()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "testing", "fake-touchque-api.mjs")) && Directory.Exists(Path.Combine(dir.FullName, "fixtures")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Could not find testing/fake-touchque-api.mjs above " + AppContext.BaseDirectory);
    }

    public static JsonObject Fixture(string name) =>
        (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(SharedRoot, "fixtures", name)))!;
}

/// <summary>
/// The shared Node fake TouchQue API (testing/fake-touchque-api.mjs): it verifies
/// this SDK's request signatures exactly like the real API, over a real HTTP round trip.
/// </summary>
public sealed class FakeApi : IAsyncLifetime
{
    private Process? _process;
    private readonly HttpClient _http = new();

    public string BaseUrl { get; private set; } = "";

    public async Task InitializeAsync()
    {
        var psi = new ProcessStartInfo("node", Path.Combine(Paths.SharedRoot, "testing", "fake-touchque-api.mjs"))
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        _process = Process.Start(psi) ?? throw new InvalidOperationException("could not start fake-touchque-api.mjs");
        _process.ErrorDataReceived += (_, _) => { };
        _process.BeginErrorReadLine();
        var line = await _process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20));
        var port = JsonNode.Parse(line ?? "{}")?["port"]?.GetValue<int>() ?? throw new InvalidOperationException("no port: " + line);
        BaseUrl = $"http://127.0.0.1:{port}";
    }

    public Task DisposeAsync()
    {
        try
        {
            if (_process is { HasExited: false }) _process.Kill(true);
        }
        catch (InvalidOperationException)
        {
        }
        _process?.Dispose();
        _http.Dispose();
        return Task.CompletedTask;
    }

    public TouchQueClient Client() => new(new TouchQueOptions { ApiKey = "tq_test_key", ApiSecret = "test_secret", BaseUrl = BaseUrl });

    /// <summary>A /__test/ call of the fake: its JSON answer.</summary>
    public async Task<JsonNode?> PostAsync(string path, object? body = null)
    {
        using var content = new StringContent((body is null ? new JsonObject() : body as JsonNode ?? System.Text.Json.JsonSerializer.SerializeToNode(body))!.ToJsonString(), Encoding.UTF8, "application/json");
        using var res = await _http.PostAsync(BaseUrl + path, content);
        return JsonNode.Parse(await res.Content.ReadAsStringAsync());
    }

    public async Task<JsonNode?> GetAsync(string path) => JsonNode.Parse(await _http.GetStringAsync(BaseUrl + path));

    public Task ResetAsync() => PostAsync("/__test/reset");

    public Task LinkAsync(string user) => PostAsync("/__test/link", new { user });

    public Task OptsAsync(object opts) => PostAsync("/__test/opts", opts);

    public Task ApproveAsync(string? id = null, string via = "DEVICE", bool provisional = false) => PostAsync("/__test/approve", new { id, via, provisional });

    public Task RejectAsync(string? id = null) => PostAsync("/__test/reject", new { id });

    public Task EscalateAsync(string? id = null) => PostAsync("/__test/escalate", new { id });

    public Task RevokeAsync(string? id = null, string reason = "COACHED") => PostAsync("/__test/revoke", new { id, reason });

    public Task ReconfirmAsync(string? id = null) => PostAsync("/__test/reconfirm", new { id });

    public Task RecoveryAsync(string to, string? id = null) => PostAsync("/__test/recovery", new { id, to });

    public Task ApproveVersionAsync(string slug, int number) => PostAsync("/__test/approve-version", new { slug, number });

    public async Task<JsonArray> CallsAsync() => (JsonArray)(await GetAsync("/__test/calls"))!;

    public async Task<JsonObject> LastCallAsync()
    {
        var calls = await CallsAsync();
        return (JsonObject)calls[^1]!;
    }

    public async Task<JsonObject?> LastCheckAsync() => await GetAsync("/__test/last-check") as JsonObject;
    public async Task<JsonObject?> LastDeviceRiskSearchAsync() => await GetAsync("/__test/last-device-risk-search") as JsonObject;
}

[CollectionDefinition("fake-api")]
public sealed class FakeApiCollection : ICollectionFixture<FakeApi>
{
}

/// <summary>An HttpMessageHandler answering from a function (in-process fakes).</summary>
public sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, string?, Task<HttpResponseMessage>> _answer;

    private StubHandler(Func<HttpRequestMessage, string?, Task<HttpResponseMessage>> answer, bool _) => _answer = answer;

    public StubHandler(Func<HttpRequestMessage, string?, HttpResponseMessage> answer) => _answer = (r, b) => Task.FromResult(answer(r, b));

    public static StubHandler Async(Func<HttpRequestMessage, string?, Task<HttpResponseMessage>> answer) => new(answer, true);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        return await _answer(request, body);
    }

    public static HttpResponseMessage Json(int status, object body) => new((System.Net.HttpStatusCode)status)
    {
        Content = JsonContent.Create(body as JsonNode ?? System.Text.Json.JsonSerializer.SerializeToNode(body)),
    };
}

public static class JsonAssert
{
    /// <summary>Deep equality of two JSON values, object key order ignored.</summary>
    public static void Equal(JsonNode? expected, JsonNode? actual, string? because = null)
    {
        Assert.True(JsonNode.DeepEquals(Normalize(expected), Normalize(actual)), $"{because}\nexpected: {expected?.ToJsonString()}\nactual:   {actual?.ToJsonString()}");
    }

    public static void Equal(object expected, JsonNode? actual, string? because = null) =>
        Equal(expected as JsonNode ?? System.Text.Json.JsonSerializer.SerializeToNode(expected), actual, because);

    private static JsonNode? Normalize(JsonNode? n) => n switch
    {
        JsonObject o => new JsonObject(o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => KeyValuePair.Create(p.Key, Normalize(p.Value)))),
        JsonArray a => new JsonArray(a.Select(Normalize).ToArray()),
        JsonValue v => JsonNode.Parse(v.ToJsonString()),
        _ => null,
    };
}
