using System.Text.Json.Nodes;
using Xunit;

namespace Touchque.Tests;

/// <summary>Touchque Actions: every management call sends exactly what fixtures/actions-api-vectors.json says.</summary>
[Collection("fake-api")]
public class ActionsTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public ActionsTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private static IReadOnlyList<string>? List(JsonNode? n) => n is JsonArray a ? a.Select(x => (string)x!).ToList() : null;

    private static async Task<object?> CallAsync(TouchqueClient tq, string name, JsonNode a)
    {
        var acts = tq.Actions;
        switch (name)
        {
            case "deploy":
                return await acts.DeployAsync((string)a["slug"]!, new DeployActionOptions { Trigger = (string?)a["trigger"], Code = (string?)a["code"], Secrets = List(a["secrets"]), Name = (string?)a["name"] });
            case "deployTemplate":
                return await acts.DeployAsync((string)a["slug"]!, new DeployActionOptions
                {
                    Trigger = (string?)a["trigger"], Template = ActionTemplateRef.Of((string)a["template"]!["id"]!, a["template"]!["params"]), OnFailure = (string?)a["onFailure"],
                });
            case "deployLoosening":
                return await acts.DeployAsync((string)a["slug"]!, new DeployActionOptions { Trigger = (string?)a["trigger"], Code = (string?)a["code"], Capabilities = List(a["capabilities"]), AllowedHosts = List(a["allowedHosts"]) });
            case "list": return await acts.ListAsync();
            case "get": return await acts.GetAsync((string)a["slug"]!);
            case "version": return await acts.VersionAsync((string)a["slug"]!, (int)a["number"]!);
            case "update": return await acts.UpdateAsync((string)a["slug"]!, new UpdateActionOptions { Enabled = (bool?)a["enabled"] });
            case "rollback": return await acts.RollbackAsync((string)a["slug"]!, (int?)a["version"]);
            case "rollbackPrevious": return await acts.RollbackAsync((string)a["slug"]!);
            case "test": return await acts.TestAsync(new TestActionOptions { Trigger = (string?)a["trigger"], Code = (string?)a["code"], EventId = (string?)a["eventId"] });
            case "testDeployed": return await acts.TestAsync(new TestActionOptions { Slug = (string?)a["slug"], Event = a["event"] });
            case "dryRun": return await acts.DryRunAsync(new DryRunActionOptions { Trigger = (string?)a["trigger"], Code = (string?)a["code"], Replaces = (string?)a["replaces"], Limit = (int?)a["limit"] });
            case "events": return await acts.EventsAsync((string?)a["trigger"], (int?)a["limit"]);
            case "logs": return await acts.LogsAsync((string)a["slug"]!, (int?)a["limit"]);
            case "metrics": return await acts.MetricsAsync((string)a["slug"]!, (string?)a["window"]);
            case "triggers": return await acts.TriggersAsync();
            case "templates": return await acts.TemplatesAsync();
            case "renderTemplate": return await acts.RenderTemplateAsync((string)a["id"]!, (string)a["trigger"]!, a["params"]);
            case "setSecret": return await acts.Secrets.SetAsync((string)a["name"]!, (string)a["value"]!);
            case "listSecrets": return await acts.Secrets.ListAsync();
            case "deleteSecret": await acts.Secrets.DeleteAsync((string)a["name"]!); return null;
            case "delete": await acts.DeleteAsync((string)a["slug"]!); return null;
        }
        throw new InvalidOperationException("no mapping for " + name);
    }

    [Fact]
    public async Task ActionsApiVectors()
    {
        var tq = _api.Client();
        foreach (var v in (JsonArray)Paths.Fixture("actions-api-vectors.json")["calls"]!)
        {
            var name = (string)v!["name"]!;
            var result = await CallAsync(tq, name, v["args"]!);
            var last = await _api.LastCallAsync();
            var want = v["request"]!;
            Assert.Equal((string)want["method"]!, (string)last["method"]!);
            Assert.Equal((string)want["path"]!, (string)last["path"]!);
            var url = (string)last["url"]!;
            var query = new JsonObject();
            if (url.Contains('?'))
            {
                foreach (var part in url[(url.IndexOf('?') + 1)..].Split('&')) query[Uri.UnescapeDataString(part.Split('=')[0])] = Uri.UnescapeDataString(part.Split('=')[1]);
            }
            JsonAssert.Equal(want["query"] ?? new JsonObject(), query, name);
            if ((string)want["method"]! is not ("GET" or "DELETE")) JsonAssert.Equal(want["body"] ?? new JsonObject(), last["body"], name);
            if (v["expect"] is JsonObject expect)
            {
                var deploy = Assert.IsType<ActionDeployResult>(result);
                Assert.Equal((bool)expect["deployed"]!, deploy.Deployed);
                Assert.Equal((bool)expect["approval.required"]!, deploy.Approval!.Required);
            }
        }
    }

    [Fact]
    public async Task LooseningVersionWaitsForThePhone()
    {
        var tq = _api.Client();
        var res = await tq.Actions.DeployAsync("silent-office", new DeployActionOptions
        {
            Trigger = "risk.check", Code = "exports.onExecute = (e, api) => api.allowSilent(\"office\");", Capabilities = new[] { "allow_silent" },
        });
        Assert.False(res.Deployed);
        Assert.True(res.Approval!.Required);
        await _api.ApproveVersionAsync("silent-office", 1);
        Assert.Equal(1, (await tq.Actions.GetAsync("silent-office")).Action.ActiveVersion);
    }

    [Fact]
    public async Task BadInputIsRefusedBeforeAnyRequest()
    {
        var tq = _api.Client();
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.Actions.DeployAsync("Bad Slug", new DeployActionOptions { Trigger = "login.request", Code = "x" }));
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.Actions.DeployAsync("no-code", new DeployActionOptions { Trigger = "login.request" }));
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.Actions.Secrets.SetAsync("lowercase", "v"));
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.Actions.RenderTemplateAsync("Bad-Id", "login.request"));
        Assert.Empty(await _api.CallsAsync());
    }
}
