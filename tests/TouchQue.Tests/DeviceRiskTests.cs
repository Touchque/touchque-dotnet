using System.Text.Json.Nodes;
using Xunit;

namespace TouchQue.Tests;

/// <summary>
/// Device risk against the shared fake API: the report goes through untouched and the answer fails toward
/// asking. Same scenarios as the Node SDK's DeviceRisk tests.
/// </summary>
[Collection("fake-api")]
public class DeviceRiskTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public DeviceRiskTests(FakeApi api) => _api = api;

    public async Task InitializeAsync()
    {
        await _api.ResetAsync();
        await _api.LinkAsync("ayse@acme.com");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task CheckSendsTheReportAndReadsTheAnswer()
    {
        var r = await _api.Client().DeviceRisk.CheckAsync(new DeviceRiskCheckOptions { RequestId = "dre_flaggedaaaaaaaaaaaaaaa", Event = "sign_up", ExternalUsername = "ayse@acme.com", ClientIp = "203.0.113.7" });
        Assert.Equal("ok", r.Report);
        Assert.Equal(("tqv_fakeVisitor00000001", "DRK-2QX"), (r.VisitorId, r.CaseCode));
        Assert.False(r.Signals[0].Enforced);
        var ev = await _api.Client().DeviceRisk.GetEventAsync("dre_aaaaaaaaaaaaaaaaaaaaaa");
        Assert.Equal("tqv_fakeVisitor00000001", (string)ev["visitorId"]!);
        Assert.Equal(["device_many_accounts"], r.Signals.Select((s) => s.Code));
        Assert.False(r.StepUp);
        Assert.True(r.WouldStepUp);
        Assert.Equal("shadow", r.Mode);
    }

    [Fact]
    public async Task TheFormFieldAsItCameIsAnsweredNeverThrown()
    {
        var tq = _api.Client();
        foreach (var value in new string?[] { null, "" })
        {
            var r = await tq.DeviceRisk.CheckAsync(value, new DeviceRiskCheckOptions { ExternalUsername = "ayse@acme.com" });
            Assert.Equal(("missing", (string?)null, false, true), (r.Report, r.VisitorId, r.StepUp, r.WouldStepUp));
            Assert.Equal(["device_identification_missing"], r.Signals.Select(x => x.Code));
        }
        Assert.Equal("missing", (await tq.DeviceRisk.CheckAsync(new DeviceRiskCheckOptions())).Report);
        Assert.Equal("unknown", (await tq.DeviceRisk.CheckAsync("nope")).Report);
        Assert.Equal("expired", DeviceRiskResource.ParseCheck(new System.Text.Json.Nodes.JsonObject { ["report"] = "expired" }).Report);
    }

    [Fact]
    public async Task BadInputFailsBeforeAnyRequest()
    {
        var tq = _api.Client();
        await Assert.ThrowsAsync<TouchQueConfigException>(() => tq.DeviceRisk.CheckAsync(new DeviceRiskCheckOptions { DeviceRisk = "r", Event = "tracking" }));
        await Assert.ThrowsAsync<TouchQueConfigException>(() => tq.DeviceRisk.GetEventAsync("../users"));
    }

    [Fact]
    public void TheAnswerFailsTowardAsking()
    {
        Assert.True(DeviceRiskResource.ParseCheck(new JsonObject()).StepUp);
        Assert.False(DeviceRiskResource.ParseCheck(new JsonObject { ["stepUp"] = false }).StepUp);
        var r = DeviceRiskResource.ParseCheck(JsonNode.Parse("""{"signals":[{"code":"device_tampered","text":"t"},null,{"text":"x"}],"requires":"passkey"}"""));
        Assert.Single(r.Signals);
        Assert.Equal(("device_tampered", "number_match"), (r.Signals[0].Code, r.Signals[0].Strength));
        Assert.Equal(("passkey", "invalid"), (r.Requires, r.Report));
    }

    [Fact]
    public void EngineUnavailableComesThroughAndANormalAnswerHasNull()
    {
        var down = DeviceRiskResource.ParseCheck(JsonNode.Parse("{\"report\":\"ok\",\"signals\":[],\"stepUp\":true,\"wouldStepUp\":true,\"requires\":\"number_match\",\"mode\":\"enforce\",\"engine\":\"unavailable\"}"));
        Assert.Equal(("unavailable", true, "number_match"), (down.Engine, down.StepUp, down.Requires));
        var normal = DeviceRiskResource.ParseCheck(JsonNode.Parse("{\"report\":\"ok\",\"signals\":[],\"stepUp\":false,\"requires\":\"none\",\"mode\":\"shadow\"}"));
        Assert.Null(normal.Engine);
        Assert.False(normal.StepUp);
        Assert.Null(DeviceRiskResource.ParseCheck(new JsonObject { ["engine"] = 42 }).Engine);
    }

    [Fact]
    public async Task RiskCheckCarriesDeviceRisk()
    {
        var r = await _api.Client().Risk.CheckAsync(new RiskCheckOptions { ExternalUsername = "ayse@acme.com", DeviceRiskRequestId = "dre_aaaaaaaaaaaaaaaaaaaaaa" });
        Assert.True(r.Prompt);
    }

    [Fact]
    public void TheAddressTheCountsAndABotAnswerComeThrough()
    {
        var r = DeviceRiskResource.ParseCheck(JsonNode.Parse("{\"report\":\"ok\",\"network\":{\"type\":\"hosting\"},\"velocity\":{\"identifications1h\":2},\"bot\":{\"result\":\"suspected\"}}")!.AsObject());
        Assert.Equal("hosting", (string?)r.Network!["type"]);
        Assert.Equal(2, (int?)r.Velocity!["identifications1h"]);
        Assert.Equal("suspected", (string?)r.Bot!["result"]);
        Assert.Null(DeviceRiskResource.ParseCheck(new JsonObject { ["network"] = "x" }).Network);
    }

    [Fact]
    public async Task SearchEventsPagesWithTheOpaqueCursorAndSendsTheFilters()
    {
        var tq = _api.Client();
        var first = await tq.DeviceRisk.SearchEventsAsync(new DeviceRiskSearchOptions { Account = "ada@example.com", StepUp = false, Ip = "203.0.113.0/24", Limit = 1 });
        Assert.Equal(new[] { "dre_fakeEvent00000000002" }, first.Events.Select(e => (string)e["requestId"]!).ToArray());
        Assert.Null(first.NextCursor);
        JsonAssert.Equal(new { account = "ada@example.com", stepUp = "false", ip = "203.0.113.0/24", limit = "1" }, await _api.LastDeviceRiskSearchAsync());
        var seen = new List<string>();
        string? cursor = null;
        do
        {
            var page = await tq.DeviceRisk.SearchEventsAsync(new DeviceRiskSearchOptions { Limit = 1, Cursor = cursor });
            seen.AddRange(page.Events.Select(e => (string)e["requestId"]!));
            cursor = page.NextCursor;
        } while (cursor != null);
        Assert.Equal(new[] { "dre_fakeEvent00000000003", "dre_fakeEvent00000000002", "dre_fakeEvent00000000001" }, seen);
        await Assert.ThrowsAsync<TouchQueConfigException>(() => tq.DeviceRisk.SearchEventsAsync(new DeviceRiskSearchOptions { Limit = 101 }));
    }
}
