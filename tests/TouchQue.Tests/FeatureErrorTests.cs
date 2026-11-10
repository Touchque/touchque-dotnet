using Xunit;

namespace TouchQue.Tests;

/// <summary>
/// A feature the workspace's organization cannot use comes back as a typed
/// exception with the feature's id, still a TouchQueApiException. Same scenarios
/// as the Node SDK, against the shared fake TouchQue API.
/// </summary>
[Collection("fake-api")]
public class FeatureErrorTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public FeatureErrorTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => _api.OptsAsync(new { featureRefused = (string?)null });

    [Theory]
    [InlineData("feature_not_in_plan", typeof(TouchQueFeatureNotInPlanException), FeatureRefusal.NotInPlan)]
    [InlineData("feature_read_only", typeof(TouchQueFeatureReadOnlyException), FeatureRefusal.ReadOnly)]
    [InlineData("feature_off", typeof(TouchQueFeatureOffException), FeatureRefusal.Off)]
    public async Task EachFeatureRefusalHasItsOwnException(string code, Type type, FeatureRefusal reason)
    {
        await _api.LinkAsync("jane@acme.com");
        await _api.OptsAsync(new { featureRefused = code, feature = "device_risk" });
        var e = await Assert.ThrowsAnyAsync<TouchQueFeatureException>(() => _api.Client().Login.RequestAsync("jane@acme.com"));
        Assert.IsType(type, e);
        Assert.IsAssignableFrom<TouchQueApiException>(e);
        Assert.Equal((403, "device_risk", reason), (e.Status, e.Feature, e.FeatureReason));
    }

    [Fact]
    public async Task OtherRefusalsStayPlainApiExceptions()
    {
        await _api.LinkAsync("jane@acme.com");
        await _api.OptsAsync(new { blocked = "access_policy" });
        var e = await Assert.ThrowsAnyAsync<TouchQueApiException>(() => _api.Client().Login.RequestAsync("jane@acme.com"));
        Assert.IsNotAssignableFrom<TouchQueFeatureException>(e);
    }
}
