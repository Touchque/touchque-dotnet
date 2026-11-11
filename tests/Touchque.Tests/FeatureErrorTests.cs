using Xunit;

namespace Touchque.Tests;

/// <summary>
/// A feature the workspace's organization cannot use comes back as a typed
/// exception with the feature's id, still a TouchqueApiException. Same scenarios
/// as the Node SDK, against the shared fake Touchque API.
/// </summary>
[Collection("fake-api")]
public class FeatureErrorTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public FeatureErrorTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => _api.OptsAsync(new { featureRefused = (string?)null });

    [Theory]
    [InlineData("feature_not_in_plan", typeof(TouchqueFeatureNotInPlanException), FeatureRefusal.NotInPlan)]
    [InlineData("feature_read_only", typeof(TouchqueFeatureReadOnlyException), FeatureRefusal.ReadOnly)]
    [InlineData("feature_off", typeof(TouchqueFeatureOffException), FeatureRefusal.Off)]
    public async Task EachFeatureRefusalHasItsOwnException(string code, Type type, FeatureRefusal reason)
    {
        await _api.LinkAsync("jane@acme.com");
        await _api.OptsAsync(new { featureRefused = code, feature = "device_risk" });
        var e = await Assert.ThrowsAnyAsync<TouchqueFeatureException>(() => _api.Client().Login.RequestAsync("jane@acme.com"));
        Assert.IsType(type, e);
        Assert.IsAssignableFrom<TouchqueApiException>(e);
        Assert.Equal((403, "device_risk", reason), (e.Status, e.Feature, e.FeatureReason));
    }

    [Fact]
    public async Task OtherRefusalsStayPlainApiExceptions()
    {
        await _api.LinkAsync("jane@acme.com");
        await _api.OptsAsync(new { blocked = "access_policy" });
        var e = await Assert.ThrowsAnyAsync<TouchqueApiException>(() => _api.Client().Login.RequestAsync("jane@acme.com"));
        Assert.IsNotAssignableFrom<TouchqueFeatureException>(e);
    }
}
