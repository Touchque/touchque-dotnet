using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Xunit;

namespace Touchque.Tests;

/// <summary>
/// QR pairing against the shared fake API: register, the QR's text and hash, the phone's scan, a request for
/// the phone that scanned, and refusals. Same scenarios as the Node SDK's QrPairings tests.
/// </summary>
[Collection("fake-api")]
public class QrPairingTests : IAsyncLifetime
{
    private const string Thumb = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    private readonly FakeApi _api;

    public QrPairingTests(FakeApi api) => _api = api;

    public async Task InitializeAsync()
    {
        await _api.ResetAsync();
        await _api.LinkAsync("ayse@acme.com");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task CreateScanThenAskThePhoneThatScanned()
    {
        var tq = _api.Client();
        var p = await tq.QrPairings.CreateAsync(new CreateQrPairingOptions { KeyThumbprint = Thumb, ClientIp = "203.0.113.7", UserAgent = "Mozilla/5.0", Browser = "Chrome 155", Os = "macOS 15" });
        Assert.Equal(QrPairingsResource.Uri(p.PairingId, p.Nonce, Thumb), p.Uri);
        Assert.Matches(new Regex(@"^touchque://pair-browser\?v=1&p=[\w-]{22}&n=[\w-]{43}&k=[\w-]{43}$"), p.Uri);
        var stored = ((JsonArray)(await _api.GetAsync("/__test/qr-pairings"))!).Last()!;
        var hash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(p.Nonce))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Assert.Equal(hash, (string)stored["nonceHash"]!);
        Assert.Equal("waiting", (await tq.QrPairings.GetAsync(p.PairingId)).State);
        var early = await Assert.ThrowsAsync<TouchqueApiException>(() => tq.Login.RequestAsync(new LoginRequestOptions { ExternalUsername = "ayse@acme.com", QrPairing = p.PairingId }));
        Assert.Equal("pairing_not_confirmed", early.Code);

        await _api.PostAsync("/__test/qr-scan", new { id = p.PairingId, user = "ayse@acme.com" });
        var seen = await tq.QrPairings.GetAsync(p.PairingId);
        Assert.Equal(("confirmed", "ayse@acme.com"), (seen.State, seen.ExternalUsername));
        Assert.Empty(seen.Proximity!.Warnings);
        var req = await tq.Login.RequestAsync(new LoginRequestOptions { ExternalUsername = "ayse@acme.com", QrPairing = p.PairingId });
        var after = await tq.QrPairings.GetAsync(p.PairingId);
        Assert.Equal(("requested", req.RequestId), (after.State, after.RequestId));
    }

    [Fact]
    public async Task RefuseAfterTheScanAndChecksBeforeTheCall()
    {
        var tq = _api.Client();
        var p = await tq.QrPairings.CreateAsync(new CreateQrPairingOptions { KeyThumbprint = Thumb, TtlSeconds = 60 });
        var early = await Assert.ThrowsAsync<TouchqueApiException>(() => tq.QrPairings.RefuseAsync(p.PairingId, new RefuseQrPairingOptions { Reason = "policy", Message = "Not yet" }));
        Assert.Equal((409, "not_open"), (early.Status, early.Code));
        await _api.PostAsync("/__test/qr-scan", new { id = p.PairingId, user = "ayse@acme.com", confirm = false });
        var refused = await tq.QrPairings.RefuseAsync(p.PairingId, new RefuseQrPairingOptions { Reason = "device_not_approved", Message = "Ask IT to approve this computer.", DeviceCode = "ABC-123" });
        Assert.Equal(("refused", "device_not_approved", "ABC-123"), (refused.State, refused.Outcome!.Reason, refused.Outcome.DeviceCode));
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.QrPairings.CreateAsync(new CreateQrPairingOptions { KeyThumbprint = "short" }));
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.QrPairings.CreateAsync(new CreateQrPairingOptions { KeyThumbprint = Thumb, TtlSeconds = 10 }));
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.QrPairings.RefuseAsync(p.PairingId, new RefuseQrPairingOptions { Reason = "nope", Message = "x" }));
        await Assert.ThrowsAsync<TouchqueConfigException>(() => tq.QrPairings.RefuseAsync(p.PairingId, new RefuseQrPairingOptions { Reason = "other", Message = " " }));
    }
}
