using Xunit;

namespace Touchque.Tests;

/// <summary>
/// A code typed back on the phone against the shared fake Touchque API, which seals it like the
/// phone does: it opens only with the one-time key, for that request.
/// </summary>
[Collection("fake-api")]
public class CodeReplyTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public CodeReplyTests(FakeApi api) => _api = api;

    public async Task InitializeAsync()
    {
        await _api.ResetAsync();
        await _api.LinkAsync("ayse@acme.com");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task TheTypedCodeOpensOnlyWithTheOneTimeKeyForThatRequest()
    {
        var tq = _api.Client();
        var key = CodeReply.NewKey();
        var sent = await tq.Login.RequestAsync(new LoginRequestOptions
        {
            ExternalUsername = "ayse@acme.com", Reply = new LoginReplyRequest(key.PublicKey, "sms", "+**********26"),
        });
        Assert.Null((await tq.Login.StatusAsync(sent.RequestId)).Reply);
        await _api.PostAsync("/__test/approve", new { id = sent.RequestId, replyCode = "482 913" });
        var ct = (await tq.Login.StatusAsync(sent.RequestId)).Reply!.Ct;
        Assert.Equal("482 913", CodeReply.Open(key.PrivateKey, sent.RequestId, ct));
        Assert.Null(CodeReply.Open(key.PrivateKey, "another-request", ct));
        Assert.Null(CodeReply.Open(CodeReply.NewKey().PrivateKey, sent.RequestId, ct));
        Assert.Null(CodeReply.Open(key.PrivateKey, sent.RequestId, "v1.bad.ct"));
    }
}
