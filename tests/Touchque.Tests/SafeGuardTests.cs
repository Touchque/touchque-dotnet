using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace Touchque.Tests;

/// <summary>
/// Safe Guard: the verifier against the shared vectors (fixtures/safe-guard-vectors.json, derived from the
/// reference project and shared with every server SDK), and request / status / wait against the shared fake API.
/// </summary>
[Collection("fake-api")]
public class SafeGuardTests : IAsyncLifetime
{
    private static readonly JsonObject Vectors = Paths.Fixture("safe-guard-vectors.json");
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);
    private static readonly string Key = (string)Vectors["approverKey"]!;
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds((long)Vectors["now"]!);
    private readonly FakeApi _api;

    public SafeGuardTests(FakeApi api) => _api = api;

    public async Task InitializeAsync()
    {
        await _api.ResetAsync();
        await _api.LinkAsync("treasurer@acme.com");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static IEnumerable<JsonObject> All() => Vectors["vectors"]!.AsArray().Select(v => v!.AsObject());

    private static JsonObject Vector(string name) => All().First(v => (string)v["name"]! == name);

    private static SafeGuardTx Tx(JsonObject v) => v["safeTx"].Deserialize<SafeGuardTx>(Web)!;

    [Fact]
    public void EveryVector()
    {
        foreach (var v in All())
        {
            var tx = Tx(v);
            Assert.Equal((string)v["safeTxHash"]!, SafeApproval.SafeTxHash(tx));
            Assert.Equal((string)v["governanceHash"]!, SafeApproval.GovernanceHash(tx));
            Assert.Equal((string)v["message"]!, SafeApproval.Message((string)v["purpose"]!, tx.ChainId, tx.Guard, tx.Safe, (string)v["subject"]!, (ulong)v["expiresAt"]!, (string)v["displayDigest"]!));
            if (v["rows"] is JsonArray rows)
            {
                Assert.Equal((string)v["rowsDigest"]!, SafeApproval.DisplayDigest(rows.Deserialize<List<SafeDisplayRow>>(Web)!));
            }
            var got = SafeApproval.Verify(tx, (string)v["approval"]!, Key, new VerifySafeApprovalOptions { Purpose = (string)v["purpose"]!, Now = Now, ApproverIndex = tx.ApproverIndex });
            Assert.Equal(new SafeApprovalVerification(true, null, (string?)v["purpose"], tx.ApproverIndex, (ulong)v["expiresAt"]!, (string?)v["displayDigest"], (string)v["safeTxHash"]!, (string)v["governanceHash"]!), got);
            // Without a purpose only an ordinary approval passes.
            var unnamed = SafeApproval.Verify(tx, (string)v["approval"]!, Key, new VerifySafeApprovalOptions { Now = Now, ApproverIndex = tx.ApproverIndex });
            Assert.Equal((string)v["purpose"]! == "approve" ? null : "signature_invalid", unnamed.Reason);
        }
    }

    [Fact]
    public void EveryCheck()
    {
        foreach (var c in Vectors["checks"]!.AsArray().Select(c => c!.AsObject()))
        {
            var o = c["options"]!.AsObject();
            var got = SafeApproval.Verify(Tx(Vector((string)c["vector"]!)), (string)c["approval"]!, (string?)c["key"] ?? Key, new VerifySafeApprovalOptions
            {
                Purpose = (string?)o["purpose"],
                ApproverIndex = (int?)o["approverIndex"],
                DisplayDigest = (string?)o["displayDigest"],
                Now = o["now"] is { } n ? DateTimeOffset.FromUnixTimeSeconds((long)n) : Now,
            });
            Assert.True((string?)c["reason"] == got.Reason, (string)c["name"]! + ": " + got.Reason);
            Assert.Equal(c["reason"] is null, got.Valid);
            if (c["purpose"] is { } purpose) Assert.Equal((string)purpose!, got.Purpose);
        }
    }

    [Fact]
    public void TrailerAndScheduleCall()
    {
        var w = Vectors["withApprovals"]!;
        Assert.Equal((string)w["expected"]!, SafeApproval.WithApprovals((string)w["ownerSignatures"]!, w["approvals"]!.AsArray().Select(a => (string)a!)));
        var s = Vectors["scheduleCall"]!;
        Assert.Equal((string)s["expected"]!, SafeApproval.ScheduleCall((string)s["safe"]!, (string)s["governanceHash"]!, s["approvals"]!.AsArray().Select(a => (string)a!)));
        var bad = Tx(All().First()) with { };
        Assert.Throws<TouchqueConfigException>(() => SafeApproval.SafeTxHash(bad with { Tx = bad.Tx with { Operation = 2 } }));
    }

    [Fact]
    public async Task RequestWaitAndCheckTheApprovalHere()
    {
        var v = Vector("bybit_pattern");
        await _api.OptsAsync(new { safeTxView = new { @class = (string)v["class"]!, flags = new[] { "delegatecall" }, safeTxHash = (string)v["safeTxHash"]!, governanceHash = (string)v["governanceHash"]!, purpose = (string)v["purpose"]! } });
        var tq = _api.Client();
        var tx = Tx(v);
        var sent = await tq.SafeGuard.RequestAsync(new SafeGuardRequestOptions { ExternalUsername = "treasurer@acme.com", Type = "safe_payment", SafeTx = tx, ReferenceId = "tx-1" });
        Assert.Equal((string)v["governanceHash"]!, sent.SafeTx.GovernanceHash);
        var call = await _api.LastCallAsync();
        Assert.Equal("/safe-guard/approvals", (string)call["path"]!);
        Assert.Equal("1", (string)call["body"]!["safeTx"]!["chainId"]!);
        Assert.Equal(tx.ApproverIndex, (int)call["body"]!["safeTx"]!["approverIndex"]!);
        Assert.Equal(172800, (int)call["body"]!["safeTx"]!["config"]!["govDelay"]!);
        Assert.Equal("tx-1", (string)call["body"]!["referenceId"]!);
        Assert.Null((await tq.SafeGuard.StatusAsync(sent.RequestId)).SafeTx!.Approval);

        await _api.PostAsync("/__test/approve", new { id = sent.RequestId, safeTx = new { approval = (string)v["approval"]!, expiresAt = (long)v["expiresAt"]! } });
        var done = await tq.SafeGuard.WaitForApprovalAsync(sent.RequestId, TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(10));
        Assert.Equal("CONFIRMED", done.Status);
        var check = SafeApproval.Verify(tx, done.SafeTx!.Approval!, Key, new VerifySafeApprovalOptions { Purpose = done.SafeTx.Purpose, Now = Now, ApproverIndex = done.SafeTx.ApproverIndex });
        Assert.True(check.Valid);
        Assert.Equal("schedule", check.Purpose);
        Assert.False(SafeApproval.Verify(tx, done.SafeTx.Approval!, Key, new VerifySafeApprovalOptions { Now = Now, ApproverIndex = done.SafeTx.ApproverIndex }).Valid);

        var again = await tq.SafeGuard.RequestAsync(new SafeGuardRequestOptions { ExternalUsername = "treasurer@acme.com", Type = "safe_payment", SafeTx = tx });
        await _api.RejectAsync(again.RequestId);
        await Assert.ThrowsAsync<TouchqueRejectedException>(() => tq.SafeGuard.WaitForApprovalAsync(again.RequestId, TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(10)));
    }
}
