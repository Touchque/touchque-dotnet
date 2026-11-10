using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace TouchQue.Tests;

/// <summary>Never Locked Out and help-desk event webhooks: the backend's exact names, signed like every event.</summary>
public class WebhookEventTests
{
    [Fact]
    public void RecoveryAndAssistEventsUseTheBackendNames()
    {
        // The enums of RecoveryEventWebhookPayload and AssistEventWebhookPayload in the API description.
        Assert.Equal(
            new[] { "RECOVERY_STARTED", "RECOVERY_DEVICE_BOUND", "RECOVERY_COOLING", "RECOVERY_COMPLETED", "RECOVERY_VETOED", "RECOVERY_EXPIRED", "RECOVERY_FAILED" },
            new[]
            {
                WebhookResource.EventRecoveryStarted, WebhookResource.EventRecoveryDeviceBound, WebhookResource.EventRecoveryCooling,
                WebhookResource.EventRecoveryCompleted, WebhookResource.EventRecoveryVetoed, WebhookResource.EventRecoveryExpired,
                WebhookResource.EventRecoveryFailed,
            });
        Assert.Equal(
            new[] { "ASSIST_OPENED", "ASSIST_ENDED", "ASSIST_CHECK_PASSED", "ASSIST_CHECK_FAILED", "ASSIST_UNFROZEN", "ASSIST_CLAIM_CONFIRMED", "ASSIST_CLAIM_UNVERIFIED" },
            new[]
            {
                WebhookResource.EventAssistOpened, WebhookResource.EventAssistEnded, WebhookResource.EventAssistCheckPassed,
                WebhookResource.EventAssistCheckFailed, WebhookResource.EventAssistUnfrozen, WebhookResource.EventAssistClaimConfirmed,
                WebhookResource.EventAssistClaimUnverified,
            });
        Assert.Equal("MOBILE_PUSH", WebhookResource.EventMobilePush);
    }

    [Fact]
    public void VerifiedEventsMatchTheConstants()
    {
        const string secret = "whsec_test";
        var webhook = new TouchQueClient(new TouchQueOptions { ApiKey = "tq_x", ApiSecret = secret }).Webhook;
        string Sign(JsonObject payload)
        {
            using var h = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            payload["signature"] = Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(WebhookResource.Canonicalize(payload.ToJsonString())))).ToLowerInvariant();
            return payload.ToJsonString();
        }
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'");

        var moved = webhook.Verify(Sign(new JsonObject
        {
            ["event"] = "RECOVERY_COMPLETED", ["externalUsername"] = "jane@acme.com", ["integrationId"] = "int_1", ["timestamp"] = now,
            ["jti"] = Guid.NewGuid().ToString(), ["recoveryId"] = Guid.NewGuid().ToString(), ["status"] = "COMPLETED",
            ["method"] = "vouch", ["probationUntil"] = DateTimeOffset.UtcNow.AddHours(24).ToString("O"),
        }));
        Assert.Equal(WebhookResource.EventRecoveryCompleted, (string?)moved["event"]);

        // Someone pretending to be IT: no assist session, so no assistId.
        var claim = webhook.Verify(Sign(new JsonObject
        {
            ["event"] = "ASSIST_CLAIM_UNVERIFIED", ["externalUsername"] = "jane@acme.com", ["integrationId"] = "int_1", ["timestamp"] = now,
            ["jti"] = Guid.NewGuid().ToString(), ["caseCode"] = "K7P-2QX",
        }));
        Assert.Equal(WebhookResource.EventAssistClaimUnverified, (string?)claim["event"]);
        Assert.False(claim.ContainsKey("assistId"));
    }
}
