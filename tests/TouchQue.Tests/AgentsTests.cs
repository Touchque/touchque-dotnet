using System.Security.Cryptography;
using System.Text.Json.Nodes;
using TouchQue.Internal;
using Xunit;

namespace TouchQue.Tests;

/// <summary>
/// AI agents: management calls send what fixtures/agent-vectors.json says, and
/// TouchQueAgent signs in with its own key against the fake API, which checks the
/// private_key_jwt assertion and the DPoP proofs like the real API.
/// </summary>
[Collection("fake-api")]
public class AgentsTests : IAsyncLifetime
{
    private readonly FakeApi _api;
    private readonly JsonObject _vectors = Paths.Fixture("agent-vectors.json");

    public AgentsTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private TouchQueAgent Agent(string id, object key, string? kid = null) =>
        new(new TouchQueAgentOptions { AgentId = id, PrivateKey = key, Kid = kid, BaseUrl = _api.BaseUrl });

    private Task<AgentInfo> CreateAsync(TouchQueClient tq, string name, JsonObject publicKey, params string[] types) =>
        tq.Agents.CreateAsync(new CreateAgentOptions { Name = name, AllowedTypes = types.Length == 0 ? new[] { "LOGIN" } : types, PublicKey = publicKey });

    [Fact]
    public void GenerateKeys()
    {
        var ec = AgentKeys.Generate();
        Assert.Equal("ES256", (string?)ec.PublicJwk["alg"]);
        Assert.Equal(AgentKeys.Thumbprint(ec.PublicJwk), (string?)ec.PublicJwk["kid"]);
        Assert.False(ec.PublicJwk.ContainsKey("d"));
        Assert.Equal("Ed25519", (string?)AgentKeys.Generate("EdDSA").PublicJwk["crv"]);
        Assert.Throws<TouchQueConfigException>(() => AgentKeys.Generate("RS256"));
    }

    [Fact]
    public async Task ManagementCallVectors()
    {
        var tq = _api.Client();
        var k1 = AgentKeys.Generate();
        var k2 = AgentKeys.Generate("EdDSA");
        var id = "";
        foreach (var v in (JsonArray)_vectors["calls"]!)
        {
            var a = v!["args"]!;
            switch ((string)v["name"]!)
            {
                case "create":
                    id = (await tq.Agents.CreateAsync(new CreateAgentOptions
                    {
                        Name = (string)a["name"]!, AllowedTypes = ((JsonArray)a["allowedTypes"]!).Select(x => (string)x!).ToList(), PublicKey = k1.PublicJwk,
                        OwnerEmail = (string?)a["ownerEmail"], Platform = (string?)a["platform"], ReviewInDays = (int?)a["reviewInDays"],
                    })).Id;
                    break;
                case "list": await tq.Agents.ListAsync((string?)a["status"]); break;
                case "get": await tq.Agents.GetAsync(id); break;
                case "update": await tq.Agents.UpdateAsync(id, new UpdateAgentOptions { ReviewInDays = (int?)a["reviewInDays"], Description = (string?)a["description"] }); break;
                case "addKey": await tq.Agents.AddKeyAsync(id, k2.PublicJwk); break;
                case "removeKey": await tq.Agents.RemoveKeyAsync(id, (string)k2.PublicJwk["kid"]!); break;
                case "suspend": await tq.Agents.SuspendAsync(id, (string?)a["reason"]); break;
                case "resume": await tq.Agents.ResumeAsync(id); break;
                case "setPolicy":
                    await tq.Agents.SetPolicyAsync(id, Json.To<AgentPolicy>(a["policy"]));
                    break;
                case "getWorkspacePolicy": await tq.Agents.GetWorkspacePolicyAsync(); break;
                case "listEvents": await tq.Agents.ListEventsAsync((string?)a["after"], null, (int?)a["limit"]); break;
                case "setWorkspacePolicy": await tq.Agents.SetWorkspacePolicyAsync(Json.To<AgentPolicy>(a["policy"])!); break;
                case "listBlocks": await tq.Agents.ListBlocksAsync(id); break;
                case "killSwitch": await tq.Agents.SetKillSwitchAsync((bool)a["engaged"]!, (string?)a["reason"]); break;
                case "killSwitchOff": await tq.Agents.SetKillSwitchAsync((bool)a["engaged"]!); break;
                case "revoke": await tq.Agents.RevokeAsync(id); break;
                default: throw new InvalidOperationException((string?)v["name"]);
            }
            var call = await _api.LastCallAsync();
            var want = JsonNode.Parse(v.ToJsonString()
                .Replace("\"{publicKey}\"", k1.PublicJwk.ToJsonString())
                .Replace("\"{publicKey2}\"", k2.PublicJwk.ToJsonString())
                .Replace("{id}", id)
                .Replace("{kid}", Uri.EscapeDataString((string)k2.PublicJwk["kid"]!)))!;
            Assert.Equal((string)want["method"]!, (string)call["method"]!);
            Assert.Equal((string)want["path"]!, (string)call["path"]!);
            if (want["query"] is not null) Assert.Equal((string)want["path"]! + "?" + (string)want["query"]!, (string)call["url"]!);
            if (want["body"] is not null) JsonAssert.Equal(want["body"], call["body"], (string?)v["name"]);
        }
        await Assert.ThrowsAsync<TouchQueConfigException>(() => CreateAsync(tq, "x", k1.PrivateJwk));
    }

    [Fact]
    public async Task AgentSignsInWithItsOwnKey()
    {
        var tq = _api.Client();
        foreach (var alg in new[] { "ES256", "EdDSA" })
        {
            var keys = AgentKeys.Generate(alg);
            var created = await CreateAsync(tq, "agent " + alg, keys.PublicJwk);
            foreach (object key in new object[] { keys.PrivateJwk, keys.PrivateJwk.ToJsonString() })
            {
                using var agent = Agent(created.Id, key);
                var me = await agent.MeAsync();
                Assert.Equal(created.Id, me.Agent.Id);
                Assert.Equal("agent:read approvals:request approvals:read vault:read", me.Scope);
            }
        }
        // An EC key as PEM too.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ec.ExportParameters(false);
        var pub = new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Base64Url.Encode(p.Q.X!), ["y"] = Base64Url.Encode(p.Q.Y!) };
        var pem = await CreateAsync(tq, "pem", pub);
        using var pemAgent = Agent(pem.Id, ec.ExportECPrivateKeyPem());
        Assert.Equal(pem.Id, (await pemAgent.MeAsync()).Agent.Id);
    }

    [Fact]
    public async Task TokenIsReusedAndRefusalsCarryTheReason()
    {
        var tq = _api.Client();
        var keys = AgentKeys.Generate();
        var created = await CreateAsync(tq, "refused", keys.PublicJwk);
        using var agent = Agent(created.Id, keys.PrivateJwk);
        await agent.MeAsync();
        await agent.MeAsync();
        Assert.Single(await _api.CallsAsync(), c => (string)c!["path"]! == "/agents/token");

        await tq.Agents.SuspendAsync(created.Id, "looping");
        var e = await Assert.ThrowsAsync<TouchQueApiException>(() => agent.MeAsync());
        Assert.Equal((403, "agent_blocked", "suspended"), (e.Status, e.Code, e.Reason));
        using var fresh = Agent(created.Id, keys.PrivateJwk);
        e = await Assert.ThrowsAsync<TouchQueApiException>(() => fresh.MeAsync());
        Assert.Equal(("unauthorized_client", "suspended"), (e.Code, e.Reason));
        await tq.Agents.ResumeAsync(created.Id);

        using var stranger = Agent(created.Id, AgentKeys.Generate().PrivateJwk, (string)keys.PublicJwk["kid"]!);
        e = await Assert.ThrowsAsync<TouchQueApiException>(() => stranger.MeAsync());
        Assert.Equal((401, "invalid_client"), (e.Status, e.Code));

        await tq.Agents.SetKillSwitchAsync(true, "incident");
        Assert.Equal("workspace_paused", (await Assert.ThrowsAsync<TouchQueApiException>(() => agent.MeAsync())).Reason);
        await tq.Agents.SetKillSwitchAsync(false);
        Assert.Equal(created.Id, (await agent.MeAsync()).Agent.Id);
    }

    [Fact]
    public void ConfigurationErrors()
    {
        var key = AgentKeys.Generate().PrivateJwk;
        Assert.Throws<TouchQueConfigException>(() => Agent("nope", key));
        Assert.Throws<TouchQueConfigException>(() => Agent("agt_abcdefghijkmnpqrstuv", "not a key"));
        Assert.Throws<TouchQueConfigException>(() => new TouchQueAgent(new TouchQueAgentOptions { AgentId = "agt_abcdefghijkmnpqrstuv", PrivateKey = key, BaseUrl = "http://api.example.com" }));
        var pub = AgentKeys.Generate().PublicJwk;
        Assert.Throws<TouchQueConfigException>(() => Agent("agt_abcdefghijkmnpqrstuv", pub));
    }

    [Fact]
    public async Task TokenVault()
    {
        var tq = _api.Client();
        var keys = AgentKeys.Generate();
        var created = await CreateAsync(tq, "calendar", keys.PublicJwk);
        using var agent = Agent(created.Id, keys.PrivateJwk);
        var conn = await tq.Agents.Vault.PutConnectionAsync("google", new AgentVaultConnectionOptions
        {
            Provider = "google", ClientId = "acme.apps.googleusercontent.com", ClientSecret = "g-secret", AgentIds = new[] { created.Id },
        });
        Assert.True(conn.HasClientSecret);
        var account = await tq.Agents.Vault.DepositAsync("google", "jane@example.com", new AgentVaultDeposit { AccessToken = "ya29.jane", RefreshToken = "1//jane", ExpiresIn = 3599, Scope = "calendar.readonly" });
        Assert.True(account.CanRefresh);
        Assert.Single(await tq.Agents.Vault.ListAccountsAsync("jane@example.com"));
        var token = await agent.GetConnectionTokenAsync("jane@example.com", "google");
        Assert.Equal(("ya29.jane", "Bearer", 3599, "calendar.readonly", "google"), (token.AccessToken, token.TokenType, token.ExpiresIn, token.Scope, token.Connection));
        Assert.Equal("not_connected", (await Assert.ThrowsAsync<TouchQueApiException>(() => agent.GetConnectionTokenAsync("john@example.com", "google"))).Code);
        await tq.Agents.Vault.RemoveAccountAsync("google", "jane@example.com");
        JsonAssert.Equal(new { removed = true, tokensDeleted = 0 }, await tq.Agents.Vault.RemoveConnectionAsync("google"));
    }

    [Fact]
    public async Task AskWaitVerifyRedeem()
    {
        var tq = _api.Client();
        const string user = "agent-approvals@example.com";
        await _api.LinkAsync(user);
        await tq.ActionTypes.DefineAsync("PAY_INVOICE", null, null, false);
        var keys = AgentKeys.Generate();
        var created = await CreateAsync(tq, "Invoice bot", keys.PublicJwk, "PAY_INVOICE");
        using var agent = Agent(created.Id, keys.PrivateJwk);
        var payment = _vectors["approvalToken"]!["claims"]!["authorization_details"]![0]!;

        var ask = await agent.RequestApprovalAsync(user, "PAY_INVOICE", new[] { payment }, new AgentApprovalOptions { Reason = "October rent" });
        Assert.Equal(("pending", "47"), (ask.Status, ask.ChallengeCode));
        await _api.ApproveAsync(ask.ApprovalId);
        var token = (await agent.WaitForApprovalAsync(ask.ApprovalId, TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(500))).ApprovalToken!;

        string? shown = null;
        var required = await agent.RequireApprovalAsync(user, "PAY_INVOICE", new[] { payment }, null, async s =>
        {
            shown = s.ChallengeCode;
            await _api.ApproveAsync(s.ApprovalId);
        }, TimeSpan.FromSeconds(10));
        Assert.Equal("47", shown);
        Assert.False(string.IsNullOrEmpty(required.ApprovalToken));

        // The workspace's own audience comes from GET /agents/approval-audience; another one is refused.
        Assert.Equal("touchque:workspace:fake-workspace", await tq.Agents.ApprovalAudienceAsync());
        var claims = await tq.Agents.VerifyApprovalTokenAsync(token, null, new ApprovalExpectation { User = user, AuthorizationDetails = payment });
        Assert.Equal(created.Id, (string?)claims["act"]!["sub"]);
        var other = await Assert.ThrowsAsync<TouchQueApprovalMismatchException>(() => tq.Agents.VerifyApprovalTokenAsync(token, "touchque:workspace:other"));
        Assert.Contains("another workspace", other.Message);
        var wrongAmount = (JsonObject)payment.DeepClone();
        wrongAmount["instructedAmount"] = new JsonObject { ["currency"] = "TRY", ["amount"] = "5000.00" };
        var mismatch = await Assert.ThrowsAsync<TouchQueApprovalMismatchException>(() => tq.Agents.RedeemApprovalAsync(token, new ApprovalExpectation { AuthorizationDetails = wrongAmount }));
        Assert.Contains("differ", mismatch.Message);
        var approval = await tq.Agents.RedeemApprovalAsync(token, new ApprovalExpectation
        {
            User = user, Type = "PAY_INVOICE", AuthorizationDetails = new { type = "payment_initiation", instructedAmount = new { currency = "try", amount = "500" } },
        });
        Assert.Equal(ask.ApprovalId, approval.Id);
        Assert.Equal("already_redeemed", (await Assert.ThrowsAsync<TouchQueApiException>(() => tq.Agents.RedeemApprovalAsync(token))).Code);

        var ask2 = await agent.RequestApprovalAsync(user, "PAY_INVOICE", new[] { payment }, new AgentApprovalOptions { Presence = "background" });
        Assert.Null(ask2.ChallengeCode);
        await _api.RejectAsync(ask2.ApprovalId);
        var rejected = await Assert.ThrowsAsync<TouchQueApprovalException>(() => agent.WaitForApprovalAsync(ask2.ApprovalId, TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(500)));
        Assert.Equal("rejected", rejected.Status);
    }

    [Fact]
    public async Task BlocksListedAndLifted()
    {
        var tq = _api.Client();
        var a = await CreateAsync(tq, "blocked", AgentKeys.Generate().PublicJwk);
        await _api.PostAsync("/__test/agent-block", new { agentId = a.Id, user = "jane@example.com" });
        Assert.Equal("not_me", (await tq.Agents.ListBlocksAsync(a.Id))[0].Reason);
        await tq.Agents.LiftBlockAsync(a.Id, "jane@example.com");
        Assert.Equal($"/agents/{a.Id}/blocks/jane%40example.com", (string)(await _api.LastCallAsync())["path"]!);
        Assert.Empty(await tq.Agents.ListBlocksAsync(a.Id));
    }

    [Fact]
    public async Task Mandates()
    {
        var tq = _api.Client();
        const string user = "agent-mandates@example.com";
        await _api.LinkAsync(user);
        await tq.ActionTypes.DefineAsync("PAY_INVOICE", null, null, false);
        var keys = AgentKeys.Generate();
        var created = await CreateAsync(tq, "Mandate bot", keys.PublicJwk, "PAY_INVOICE");
        using var agent = Agent(created.Id, keys.PrivateJwk);
        var payment = _vectors["approvalToken"]!["claims"]!["authorization_details"]![0]!;
        var mandate = await agent.RequestMandateAsync(user, "PAY_INVOICE", 2, new MandateAmount("TRY", "1000"), new MandateOptions { ValidFor = 3600 });
        Assert.Equal("pending", mandate.Status);
        var requests = (JsonArray)(await _api.GetAsync("/__test/requests"))!;
        await _api.ApproveAsync((string)requests[^1]!["id"]!);
        Assert.Equal("active", (await agent.GetMandateAsync(mandate.MandateId)).Status);
        var used = await agent.RequestApprovalAsync(user, "PAY_INVOICE", new[] { payment }, new AgentApprovalOptions { MandateId = mandate.MandateId });
        Assert.Equal(("approved", 1), (used.Status, used.Mandate!.UsedCount));
        Assert.Equal(mandate.MandateId, (await tq.Agents.ListMandatesAsync(created.Id, user))[0].MandateId);
        Assert.Equal("revoked", (await tq.Agents.RevokeMandateAsync(created.Id, mandate.MandateId)).Status);
        Assert.Equal("mandate_revoked", (await Assert.ThrowsAsync<TouchQueApiException>(() =>
            agent.RequestApprovalAsync(user, "PAY_INVOICE", new[] { payment }, new AgentApprovalOptions { MandateId = mandate.MandateId }))).Code);
    }
}
