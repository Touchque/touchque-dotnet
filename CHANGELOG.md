# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [4.2.0] — 2026-11-10

### Security
- **The offline approval-token check refuses another workspace's token.** `GET /agents/jwks.json` is one key set for every Touchque workspace, and the check used to compare `aud` only when you passed an audience, so a token Touchque signed for someone else's workspace (their own phone, any person's name, any details) could pass your executor. Now:
  - `Agents.VerifyApprovalTokenAsync(token, audience = null, expect)` uses this workspace's own audience by default: `Agents.ApprovalAudienceAsync()` asks `GET /agents/approval-audience` once (`touchque:workspace:<id>`) and keeps it.
  - `ApprovalToken.VerifyWith(token, jwks, audience, ...)` requires the audience. A missing or empty one throws TouchQueApprovalMismatchException (`audience is required`).
  - A token without `aud` is refused (`the approval token names no workspace`), as is one for another workspace (`the approval token is for another workspace`).
  - Breaking for callers of the low-level function who passed no audience: pass Agents.ApprovalAudienceAsync()'s value.
  - `redeemApproval` was already safe: Touchque compares `aud` with your workspace there.

### Added
- **`DeviceRisk.SearchEventsAsync(new DeviceRiskSearchOptions { ... })`: search your workspace's Device risk identifications**, newest first, one page at a time (`GET /device-risk/events`): `From`/`To` (7 days by default, at most 90, within your retention), `Signal`, `StepUp`, `Kind`, `Origin`, `Ip` (an address or a CIDR range; never returned), `Account`, `VisitorId`, `RequestId`, `Limit` (1 to 100) and the opaque `Cursor` from the previous page's `NextCursor`. `DeviceRiskSearchResult` record.
- `DeviceRiskCheckResult.Engine` (`string?`): the engine's state for this check; `unavailable` when the risk engine could not be reached and the verdict is a safe default (`StepUp` true), so an outage can be told apart from risk.
- **`WebAuthn.PrimaryAvailabilityAsync()`: is passkey sign-in on for your workspace?** `GET /webauthn/authenticate/primary/availability` answers a `WebAuthnPrimaryAvailability` (`Enabled`, `UserVerification` `required` or `preferred`, null when off). Ask before your sign-in page shows its passkey button and passkey autofill; when it is off, `PrimaryOptionsAsync` answers 403 `passwordless_login_disabled`.
- **Shared Signals: receive the security events an identity provider sends after sign-in.** TouchQue SSO sends Security Event Tokens (OpenID Shared Signals Framework 1.0) for an organization's members to the receivers its admin adds (Organization > Continuous access): CAEP `session-revoked`, `credential-change`, `device-compliance-change`, RISC `account-disabled`, `credential-compromise`; `txn` carries the case code of TouchQue's decision. `new SecurityEventVerifier(new() { Issuer, Audience, JwksUri?, Jwks?, ClockSkew? }).VerifyAsync(token)` returns a `SecurityEvent` (`Jti`, `Issuer`, `Audience`, `IssuedAt`, `Txn`, `Subject`, `Type`, `Name`, `Claims`) or throws `TouchQueSecurityEventException` with the RFC 8935 code to answer in `Error` (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`); `SecurityEvents.PollAsync(new() { Url, Token, Ack, SetErrs, MaxEvents })` for poll delivery (RFC 8936); `SecurityEvents.Types`. The keys come from the issuer's `/.well-known/ssf-configuration`; a SET does not expire, so keep the jtis you handled. Tested against the shared vectors (`fixtures/security-event-vectors.json`).
- **Safe Guard: Safe transactions approved on the approver's phone, for TouchQueSafeGuard.** `tq.SafeGuard.RequestAsync(new SafeGuardRequestOptions { ExternalUsername, Type, SafeTx })` sends the raw transaction (the phone decodes it itself and signs with a key only its biometrics unlock), `StatusAsync(requestId)` and `WaitForApprovalAsync(requestId)` hand back the 105-byte approval. `SafeApproval.Verify(target, approval, approverKey, new VerifySafeApprovalOptions { Purpose, ApproverIndex, Rows | DisplayDigest, Now })` checks it the way the guard does, without trusting TouchQue: the Safe transaction hash (EIP-712, Keccak-256 here) and the governance hash computed here, the 149-byte message, low `s`, the one-day expiry window, the P-256 signature. `SafeApproval.WithApprovals(ownerSignatures, approvals)` for `execTransaction`, `SafeApproval.ScheduleCall(safe, governanceHash, approvals)` for a governance change; `SafeTxHash`, `GovernanceHash`, `Message`, `DisplayDigest`. Tested against the shared vectors (`fixtures/safe-guard-vectors.json`).
- **Guard tokens with typed claims:** `GuardToken.Sign(apiSecret, claims)` and `GuardToken.Verify(apiSecret, token)` (Node `signGuardToken` / `verifyGuardToken`) sign and check the token `Guard.RunAsync` hands the browser, for a flow of your own. `GuardTokenClaims` names the short claims (`User`, `Action`, `DetailsDigest`, `ReferenceId`, `State`, `RequestId`, `Number`, `OfflineChallengeId`, `CaseCode`, `ExpiresAt` in Unix milliseconds); `Verify` returns null for a missing, changed, foreign, expired or incomplete token. Tokens are byte-for-byte those of the Node SDK.
- **Webhook events of Never Locked Out and the help desk:** `WebhookResource.EventRecoveryStarted`, `EventRecoveryDeviceBound`, `EventRecoveryCooling`, `EventRecoveryCompleted`, `EventRecoveryVetoed`, `EventRecoveryExpired`, `EventRecoveryFailed` (`RECOVERY_*`) and `EventAssistOpened`, `EventAssistEnded`, `EventAssistCheckPassed`, `EventAssistCheckFailed`, `EventAssistUnfrozen`, `EventAssistClaimConfirmed`, `EventAssistClaimUnverified` (`ASSIST_*`).
- Shared Signals: a README section (verifying a pushed SET, polling) and tests for discovery through `/.well-known/ssf-configuration` and for `SecurityEvents.PollAsync` against a transmitter on this machine.

### Fixed
- `Login.VerifyAsync` (and `TouchQueClient.ProtectAsync`) now send `ExpiresIn` and `ClientSignals` with the request; they were dropped, so the push expired after the 30-second default and the page's automation check never reached the risk engine.
- `MapTouchQueRelay` works on a nested route group (`app.MapGroup("/api").MapTouchQueRelay("/touchque")`) and under a prefix with route parameters; every relay call answered 404 there.
- An empty `ReferenceId` counts as no reference in `CompleteAsync`, so an approval started with `ReferenceId = ""` is no longer used up and then refused as a mismatch. `Guard.RunAsync` (the `RequireTouchQue` filter and the relay) answers 503 `unavailable` for an approval mismatch instead of letting the exception escape as a 500.

### Security
- **Hosted login: an empty `iss` is refused too (RFC 9207).** `HandleCallbackAsync` (and so `MapTouchQueLogin`'s callback) already refused a callback whose `iss` names another issuer; one with an empty `iss=` now throws `issuer_mismatch` as well, before the code is exchanged. A callback without `iss` (a server that does not send it yet, or a null value) is still accepted.
- `SafeApproval.Verify` without `Purpose` now accepts only an ordinary approval (`approve`). An approval to schedule a governance change covers no Safe nonce or gas fields and is accepted only when you pass `Purpose = "schedule"`; before, either purpose passed and a caller treating `Valid` as permission to execute could be handed a schedule approval.
- `HostedLogin` and `MyAccount` refuse a plaintext `http://` Domain except on localhost (`localhost`, `127.0.0.1`, `::1`, `*.localhost`), as `TouchQueOptions.BaseUrl` does; authorization codes, PKCE verifiers, the client secret and tokens would otherwise travel in the clear.

## [4.1.0] — not published (these changes ship in 4.2.0)

### Added
- **Device risk events like a device-intelligence event, without raw traits:** `deviceRisk.check` and `getEvent` answers carry `Network`, `Velocity` and `Bot`: the address as the risk engine saw it (country, region, city, never coordinates; the operator; `type` isp, hosting or tor; `timezoneMismatch` when the browser's clock does not fit the address), the visitor's counts (accounts, sign-ups, countries, stored-id resets, identifications in the last hour and day) and one answer to "a bot?" (`detected`, `suspected` or `not_detected`, with reasons). The field the script tag fills may now carry its pointer summary after the requestId: pass it as it came.

### Changed
- **Silent by default.** Nothing goes to `Console.Error` on its own any more: the SDK's own problems (a misconfigured guard, a failed `OnChallenge`, a relay error or a relay without `GetLoginUser`) go to `TouchQueOptions.Logger` (an `ILogger`), or to `Console.Error` with `Debug = true`; otherwise nowhere. The package now depends on `Microsoft.Extensions.Logging.Abstractions`.
- `TouchQueApprovalMismatchException` no longer names the other person in its message.

### Added
- **A code typed back on the phone:** `LoginRequestOptions.Reply` (`LoginReplyRequest`), `LoginStatus.Reply` (`LoginReply`), `CodeReply.NewKey()` and `CodeReply.Open(privateKey, requestId, ct)`.
- **Feature errors:** a feature your organization cannot use here (403 `feature_not_in_plan`, `feature_read_only`, `feature_off`) throws `TouchQueFeatureNotInPlanException`, `TouchQueFeatureReadOnlyException` or `TouchQueFeatureOffException`, all `TouchQueFeatureException` (`Feature`, `FeatureReason`) and still `TouchQueApiException`.

First release of the .NET SDK, at the same surface as the Node, Python, PHP and Go SDKs 4.1.0.

### Added
- **Webhook events `DEVICE_RISK_SIGNAL` and `DEVICE_RISK_ALERT`** (`Webhook.EventDeviceRiskSignal`, `EventDeviceRiskAlert`): a Device risk signal that asks for more (identifiers, signals and the engine's verdict, never a trait), and an alert rule of the workspace that went off. Signed like every event.
- **Device risk in one line: `await tq.DeviceRisk.CheckAsync(Request.Form["touchque_request_id"], new() { ExternalUsername = email })`** with the script tag (`device.js`, `@touchque/web` 1.6.0), which fills that field. Pass it as it came: null, empty, made up or expired is still a verdict (`Report` missing, unknown, expired, invalid; the signal `device_identification_missing`, a number-matched step-up at most), never an exception. `DeviceRiskResource.Reports`.
- **Device risk: `tq.DeviceRisk.CheckAsync(new DeviceRiskCheckOptions { RequestId = ... })` and `tq.DeviceRisk.GetEventAsync(requestId)`** (a paid add-on; 409 `device_risk_off` until the workspace turns it on), and `DeviceRiskRequestId` (or `DeviceRisk`) on `LoginRequestOptions` and `RiskCheckOptions`. The page's requestId comes from `@touchque/web` `deviceRisk.identify`. Every signal only ever asks for more (`StepUp`, never a refusal); signals start in shadow. `DeviceRiskResource.ParseCheck`, `DeviceRiskResource.Events`.
- **Pairing a browser by QR code: `tq.QrPairings`.** `CreateAsync(new CreateQrPairingOptions { KeyThumbprint, ClientIp, UserAgent, Browser, Os, TtlSeconds })` registers a pairing for the browser key your page holds (`@touchque/web` `browserKey.thumbprint()`) and returns `Uri` (`touchque://pair-browser?...`) to show as a QR code; the nonce in it stays with you (TouchQue keeps its hash). `GetAsync` says who scanned it and how near the phone was (`Proximity`), `RefuseAsync` tells the phone why your own checks said no. `LoginRequestOptions.QrPairing` asks the phone that scanned, once, with number matching. `QrPairingsResource.Uri`, `QrPairingsResource.RefusalReasons`.
- **Actions: the `agent.approval` trigger**, before an AI agent's request reaches the phone (`Trigger = "agent.approval"`); only tightening counts: `api.deny`, `api.requirePasskey`, `api.stepUp`. See [Actions](https://support.touchque.com/actions).
- **Webhook reason `user_blocked_agent`** (`WebhookResource.ReasonUserBlockedAgent`): the person rejected an AI agent's request with Block this agent on their phone; the agent may not ask them again, and 2FA is not frozen. `ListBlocksAsync` can return the block reason `phone`.
- Request options and resources at the 4.1.0 surface: `ChallengeDigits`, `ExpiresIn`, `ClientSignals`, `SecurityChanges`, `Destination` (with the answer's `DestinationCheck`) and `Locale` on login requests; `ClientSignals` on risk checks; the linked phone's posture on `Auth.GetUserAsync`; `Offline.TotpVerifiersAsync` + `OfflineResource.MatchTotpVerifier` for a TouchQue outage; TouchQue Login email and SMS providers (`Identity.SetDeliveryAsync`) and attack protection; Mobile SDK settings with your own APNs key / FCM service account, `AndroidCerts` and `TestPushAsync`.
- **AI agents: events for a SIEM.** `Agents.ListEventsAsync(after, since, limit)`: the workspace's agent events (`AGENT_*`, `AGENTS_*`) oldest first, each with its agent, person, approval and case code; keep `Next` and pass it as `after`.
- **AI agents: the workspace's policy and a passkey line.** `Agents.GetWorkspacePolicyAsync()` / `SetWorkspacePolicyAsync(policy)`: every agent's floor (an agent's own policy can only be stricter, field by field). `AgentPolicy.RequirePasskeyAbove`: over it the person approves with a passkey on your page (`AgentApprovalState.RequiresPasskey`), never on the phone or with a mandate; a background request gets 409 `interactive_required`. `Webhook.EventAgentWorkspacePolicyChanged`. A second approver who answers sooner than a person can gets no token (status `blocked`, reason `inhuman_approval`).
- **TouchQue Login: the approving app's name and custom-domain-only sign-in.** `Identity.SetApproverAppNameAsync(name)`: the phone app the hosted pages tell customers to approve on ("Approve on the Acme app"; `null` = your brand when the Mobile SDK is set up, else TouchQue). `Identity.SetCustomDomainOnlyAsync(true)`: serve sign-in only on the primary custom domain ({slug}.login.touchque.com redirects page loads there and refuses other calls; needs a verified primary domain with a working certificate). `Identity.CheckDomainCertificateAsync(domainId)`: the domain's certificate at the sign-in edge now (`certificate`: pending, active or error).
- **Cross App Access (ID-JAG) and A2A agent cards.** `CrossAppAccess.RequestIdJagAsync` trades a member's ID token for an ID-JAG at the organization's identity provider, `RedeemIdJagAsync` trades it for an access token at the other service (jwt-bearer); `IdJagVerifier` checks one at your own authorization server (typ, issuer, single audience, client, expiry, used once; `FirstUse` for a shared store). `AgentCard.VerifyAsync` checks an A2A card's signatures (JWS over the RFC 8785 canonical card; `jku` only on the card's host or `TrustedJkuHosts`), `Sign`, `CanonicalJson`.
- **`TouchQue`** (.NET 8+, async, nullable): `TouchQueClient` with `Auth`, `Login` (request, status,
  `VerifyAsync` with `OnChallenge`, `ConsumeAsync`, `ReportFraudAsync`, recovery codes), `WebAuthn`,
  `Offline` (QR and typed codes, outage verifiers), `Risk` (silent sign-ins), `ActionTypes`
  (Second Thought questions), `Actions` (TouchQue Actions and their secrets), `Recovery` (Never
  Locked Out), `Assist` (help desk), `Agents` (with the token vault, mandates, blocks, the kill
  switch, approval tokens), `Identity` (the TouchQue Login Management API), `Mobile` (the Mobile
  SDK's server side, `PushFromWebhook`) and `Webhook` (signature, timestamp window, replay cache).
- `StartAsync` / `CheckAsync` / `CompleteAsync` and `Guard.RunAsync`: the two-phase step-up
  contract shared by every TouchQue server SDK, with offline codes, silent sign-ins, Vishing Shield
  (provisional approvals, passkey step-up), Mirror Alarm canaries and "Why?" case codes.
- `RelayHandler<TRequest>`: the routes `@touchque/web` calls, with rate limits (`IRateLimitStore`).
- `ApprovalProof.Verify`, `ApprovalToken`, `AgentKeys` (ES256 and EdDSA), `TouchQueAgent`
  (private_key_jwt + DPoP), `TouchQueOrgAgent` (TouchQue SSO agents: DPoP tokens, token exchange,
  CIBA, token vault, shared accounts, GitHub Actions / file tokens) and `McpAuth`.
- `HostedLogin` (TouchQue Login OpenID Connect client: PKCE, ID and access token checks, refresh,
  token exchange, CIBA, token vault, client credentials, logout) and `MyAccount`.
- **`TouchQue.AspNetCore`**: `AddTouchQue()` (options, the named HttpClient, the webhook replay
  cache), `RequireTouchQue()` endpoint filter and `[RequireTouchQue]` MVC filter,
  `MapTouchQueRelay()`, `MapTouchQueWebhook()`, `AddTouchQueLogin()` + `MapTouchQueLogin()` (cookie
  session with token refresh), `AddTouchQueBearer()` and `MapTouchQueMcpMetadata()` /
  `RequireTouchQueMcp()`.
