# Touchque for .NET

The official .NET server SDK for [Touchque](https://touchque.com): push approvals with number
matching, passkeys, silent sign-ins, offline codes, verified webhooks, Touchque Actions, AI agent
approvals, Touchque Login (hosted sign-in and the Management API) and the server side of the
Mobile SDK.

| Package | What it is |
| --- | --- |
| `Touchque` | The client. .NET 8+, async throughout, nullable annotations, `HttpClient` / `IHttpClientFactory` friendly. |
| `Touchque.AspNetCore` | `AddTouchque()`, `RequireTouchque()` on endpoints and `[RequireTouchque]` on controllers, the relay endpoints `@touchque/web` needs, verified webhooks, Touchque Login sign-in endpoints and a bearer handler. |

📘 Full docs: **[support.touchque.com](https://support.touchque.com)**

## Install

```bash
dotnet add package Touchque.AspNetCore   # ASP.NET Core (brings Touchque)
dotnet add package Touchque              # anything else: workers, consoles, Azure Functions
```

> **Not on NuGet yet.** Until it is, clone [this repository](https://github.com/Touchque/touchque-dotnet) and add
> `src/Touchque/Touchque.csproj` and `src/Touchque.AspNetCore/Touchque.AspNetCore.csproj` to your solution where they
> are (`dotnet sln add …`): they take net8.0 and their compiler settings from the repository's `Directory.Build.props`.

The packages, assemblies and namespaces are `Touchque` and `Touchque.AspNetCore` (`using Touchque;`, `using Touchque.AspNetCore;`). Coming from 4.x, where the namespaces were spelled with a capital Q: see the 5.0.0 entry in the [CHANGELOG](CHANGELOG.md).

## Setup

Get an API key and secret from your [Touchque dashboard](https://dashboard.touchque.com):

```bash
export TQ_API_KEY=tq_auth_your_key
export TQ_API_SECRET=your_api_secret
```

The secret signs every request: it belongs on your server only, never in a browser or an app.

```csharp
builder.Services.AddTouchque();                       // from the environment
builder.Services.AddTouchque(o => o.ApiKey = "…");    // or from your own configuration
```

Outside ASP.NET Core:

```csharp
var tq = new TouchqueClient();                                            // TQ_API_KEY / TQ_API_SECRET
var tq = new TouchqueClient(new TouchqueOptions { ApiKey = "…", ApiSecret = "…" });
```

`TouchqueClient` is thread-safe: create one and reuse it.

## Quick start (ASP.NET Core)

One line per protected endpoint:

```csharp
app.MapPost("/transfer", (Transfer t, HttpContext http) =>
    {
        var approval = http.GetTouchqueApproval()!;   // only reached once the user approved
        return Results.Ok();
    })
    .RequireAuthorization()
    .RequireTouchque("SEND_MONEY", o => o.Details = c =>
        [("Amount", c.Argument<Transfer>()!.Amount), ("To", c.Argument<Transfer>()!.To)]);
```

Controllers:

```csharp
[HttpPost("/payouts")]
[RequireTouchque("PAYOUT")]
public IActionResult Create() => Ok(HttpContext.GetTouchqueApproval());
// details, a login user or silent sign-ins for it:
builder.Services.Configure<TouchqueGuardOptions>("PAYOUT", o => o.Details = c => …);
```

Until the user approves on their phone the endpoint answers
**`202 {"touchque": step, "token": "..."}`**. Your page shows `step` in its own design (the
matching number, or a QR code the first time the user links the app) and sends the same request
again with header `X-Touchque-Token: <token>`; [`@touchque/web`](https://www.npmjs.com/package/@touchque/web)
does this loop for you. Once approved the endpoint runs **once**. Refusals answer 403 (rejected,
blocked), 408 (expired), 423 (frozen) or 429 (rate limited) with `Retry-After`. Every refusal
also carries `X-Touchque-State: <state>`, and `X-Touchque-Reason: <reason>` when the step has
one. A page on another origin must expose them (`Access-Control-Expose-Headers`).

The approving user is the signed-in user's `email` claim, else `sub`, else the name. For your
login endpoint (nobody is signed in yet) set `o.User = c => …` to whoever just passed your
password check. `o.Enroll = false` never shows a first-time QR: a user with no phone gets 202
with reason `enrollment_off`.

**The end user's address.** The risk checks (Tor, location, impossible travel) and the location
shown on the phone use `HttpContext.Connection.RemoteIpAddress`. Behind a load balancer add
`app.UseForwardedHeaders()` with your proxy as a known proxy, so it is the address your proxy saw.

### Refusals in your app's error shape (`ErrorBody`)

By default, 403, 408, 423 and 429 refusals answer `{"touchque": step, "token": "..."}`, and 401,
500 and 503 answer `{"touchque": step, "error": {"code": ..., "message": ...}}`. To keep your
app's own error shape, set `ErrorBody`:

```csharp
app.MapPost("/transfer", …)
    .RequireTouchque("SEND_MONEY", o => o.ErrorBody = r => new { message = r.Message, code = r.Code });
// 403 {"message":"The approval was rejected.","code":"rejected","touchque":{"state":"rejected",...}}

// Controllers: one action with Configure<TouchqueGuardOptions>("PAYOUT", …), every action with
builder.Services.ConfigureAll<TouchqueGuardOptions>(o => o.ErrorBody = r => new { message = r.Message, code = r.Code });
```

- It is called for every answer with status 400 or more (401, 403, 408, 423, 429, 500, 503),
  never for a 202 step or on approval.
- `r.Status`; `r.Code`: the guard's `error.code`, else the step's `reason`, else its `state`;
  `r.Message`: the guard's message, else a sentence for the state ("The approval was rejected.",
  "The approval expired. Try again.", "Too many rejected approvals. Try again later.", "Too many
  attempts. Try again later.", "The approval was refused."); `r.Touchque`: the step.
- What it returns is written with your app's JSON options: MVC's (`AddJsonOptions`) for a
  controller, the minimal APIs' (`ConfigureHttpJsonOptions`) for an endpoint. When that gives a
  JSON object (an anonymous object, a record, a dictionary, a `JsonObject`), it is sent with
  `touchque` set to the step, and no other spelling of that key is kept (the SDK's key wins, so
  `@touchque/web` still sees the state). No `token` is added. Anything else (a string, a number,
  an array, null) is sent as it is.
- The status and headers stay the same: JSON, `Cache-Control: no-store`, `Retry-After`,
  `X-Touchque-State`, `X-Touchque-Reason`. The callback gets a copy of the step.
- If it throws, or returns what the serializer cannot write, the default body is sent and
  `[Touchque] errorBody failed: <message>` is logged.

### Without an API key

`AddTouchque()` builds the client on the first guarded request, so the app starts without
`TQ_API_KEY` / `TQ_API_SECRET`. Until they are set, a guarded endpoint never runs. It answers 401
`unauthenticated` without a signed-in user, otherwise 500 with `Cache-Control: no-store`:

```json
{"touchque":{"state":"blocked","reason":"misconfigured"},"error":{"code":"misconfigured","message":"Two-factor approval is not configured correctly."}}
```

It is a 500 and not a 503 because it is a setup mistake to fix, not an outage to retry.
`@touchque/web` shows "Approvals are not set up correctly on this site." The SDK logs it once
through `TouchqueOptions.Logger` (or `Debug`): `[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.`
`MapTouchqueRelay` still needs the keys when the app starts, and the webhook endpoint when a
delivery arrives. A guard inside your own handler answers the same with `Guard.WithoutClient(input)`
(see below).

## Action types

`"SEND_MONEY"` above is an action type: one kind of approval, with the title the phone shows and
whether it is critical. Define each one once, in the dashboard (**Developers → Action types**)
or from code:

```csharp
await tq.ActionTypes.DefineAsync("SEND_MONEY", name: "Send money", critical: true);
```

The guard refuses what is not ready. A name that is not defined is a setup error
(`TouchqueConfigException`, "Unknown action …"): the guard answers 500 with `reason: "misconfigured"`. A type
turned off in the dashboard answers 403 with `reason: "action_disabled"`, which stops that kind of
approval at once, without a deploy.

## The three primitives (any framework)

```csharp
var step = await tq.StartAsync("SEND_MONEY", new StartOptions { User = "jane@acme.com", Details = [("Amount", "250 EUR")] });
// step.State: waiting (show step.Number) | enroll (show step.Enroll.QrCodeDataUrl) | passkey_required | blocked | frozen | rate_limited
var now = await tq.CheckAsync(step.RequestId!);
var approval = await tq.CompleteAsync(step.RequestId!, new CompleteExpectations
{
    User = "jane@acme.com", Action = "SEND_MONEY", Details = [("Amount", "250 EUR")],
});   // uses the approval once, and only for this user, action and amount
```

## Guard inside your handler

`Guard.RunAsync` is the whole two-phase contract of `RequireTouchque` as one call, for any
framework (minimal APIs, controllers, Azure Functions). Use it when your own checks must come
first. `r.ToResult()` turns its answer into the status, headers and JSON body that
`RequireTouchque`, `[RequireTouchque]` and `MapTouchqueRelay` send (they share the code):

```csharp
app.MapPost("/transfer", async (Transfer t, HttpContext http) =>
{
    var user = http.User.TouchqueUser();
    // 1. Your own checks first (ownership, balance): a request you refuse anyway never reaches the phone.
    if (!await accounts.CanSendAsync(user, t.Amount)) return Results.Conflict(new { error = "insufficient_funds" });

    var h = http.Request.Headers;
    var input = new GuardInput
    {
        User = user, Action = "SEND_MONEY", Details = [("Amount", t.Amount), ("To", t.To)],
        Ip = http.TouchqueClientIp(), UserAgent = h.UserAgent,
        Token = h[Guard.TokenHeader], Offline = h[Guard.OfflineHeader] == "1",
        Code = h[Guard.CodeHeader], CodeType = h[Guard.CodeTypeHeader],
    };
    GuardResult r;
    try
    {
        // The client AddTouchque registers, resolved per request: built on the first one, never at startup.
        r = await Guard.RunAsync(http.RequestServices.GetRequiredService<TouchqueClient>(), input, http.RequestAborted);
    }
    catch (TouchqueConfigException)
    {
        r = Guard.WithoutClient(input);   // no TQ_API_KEY / TQ_API_SECRET yet: 500 misconfigured (401 without a user)
    }
    // 2. A step (202) or a refusal: its status, headers (Cache-Control, Retry-After, X-Touchque-*) and JSON body.
    if (r.Approved is null) return r.ToResult();
    // 3. Approved: run the action once. The approval is used up.
    return Results.Ok(await payments.SendAsync(t));
});
```

- The client: resolve it per request from `http.RequestServices` and answer
  `Guard.WithoutClient(input)` while it cannot be built. That client reads `AddTouchque`'s options,
  then the environment. Do not take `TouchqueClient` as a handler parameter: it is resolved before
  your code runs, and without keys it throws `TouchqueConfigException` outside your `try`.
- Keys in the environment only (no options in `AddTouchque`, or no `AddTouchque`): pass `null`.
  `Guard.RunAsync(null, input)` uses `Guard.DefaultClient()`, built from `TQ_API_KEY`,
  `TQ_API_SECRET` and `TQ_API_URL` on the first request and kept (a failed build is tried again on
  the next one). It never reads `AddTouchque`'s options. While it cannot be built, the answer is
  401 `unauthenticated` without a user, else 500 `misconfigured`, and
  `Guard.IsStatusPoll(null, input)` is false.
- That null-client path logs nothing: the SDK's logger belongs to a client, and it is silent by
  default. To fail fast, call `Guard.DefaultClient()` at startup: it throws
  `TouchqueConfigException`, naming the problem. To give the path a logger, set a client built with
  one: `Guard.SetDefaultClient(new TouchqueClient(new TouchqueOptions { Logger = logger }))`.
  `Guard.SetDefaultClient(null)` forgets it, and the next call builds one from the environment again.
- Run it after your own checks (ownership, balance), with the details the phone shows, built on
  your server.
- Not approved: return `r.ToResult(errorBody)`, or `await r.WriteAsync(http, errorBody)` where you
  write the response yourself. Its headers are `Cache-Control: no-store`, `Retry-After` on 423 and
  429, and on a refusal `X-Touchque-State` and `X-Touchque-Reason`. `errorBody` is your shape for
  refusals, with the [`ErrorBody`](#refusals-in-your-apps-error-shape-errorbody) rules: written
  with your app's JSON options (MVC's in a controller action), and a failure is logged through
  `TouchqueOptions.Logger`.
- Approved (`r.Approved` is set): run the action once. A replay of the same token is refused.
- 202 `{"touchque": step, "token": "..."}`: the page shows the step and sends the same request
  again with `X-Touchque-Token: <token>`, every ~1.5 s (`touchqueFetch` from `@touchque/web` does
  this). The token is bound to the user, action, details and `ReferenceId`.
- Waiting polls (`waiting`, `passkey_required`) carry the request's `expiresAt` on every answer,
  not only the first, so a page can stop by time on the latest one. It is the live expiry from
  Touchque's status answer: a Vishing Shield escalation to a passkey extends it to 180 s.
- While the first-time QR is up, polls answer `{state: "enroll", expiresAt}` without `enroll`:
  keep showing the QR you have. About 15 s before it expires, a new QR comes with
  `enroll.qrCodeDataUrl`, together with new recovery codes; the old QR and the old codes stop
  working. Pages on @touchque/web need 2.1.0.
- `Enroll = false` never shows a first-time QR: a user with no phone gets 202
  `{"state": "enroll", "reason": "enrollment_off"}`. `@touchque/web` 2.2.0 stops polling there and
  says no phone is linked yet.
- A 202 state other than `waiting` or `enroll` (`passkey_required`, `offline`, an `enroll` with a
  reason) needs `@touchque/web`, or your own UI following this contract.
- `Guard.IsStatusPoll(tq, input)` is true for a poll that only reads a state (a push on its way,
  or a first-time QR with more than 15 s left), so your own rate limit can let it through. If it
  does, charge what such a poll may still start in `BeforeStart = async () => …`: the guard calls
  it once, right before a first-time QR poll starts a push (the phone got linked) or a new QR, and
  answers your result instead when you return one. `MapTouchqueRelay` does this, so every start
  is counted.
- `GuardRefusal.From(r)` gives a refusal's status, code and message for your own error body.

## Waiting in one call

```csharp
var result = await tq.Login.VerifyAsync(new LoginRequestOptions
{
    ExternalUsername = "jane@acme.com",
    Type = "LOGIN",
    ClientIp = ip, UserAgent = userAgent,
    // Number matching: show the number now; the phone asks for it.
    OnChallenge = c => { if (c.ChallengeCode is { } n) Notify($"Pick {n} on your phone"); return Task.CompletedTask; },
});
```

`VerifyAsync` throws `TouchqueRejectedException`, `TouchqueTimeoutException` or
`TouchquePasskeyRequiredException` (`Reason` `policy`: approve with a passkey; `step_up`: the user
tapped Approve during a call and the request now waits for a passkey).

## Relay endpoints for `@touchque/web`

```csharp
app.MapTouchqueRelay("/touchque", new RelayOptions<HttpContext>
{
    GetUserId = http => http.User.TouchqueUser(),
    // The user who already passed your password step. Binds /login and the offline routes to them.
    GetLoginUser = http => http.Session.GetString("password_verified_user"),
    OnAuthenticated = async (http, response, info) => await SignInAsync(http, info.ExternalUsername),
    SilentSignIn = new(),   // a known browser with nothing new skips the push
});
```

Routes: `POST /login`, `/enroll/start`, `GET /enroll/status`, `/offline/challenge|verify|totp`,
`/passkey/authenticate/options|verify`, `/passkey/login/options|verify`,
`/passkey/register/options|verify`, `GET /passkey/credentials`, `DELETE /passkey/credentials/{id}`.
Pre-auth routes are rate limited (20 per IP, 5 per username a minute; `RateLimit = new() { Store = … }`
for Redis across instances). The offline routes stay off until `GetLoginUser` is set, and so does
the first-time QR on `/login`: without `GetLoginUser`, a user with no phone gets 202
`{"state": "enroll", "reason": "enrollment_off"}`. Adding a passkey for a user with a linked phone
waits for the phone first.

## Webhooks

```csharp
app.MapTouchqueWebhook("/webhooks/touchque", async (JsonObject e, HttpContext http) =>
{
    if ((string?)e["event"] == WebhookResource.EventApprovalRevoked) await EndSessionAsync((string)e["requestId"]!);
});
```

The signature (your API secret over the canonical JSON), the signed timestamp (5 minutes) and the
`jti` (replays answered 200 without calling you again) are checked first. The in-process replay
cache is registered by `AddTouchque()`; with several instances register your own
`IWebhookReplayCache` (Redis `SET NX EX`). Anywhere else: `tq.Webhook.VerifyAsync(rawBody, signatureHeader, 300, cache)`.

## Silent sign-ins

```csharp
var risk = await tq.Risk.CheckAsync(new RiskCheckOptions { ExternalUsername = user, BrowserProof = Request.Headers["X-Touchque-Browser"], ClientIp = ip });
if (!risk.Prompt) SignIn(user);   // a known browser, nothing new: no push
```

Fails closed: only an answer of exactly `prompt: false` skips the phone. `tq.Risk.BrowsersAsync()`
lists a user's known browsers, `ForgetBrowsersAsync()` forgets them (after a password reset).

## Passkeys, offline codes, recovery, help desk

- `tq.WebAuthn`: registration, second factor and passwordless sign-in options/verify, list and delete passkeys.
- `tq.Offline`: QR challenge and typed codes with the phone offline; `TotpVerifiersAsync` +
  `OfflineResource.MatchTotpVerifier` check time-based codes while Touchque is unreachable.
- `tq.Recovery` (Never Locked Out): vouchers, `StartAsync` (show `BindUri` as a QR), `StatusAsync`, `VetoAsync`.
- `tq.Assist` (help desk): `OpenAsync`, `VerifyAsync` (a 2-digit code the agent reads to the person), `SpendAsync`, `UnfreezeAsync`, `EndAsync`.
- `ApprovalProof.Verify(proof, options)`: the phone's own signature over what it showed ("what you see is what you sign").

## Touchque Actions

```csharp
await tq.Actions.DeployAsync("night-alert", new DeployActionOptions
{
    Trigger = "approval.decided",
    Template = ActionTemplateRef.Of("alert", new { channel = "slack", when = new { countries = new[] { "TR" } } }),
});
var replay = await tq.Actions.DryRunAsync(new DryRunActionOptions { Trigger = "login.request", Code = code, Limit = 500 });
```

Plus `TestAsync`, `RollbackAsync`, `LogsAsync`, `MetricsAsync`, `TemplatesAsync`, `Secrets`. Action code is JavaScript run by Touchque in a sandbox, whatever language your server is in. Action types: `tq.ActionTypes.DefineAsync("SEND_MONEY", "Send money", critical: true)`.

## AI agents

Your server registers agents (public key only) and checks their approvals; the agent signs in with its own key:

```csharp
var keys = AgentKeys.Generate();                       // where the agent runs; ES256 or "EdDSA"
var agent = await tq.Agents.CreateAsync(new CreateAgentOptions { Name = "Invoice bot", AllowedTypes = ["PAY_INVOICE"], PublicKey = keys.PublicJwk });

// The agent (TQ_AGENT_ID, TQ_AGENT_KEY): private_key_jwt + DPoP, never your API key.
using var bot = new TouchqueAgent();
var approved = await bot.RequireApprovalAsync("ayse@acme.com", "PAY_INVOICE", new[] { payment },
    onChallenge: s => Say($"Type {s.ChallengeCode} on your phone"));

// Your server, right before it pays:
var used = await tq.Agents.RedeemApprovalAsync(approved.ApprovalToken!, new ApprovalExpectation { User = "ayse@acme.com", AuthorizationDetails = payment });
```

Also: mandates (`RequestMandateAsync`), the token vault (`tq.Agents.Vault`, `bot.GetConnectionTokenAsync`),
policies, blocks, the kill switch, offline token checks (`VerifyApprovalTokenAsync`).
`TouchqueOrgAgent` is an organization's agent on Touchque SSO (DPoP tokens for one app, token
exchange, CIBA, the token vault, shared accounts; GitHub Actions and Kubernetes tokens instead of
a stored key). `McpAuth` protects an MCP server whose authorization server is Touchque SSO
(`app.MapTouchqueMcpMetadata(auth)`, `.RequireTouchqueMcp(auth)`).

### Cross App Access (ID-JAG) and A2A agent cards

An organization's identity provider (Touchque SSO) can let one of its apps reach another service for a member with no consent screen (Cross App Access, ID-JAG, an open IETF draft): the app trades the member's ID token for an ID-JAG, then the ID-JAG for an access token at the other service. If you run an authorization server, the verifier checks an ID-JAG (issuer, single audience, your client, expiry, `typ`) and uses it once. Before your agent trusts another agent's A2A card, check its signatures (A2A 1.0 §8.4: JWS over the RFC 8785 canonical card); keys named by `jku` are only fetched from the card's own host or hosts you trust.

```csharp
var jag = await CrossAppAccess.RequestIdJagAsync(new() { Issuer = "https://sso.touchque.com", ClientId = clientId,
    ClientSecret = secret, IdToken = idToken, Audience = "https://auth.files.example" });
var tokens = await CrossAppAccess.RedeemIdJagAsync(new() { TokenEndpoint = "https://auth.files.example/token", ClientId = "acme",
    ClientSecret = filesSecret, Assertion = jag.Assertion });

// Your own authorization server (jwt-bearer grant):
var verifier = new IdJagVerifier(new() { Issuer = "https://sso.touchque.com", Audience = "https://auth.files.example" });
var claims = await verifier.VerifyAsync(form["assertion"]!, authenticatedClientId);

await AgentCard.VerifyAsync(cardJson, new() { CardUrl = "https://agent.example/.well-known/agent-card.json" });
```

## Shared Signals (security events from Touchque SSO)

When something happens to an organization member's account after sign-in, Touchque SSO sends a Security Event Token (OpenID Shared Signals Framework 1.0, RFC 8417) to the receivers its admin adds (Organization > Continuous access): CAEP `session-revoked`, `credential-change`, `device-compliance-change`; RISC `account-disabled`, `credential-compromise`. Your app ends the person's sessions or asks them to sign in again. `SecurityEventVerifier` checks the signature (RS256, with the keys named by the issuer's `/.well-known/ssf-configuration`, or `JwksUri` / pinned `Jwks`), `typ`, the issuer, your audience and that the SET carries exactly one event; `Txn` is the case code of Touchque's decision.

```csharp
var verifier = new SecurityEventVerifier(new() { Issuer = "https://sso.touchque.com", Audience = "https://app.example.com" });

// Push delivery (RFC 8935): the SET is the request body (application/secevent+jwt).
app.MapPost("/ssf", async (HttpRequest req) =>
{
    try
    {
        var ev = await verifier.VerifyAsync(await new StreamReader(req.Body).ReadToEndAsync());
        if (ev.Name == "session-revoked") await EndSessionsAsync((string?)ev.Subject["email"]);
        return Results.StatusCode(202);
    }
    catch (TouchqueSecurityEventException e)
    {
        return Results.Json(new { err = e.Error, description = e.Message }, statusCode: e.Error == "temporarily_unavailable" ? 503 : 400);
    }
});

// Poll delivery (RFC 8936): acknowledge the jtis you handled, read the SETs that wait.
var (sets, moreAvailable) = await SecurityEvents.PollAsync(new() { Url = pollUrl, Token = streamToken, Ack = handled });
foreach (var (jti, set) in sets) await HandleAsync(await verifier.VerifyAsync(set));
```

A refused SET throws `TouchqueSecurityEventException`; `Error` is the RFC 8935 code to answer with (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`), or `temporarily_unavailable` when the issuer's keys could not be read (answer 503: the transmitter tries again). A SET does not expire: keep the jtis you handled and skip a repeat. `SecurityEvents.Types` maps the short names to the event type URIs.

## Touchque Login (hosted sign-in)

```csharp
builder.Services.AddTouchqueLogin(o =>
{
    o.Domain = "acme.login.touchque.com";
    o.ClientId = "…";
    o.ClientSecret = "…";
    o.Scope = "openid profile email offline_access";
});
app.UseAuthentication();
app.UseAuthorization();
app.MapTouchqueLogin();                                  // GET /login, /callback, /logout
app.MapGet("/account", (ClaimsPrincipal u) => u.FindFirstValue("email")).RequireAuthorization();
```

The session is ASP.NET Core's cookie authentication; tokens are kept in it
(`HttpContext.GetTokenAsync("access_token")`) and refreshed before they expire. Your API checks
Touchque Login access tokens with a bearer scheme:

```csharp
builder.Services.AddAuthentication().AddTouchqueBearer(o =>
{
    o.Domain = "acme.login.touchque.com";
    o.Audience = "https://api.acme.com";
    o.RequiredScopes = ["read:orders"];
});
```

`HostedLogin` is the OpenID Connect client underneath (PKCE, ID token checks, refresh, token
exchange, CIBA, the token vault, client credentials, logout); `login.MyAccount(accessToken)` is
the customer's own account API (profile, sign-in methods, sessions, apps, data export, deletion).
The Management API is `tq.Identity` (users, roles, organizations, apps, connections, imports and
exports, attack protection, email and SMS providers).

## Mobile SDK (your own app approves)

```csharp
var e = await tq.Mobile.CreateEnrollmentAsync(userId);   // the app spends e.EnrollmentToken
var push = MobileResource.PushFromWebhook(webhookEvent);  // a MOBILE_PUSH webhook → APNs payload / FCM data
```

Or give Touchque your APNs key / FCM service account (`UpdateSettingsAsync`) and it pushes for you.

## Pairing a browser by QR code

Your page shows a QR code, the person scans it with the Touchque app, and the phone that scanned is the one asked to approve, with number matching. Your page sends the thumbprint of its browser key (`@touchque/web` `browserKey.thumbprint()`); the nonce in the QR never leaves your server (Touchque keeps its hash).

```csharp
var p = await tq.QrPairings.CreateAsync(new CreateQrPairingOptions { KeyThumbprint = thumb, ClientIp = ip, UserAgent = userAgent });
// show p.Uri (touchque://pair-browser?...) as a QR code; poll:
var now = await tq.QrPairings.GetAsync(p.PairingId);   // waiting -> scanned -> confirmed
if (now.State == "confirmed")
    await tq.Login.RequestAsync(new LoginRequestOptions { ExternalUsername = now.ExternalUsername!, QrPairing = p.PairingId });
// or: await tq.QrPairings.RefuseAsync(p.PairingId, new RefuseQrPairingOptions { Reason = "device_not_approved", Message = "Ask IT to approve this computer." });
```

`get` says `scanned` / `confirmed` once a phone holding one of your users' accounts read it (with `proximity`: same network, same country), `reported` when the person said someone told them to scan it (their 2FA freezes). `refuse` tells the phone why your own checks said no.

## A code typed back on the phone

When a sign-in needs a code another service sent the person (a text message, WhatsApp, e-mail), ask them to type it on the phone instead. The phone encrypts it to a one-time key you made for this request: Touchque only ever holds the ciphertext. Such a request lives 5 minutes.

```csharp
var key = CodeReply.NewKey();   // keep key.PrivateKey for this request
var sent = await tq.Login.RequestAsync(new LoginRequestOptions { ExternalUsername = user, Reply = new LoginReplyRequest(key.PublicKey, "sms", "+**********26") });
var status = await tq.Login.StatusAsync(sent.RequestId);   // once CONFIRMED
var code = status.Reply is { } r ? CodeReply.Open(key.PrivateKey, sent.RequestId, r.Ct) : null;
```

## Safe Guard (Safe transactions approved on the phone)

TouchqueSafeGuard is a transaction guard for a Safe: a transaction runs only with approvals signed by the P-256 keys on its approvers' phones. You send the raw transaction; the phone decodes it itself, shows its own rows and signs what it computed with a key only its biometrics unlock. Delegatecalls, changes to the Safe and proxy upgrades are governance: scheduled, time-locked and vetoable. A phone without that key yet gets `409 crypto_key_missing`.

```csharp
var tx = new SafeGuardTx
{
    ChainId = "1", Safe = safe, Guard = guard,
    Tx = new SafeTxCall { To = to, Value = "0", Data = data, Operation = 0, Nonce = "42" },
    Config = new SafeGuardConfig { Threshold = 2, GovThreshold = 3, GovDelay = 172800, ExitDelay = 259200 },
    BatchTargets = [multiSendCallOnly],
    ApproverIndex = 0,   // this approver's index in the guard
};
var sent = await tq.SafeGuard.RequestAsync(new SafeGuardRequestOptions { ExternalUsername = "treasurer@acme.com", Type = "safe_payment", SafeTx = tx });
var done = await tq.SafeGuard.WaitForApprovalAsync(sent.RequestId);   // 5 minutes at most
var approval = done.SafeTx!.Approval!;

// Check it yourself: your own transaction, the approver's key from the guard on chain, the purpose you act on.
var purpose = done.SafeTx.Purpose;   // "approve" runs the transaction, "schedule" only starts a governance change's waiting time
var check = SafeApproval.Verify(tx, approval, approverKey, new VerifySafeApprovalOptions { Purpose = purpose, ApproverIndex = 0 });
if (!check.Valid) throw new InvalidOperationException($"approval refused: {check.Reason}");
var payload = purpose == "approve"
    ? SafeApproval.WithApprovals(ownerSignatures, [approval])                  // execTransaction(…, signatures)
    : SafeApproval.ScheduleCall(safe, check.GovernanceHash, [approval]);      // a call to the guard; runs after govDelay
```

`SafeApproval.Verify` makes the guard's check off chain, so a co-signer or your own server never has to trust Touchque: it computes the Safe transaction hash (EIP-712) and the governance hash from the raw fields, rebuilds the 149-byte message the phone signed and checks the P-256 signature. It refuses a high `s`, an approval that expired or is valid for more than a day, another approver index, and, when you pass `Rows` or `DisplayDigest` from your own decoding, rows the phone did not show. Without `Purpose` it checks only an ordinary approval (`approve`): an approval to schedule a governance change covers no Safe nonce or gas fields, so it is accepted only when you pass `Purpose = "schedule"`. `Reason` is `approval_malformed`, `public_key_invalid`, `approver_index_mismatch`, `approval_expired`, `rows_differ`, `high_s` or `signature_invalid`. `SafeApproval.SafeTxHash`, `GovernanceHash`, `Message` and `DisplayDigest` are public too.

## Errors, case codes and retries

| Exception | When |
| --- | --- |
| `TouchqueApiException` | Touchque answered with an error: `Status`, `Code` (`device_not_linked`, `already_used`…), `CaseCode`, `RetryAfter`, `Body` |
| `TouchqueNetworkException` | the request never reached Touchque (safe to retry) |
| `TouchqueRejectedException`, `TouchqueTimeoutException`, `TouchquePasskeyRequiredException` | `VerifyAsync` outcomes |
| `TouchqueWebhookSignatureException`, `TouchqueWebhookReplayException` | webhooks |
| `TouchqueApprovalException`, `TouchqueApprovalMismatchException` | agent approvals |
| `TouchqueConfigException` | a missing key, an unknown action type, a wrong argument |

A feature your organization cannot use here throws a `TouchqueFeatureException` (still a `TouchqueApiException`, status 403) with `Feature` (`device_risk`, `ai_agents`…) and `FeatureReason`: `TouchqueFeatureNotInPlanException`, `TouchqueFeatureReadOnlyException` or `TouchqueFeatureOffException` — not in its plan (an owner or admin adds it in the Touchque dashboard), being turned off (reads work for 14 days, changes are refused) or switched off on this Touchque deployment.

**"Why?" case codes.** Refusals and pushes carry a 6-character case code (`K7P-2QX`): show it
("Tell your support team: K7P-2QX"); your team opens the whole decision by it in the dashboard.

**Retries.** Every request is signed with a one-time nonce, so the SDK never replays one and you
should not add a retry handler to the `Touchque` HttpClient. Retry `TouchqueNetworkException` at
the call site; on 429 / 423 wait `RetryAfter` seconds. The client never follows redirects and
refuses plain `http://` except for localhost.

**HttpClient.** `AddTouchque()` registers the named client `Touchque` (no redirects, connections
recycled every 5 minutes) and returns its `IHttpClientBuilder` for logging or a proxy. Outside
DI pass your own: `new TouchqueClient(options, httpClient)`.

## Logging

The SDK writes nothing to the console on its own. To see its own problems (a misconfigured guard or missing keys behind one, a failed `ErrorBody` or `OnChallenge`, a relay without `GetLoginUser`), set `TouchqueOptions.Logger` to an `ILogger` (`loggerFactory.CreateLogger("Touchque")`), or `Debug = true` for `Console.Error`. Lines carry an error's type and message, never the request.

## Development

```bash
dotnet test        # needs Node.js: the tests run against testing/fake-touchque-api.mjs and fixtures/
dotnet pack -c Release
```

## License

MIT
