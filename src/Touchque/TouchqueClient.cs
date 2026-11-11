using Touchque.Internal;

namespace Touchque;

/// <summary>
/// The Touchque client. Every call is signed with your API secret, so it belongs on
/// your server; browser pieces relay through it.
/// <code>
/// // TQ_API_KEY=tq_…  TQ_API_SECRET=…
/// var tq = new TouchqueClient();
/// var step = await tq.StartAsync("SEND_MONEY", new StartOptions { User = "jane@acme.com", Details = [("Amount", "250 EUR")] });
/// </code>
/// Thread-safe; create one and reuse it (in ASP.NET Core, <c>services.AddTouchque()</c>).
/// </summary>
public sealed class TouchqueClient
{
    public const string DefaultBaseUrl = TouchqueOptions.DefaultBaseUrl;

    private readonly TouchqueHttp _http;

    /// <summary>A client from the environment (<c>TQ_API_KEY</c>, <c>TQ_API_SECRET</c>, <c>TQ_API_URL</c>).</summary>
    public TouchqueClient() : this(new TouchqueOptions()) { }

    /// <param name="options">Anything left null falls back to the environment.</param>
    /// <param name="httpClient">
    /// Your own HttpClient (e.g. from IHttpClientFactory). Configure it NOT to follow
    /// redirects: a redirect could replay the signed headers to another host.
    /// </param>
    public TouchqueClient(TouchqueOptions options, HttpClient? httpClient = null)
    {
        var resolved = options.Resolve();
        _http = new TouchqueHttp(resolved, httpClient);
        Auth = new AuthResource(_http);
        Login = new LoginResource(_http);
        WebAuthn = new WebAuthnResource(_http);
        Webhook = new WebhookResource(resolved.ApiSecret);
        Offline = new OfflineResource(_http);
        ActionTypes = new ActionTypesResource(_http);
        Actions = new ActionsResource(_http);
        Risk = new RiskResource(_http);
        Recovery = new RecoveryResource(_http);
        Assist = new AssistResource(_http);
        Agents = new AgentsResource(_http);
        Identity = new IdentityResource(_http);
        Mobile = new MobileResource(_http);
        QrPairings = new QrPairingsResource(_http);
        DeviceRisk = new DeviceRiskResource(_http);
        SafeGuard = new SafeGuardResource(_http);
    }

    /// <summary>Setup secrets and a user's link status.</summary>
    public AuthResource Auth { get; }

    /// <summary>Push approvals: request, status, verify, use once, report fraud.</summary>
    public LoginResource Login { get; }

    /// <summary>Passkeys (the backend half of the browser ceremonies).</summary>
    public WebAuthnResource WebAuthn { get; }

    /// <summary>Webhook signature verification.</summary>
    public WebhookResource Webhook { get; }

    /// <summary>Offline Sign: QR challenge and typed-code approvals with the phone offline.</summary>
    public OfflineResource Offline { get; }

    /// <summary>Action types: what users approve (LOGIN, SEND_MONEY…).</summary>
    public ActionTypesResource ActionTypes { get; }

    /// <summary>Touchque Actions: your own code in the approval pipeline (deploy, test, dry run, logs).</summary>
    public ActionsResource Actions { get; }

    /// <summary>Silent sign-ins: should this sign-in ask the phone, and which browsers Touchque knows.</summary>
    public RiskResource Risk { get; }

    /// <summary>Never Locked Out: move a user whose phone is gone to a new phone, with colleagues vouching.</summary>
    public RecoveryResource Recovery { get; }

    /// <summary>Help desk: IT working on a person's account in the open, and checks on their phone before sensitive actions.</summary>
    public AssistResource Assist { get; }

    /// <summary>AI agents as identities of their own. The agent itself uses <see cref="TouchqueAgent"/>.</summary>
    public AgentsResource Agents { get; }

    /// <summary>Touchque Login: your customers' accounts, roles, organizations, apps, connections (Management API).</summary>
    public IdentityResource Identity { get; }

    /// <summary>Mobile SDK: your own iOS/Android app approves for your users.</summary>
    public MobileResource Mobile { get; }

    /// <summary>Pairing a browser by QR code: the phone that scans it is the one asked to approve.</summary>
    public QrPairingsResource QrPairings { get; }

    /// <summary>Device risk: the device on your sign-up, reset, sign-in or approval page (a paid add-on).</summary>
    public DeviceRiskResource DeviceRisk { get; }

    /// <summary>Safe Guard: Safe transactions approved on the approver's phone, for TouchqueSafeGuard.</summary>
    public SafeGuardResource SafeGuard { get; }

    internal string ApiSecret => _http.ApiSecret;

    internal SdkLog Log => _http.Log;

    internal string BaseUrl => _http.BaseUrl;

    /// <summary>
    /// Starts an approval and returns at once: show the step in your UI. <c>waiting</c>
    /// with <c>Number</c>: show the number, the user picks it on the phone. <c>enroll</c>:
    /// show <c>Enroll.QrCodeDataUrl</c> so the user links the Touchque app first.
    /// </summary>
    public Task<Step> StartAsync(string action, StartOptions options, CancellationToken ct = default) =>
        Steps.StartAsync(this, action, options, ct);

    /// <summary>Where a started approval is now: waiting, approved, rejected, expired…</summary>
    public Task<Step> CheckAsync(string requestId, CancellationToken ct = default) =>
        Steps.CheckAsync(this, requestId, ct);

    /// <summary>
    /// Uses an approved request exactly once, after checking it is for this user, action
    /// and transaction. Call it right before doing the protected thing.
    /// </summary>
    /// <exception cref="TouchqueApprovalMismatchException">The approval is for a different user, action or transaction.</exception>
    /// <exception cref="TouchqueApiException">409 already_used, not_approved, rejected, expired or revoked.</exception>
    public Task<Approval> CompleteAsync(string requestId, CompleteExpectations expect, CancellationToken ct = default) =>
        Steps.CompleteAsync(this, requestId, expect, ct);

    /// <summary>
    /// Runs <paramref name="action"/> only after the user approved it on the phone (the push
    /// and the wait of <see cref="LoginResource.VerifyAsync(LoginRequestOptions, CancellationToken)"/>).
    /// </summary>
    public async Task<T> ProtectAsync<T>(LoginRequestOptions request, Func<Task<T>> action, CancellationToken ct = default)
    {
        await Login.VerifyAsync(request, ct).ConfigureAwait(false);
        return await action().ConfigureAwait(false);
    }
}
