using Microsoft.Extensions.Logging;

namespace Touchque;

/// <summary>
/// Settings of a <see cref="TouchqueClient"/>. Anything left null falls back to the
/// environment: <c>TQ_API_KEY</c>, <c>TQ_API_SECRET</c> and <c>TQ_API_URL</c>
/// (default <c>https://api.touchque.com</c>).
/// </summary>
public sealed class TouchqueOptions
{
    public const string DefaultBaseUrl = "https://api.touchque.com";

    /// <summary>Your API key from the dashboard (<c>tq_…</c>).</summary>
    public string? ApiKey { get; set; }

    /// <summary>Your API secret. Signs every request and verifies webhooks; never send it to a browser or an app.</summary>
    public string? ApiSecret { get; set; }

    /// <summary>The API's address. Plain http is accepted only for localhost.</summary>
    public string? BaseUrl { get; set; }

    /// <summary>Timeout of one HTTP request (default 10 seconds). Ignored when you pass your own HttpClient.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Where the SDK reports its own problems: a misconfigured guard, an OnChallenge that threw,
    /// a relay without GetLoginUser. Default: nothing is logged. Lines carry an error's type and
    /// message, never request data.
    /// </summary>
    public ILogger? Logger { get; set; }

    /// <summary>With no <see cref="Logger"/>: write those lines to Console.Error (local development).</summary>
    public bool Debug { get; set; }

    /// <summary>The options with the environment filled in, checked.</summary>
    internal ResolvedOptions Resolve()
    {
        var apiKey = ApiKey ?? Environment.GetEnvironmentVariable("TQ_API_KEY");
        var apiSecret = ApiSecret ?? Environment.GetEnvironmentVariable("TQ_API_SECRET");
        var baseUrl = BaseUrl ?? Environment.GetEnvironmentVariable("TQ_API_URL");
        if (string.IsNullOrEmpty(baseUrl)) baseUrl = DefaultBaseUrl;
        if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(apiSecret))
        {
            throw new TouchqueConfigException("Set TQ_API_KEY and TQ_API_SECRET (or ApiKey and ApiSecret in TouchqueOptions).");
        }
        if (!apiKey.StartsWith("tq_", StringComparison.Ordinal))
        {
            throw new TouchqueConfigException("ApiKey must start with \"tq_\". Did you accidentally swap ApiKey and ApiSecret?");
        }
        AssertSafeBaseUrl(baseUrl, "BaseUrl");
        return new ResolvedOptions(apiKey, apiSecret, baseUrl.TrimEnd('/'), Timeout, new Internal.SdkLog(Logger, Debug));
    }

    /// <summary>Allow plaintext http only for localhost / loopback (local development).</summary>
    internal static void AssertSafeBaseUrl(string url, string name)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new TouchqueConfigException($"{name} is not a valid URL: {url}");
        }
        if (uri.Scheme == Uri.UriSchemeHttps) return;
        if (uri.Scheme == Uri.UriSchemeHttp)
        {
            if (IsLoopback(uri.Host)) return;
            throw new TouchqueConfigException(
                $"Refusing a plaintext http:// {name} for \"{uri.Host}\". The API key and request signature would be sent in the clear: use https://.");
        }
        throw new TouchqueConfigException($"{name} must be http(s): {url}");
    }

    internal static bool IsLoopback(string host)
    {
        var h = host.ToLowerInvariant();
        return h is "localhost" or "127.0.0.1" or "::1" or "[::1]";
    }
}

internal sealed record ResolvedOptions(string ApiKey, string ApiSecret, string BaseUrl, TimeSpan Timeout, Internal.SdkLog Log);
