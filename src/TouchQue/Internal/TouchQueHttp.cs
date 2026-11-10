using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace TouchQue.Internal;

/// <summary>
/// Every partner API call: signed with HMAC-SHA256 over
/// <c>METHOD:pathWithQuery:timestamp:nonce:sha256(body)</c>, sent once, never redirected.
/// </summary>
internal sealed class TouchQueHttp
{
    internal const string SdkVersion = "4.2.0";
    private const int MaxResponseBytes = 10 * 1024 * 1024;

    private readonly HttpClient _client;
    private readonly ResolvedOptions _options;

    public TouchQueHttp(ResolvedOptions options, HttpClient? client)
    {
        _options = options;
        _client = client ?? CreateClient(options.Timeout);
    }

    public string BaseUrl => _options.BaseUrl;

    public string ApiSecret => _options.ApiSecret;

    public SdkLog Log => _options.Log;

    /// <summary>An HttpClient that never follows redirects: a redirect could replay the signed headers to another host.</summary>
    internal static HttpClient CreateClient(TimeSpan timeout) =>
        new(new SocketsHttpHandler { AllowAutoRedirect = false, PooledConnectionLifetime = TimeSpan.FromMinutes(5) })
        {
            Timeout = timeout <= TimeSpan.Zero ? TimeSpan.FromSeconds(10) : timeout,
        };

    public Task<JsonNode?> GetAsync(string path, IEnumerable<KeyValuePair<string, string?>>? query = null, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Get, path + BuildQuery(query), null, ct);

    public Task<JsonNode?> PostAsync(string path, JsonNode? body = null, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Post, path, body ?? new JsonObject(), ct);

    public Task<JsonNode?> PutAsync(string path, JsonNode? body = null, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Put, path, body ?? new JsonObject(), ct);

    public Task<JsonNode?> PatchAsync(string path, JsonNode? body = null, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Patch, path, body ?? new JsonObject(), ct);

    public Task<JsonNode?> DeleteAsync(string path, CancellationToken ct = default) =>
        SendAsync(HttpMethod.Delete, path, null, ct);

    /// <summary>A signed GET whose answer is returned as text (an export file).</summary>
    public async Task<string> GetTextAsync(string path, CancellationToken ct = default) =>
        (await SendRawAsync(HttpMethod.Get, path, null, ct).ConfigureAwait(false)).Text;

    public async Task<T> GetAsync<T>(string path, IEnumerable<KeyValuePair<string, string?>>? query = null, CancellationToken ct = default) =>
        Json.To<T>(await GetAsync(path, query, ct).ConfigureAwait(false));

    public async Task<T> PostAsync<T>(string path, JsonNode? body = null, CancellationToken ct = default) =>
        Json.To<T>(await PostAsync(path, body, ct).ConfigureAwait(false));

    public async Task<T> PutAsync<T>(string path, JsonNode? body = null, CancellationToken ct = default) =>
        Json.To<T>(await PutAsync(path, body, ct).ConfigureAwait(false));

    public async Task<T> PatchAsync<T>(string path, JsonNode? body = null, CancellationToken ct = default) =>
        Json.To<T>(await PatchAsync(path, body, ct).ConfigureAwait(false));

    public async Task<T> DeleteAsync<T>(string path, CancellationToken ct = default) =>
        Json.To<T>(await DeleteAsync(path, ct).ConfigureAwait(false));

    /// <summary>Deterministic query string: keys sorted, values URL-encoded, <c>?</c>-prefixed (or empty).</summary>
    internal static string BuildQuery(IEnumerable<KeyValuePair<string, string?>>? query)
    {
        if (query is null) return "";
        var pairs = query.Where(p => p.Value is not null).OrderBy(p => p.Key, StringComparer.Ordinal).ToList();
        if (pairs.Count == 0) return "";
        return "?" + string.Join("&", pairs.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value!)));
    }

    /// <summary>A path segment, URL-encoded (rawurlencode / encodeURIComponent).</summary>
    internal static string Seg(string value) => Uri.EscapeDataString(value);

    internal static string Sign(string secret, string method, string pathWithQuery, string body, string timestamp, string nonce)
    {
        var bodyHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant();
        var message = $"{method.ToUpperInvariant()}:{pathWithQuery}:{timestamp}:{nonce}:{bodyHash}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(message))).ToLowerInvariant();
    }

    private async Task<JsonNode?> SendAsync(HttpMethod method, string pathWithQuery, JsonNode? body, CancellationToken ct) =>
        (await SendRawAsync(method, pathWithQuery, body, ct).ConfigureAwait(false)).Json;

    private async Task<(JsonNode? Json, string Text)> SendRawAsync(HttpMethod method, string pathWithQuery, JsonNode? body, CancellationToken ct)
    {
        var bodyText = body is null ? "" : Json.Serialize(body);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

        using var request = new HttpRequestMessage(method, _options.BaseUrl + pathWithQuery);
        request.Headers.TryAddWithoutValidation("x-api-key", _options.ApiKey);
        request.Headers.TryAddWithoutValidation("x-signature", Sign(_options.ApiSecret, method.Method, pathWithQuery, bodyText, timestamp, nonce));
        request.Headers.TryAddWithoutValidation("x-timestamp", timestamp);
        request.Headers.TryAddWithoutValidation("x-nonce", nonce);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.TryAddWithoutValidation("User-Agent", "touchque-dotnet-sdk/" + SdkVersion);
        if (body is not null)
        {
            request.Content = new StringContent(bodyText, new UTF8Encoding(false), "application/json");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_options.Timeout <= TimeSpan.Zero ? TimeSpan.FromSeconds(10) : _options.Timeout);

        HttpResponseMessage response;
        try
        {
            response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TouchQueNetworkException("timed out");
        }
        catch (HttpRequestException e)
        {
            throw new TouchQueNetworkException(e.Message, e);
        }

        using (response)
        {
            string text;
            try
            {
                text = await ReadLimitedAsync(response, timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new TouchQueNetworkException("timed out reading the answer");
            }
            var status = (int)response.StatusCode;
            var parsed = Json.Parse(text);
            if (status >= 300)
            {
                var data = parsed as JsonObject ?? new JsonObject();
                if (Json.Int(data, "retryAfter") is null && response.Headers.RetryAfter?.Delta is { } delta)
                {
                    data["retryAfter"] = (int)delta.TotalSeconds;
                }
                if (status < 400)
                {
                    // An API endpoint never redirects; one that does is not TouchQue's.
                    throw new TouchQueApiException(status, data, $"TouchQue: unexpected redirect (HTTP {status}); redirects are never followed.");
                }
                throw TouchQueApiException.For(status, data);
            }
            return (parsed ?? new JsonObject(), text);
        }
    }

    internal static async Task<string> ReadLimitedAsync(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength > MaxResponseBytes)
        {
            throw new TouchQueNetworkException("the answer is larger than 10 MB");
        }
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxResponseBytes)
            {
                throw new TouchQueNetworkException("the answer is larger than 10 MB");
            }
            buffer.Write(chunk, 0, read);
        }
        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    internal static bool IsRedirect(HttpStatusCode code) => (int)code is >= 300 and < 400;
}
