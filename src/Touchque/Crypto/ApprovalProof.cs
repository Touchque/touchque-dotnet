using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Touchque.Internal;

namespace Touchque;

/// <summary>Transaction details the way the API normalizes and digests them.</summary>
public static class Details
{
    /// <summary>Labels and values trimmed, in order.</summary>
    public static IReadOnlyList<LoginDetail> Normalize(IEnumerable<LoginDetail>? details) =>
        details is null ? Array.Empty<LoginDetail>() : details.Select(d => new LoginDetail((d.Label ?? "").Trim(), (d.Value ?? "").Trim())).ToList();

    /// <summary>Details from the API's JSON (a list of {label, value} or an object), normalized.</summary>
    public static IReadOnlyList<LoginDetail> FromJson(JsonNode? node)
    {
        var list = new List<LoginDetail>();
        if (node is JsonArray arr)
        {
            foreach (var d in arr)
            {
                list.Add(new LoginDetail(Text(d?["label"]), Text(d?["value"])));
            }
        }
        else if (node is JsonObject obj)
        {
            foreach (var (k, v) in obj) list.Add(new LoginDetail(k, Text(v)));
        }
        return Normalize(list);
    }

    /// <summary>
    /// SHA-256 (hex) over the normalized details joined as label US value RS label…;
    /// empty for no details. The phone signs this digest (<see cref="ApprovalProof"/>).
    /// </summary>
    public static string Digest(IEnumerable<LoginDetail>? details)
    {
        var pairs = Normalize(details);
        if (pairs.Count == 0) return "";
        var canonical = string.Join("\u001e", pairs.Select(p => p.Label + "\u001f" + p.Value));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static string Text(JsonNode? n) => n switch
    {
        null => "",
        JsonValue v when v.TryGetValue<string>(out var s) => s,
        _ => n.ToJsonString(),
    };
}

/// <summary>What <see cref="ApprovalProof.Verify"/> checks the proof against.</summary>
public sealed record ApprovalProofOptions
{
    /// <summary>The id <c>Login.RequestAsync</c> returned.</summary>
    public required string RequestId { get; init; }
    /// <summary>The action type you sent, e.g. WITHDRAW.</summary>
    public required string Type { get; init; }
    /// <summary>The details you sent, exactly as you sent them.</summary>
    public IReadOnlyList<LoginDetail>? Details { get; init; }
    /// <summary>The number-match code, when used.</summary>
    public string? ChallengeCode { get; init; }
    /// <summary>
    /// Pin the device: the base64 public key you stored for this user (e.g. the
    /// <c>publicKey</c> of their first verified approval). Required unless
    /// <see cref="AllowUnpinnedKey"/> is true.
    /// </summary>
    public string? ExpectedPublicKey { get; init; }
    /// <summary>Accept whatever key the proof carries (trust on first use only: store the key, pin it after).</summary>
    public bool AllowUnpinnedKey { get; init; }
}

/// <summary>
/// Verifies the device-signed proof of an approval ("what you see is what you
/// sign"). When the phone holds a hardware key (Secure Enclave / Android Keystore),
/// every approval is signed over the request id, the action type, the number-match
/// code and a digest of the details the user was shown. The proof arrives in the
/// SUCCESS webhook (<c>approvalProof</c>) and in the consumed approval. Verifying it
/// does not require trusting Touchque.
/// </summary>
public static class ApprovalProof
{
    private const string MessagePrefix = "touchque-approve:v2";

    /// <summary>True only if the proof was signed by the device key over exactly what you expect. Never throws.</summary>
    public static bool Verify(JsonObject? proof, ApprovalProofOptions options)
    {
        try
        {
            if (proof is null || Json.Str(proof, "version") != "v2" || Json.Str(proof, "algorithm") != "ECDSA-P256-SHA256") return false;
            var publicKey = Json.Str(proof, "publicKey");
            var message = Json.Str(proof, "message");
            var signature = Json.Str(proof, "signature");
            if (publicKey is null || message is null || signature is null) return false;
            if (!string.IsNullOrEmpty(options.ExpectedPublicKey))
            {
                if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(options.ExpectedPublicKey), Encoding.UTF8.GetBytes(publicKey))) return false;
            }
            else if (!options.AllowUnpinnedKey)
            {
                return false;
            }
            var expected = string.Join("\n", MessagePrefix, options.RequestId ?? "", options.Type ?? "", options.ChallengeCode ?? "", Details.Digest(options.Details));
            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(message))) return false;
            var raw = Convert.FromBase64String(publicKey);
            if (raw.Length != 65 || raw[0] != 0x04) return false;
            var sig = Convert.FromBase64String(signature);
            if (sig.Length == 0) return false;
            using var ec = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = raw[1..33], Y = raw[33..65] },
            });
            return ec.VerifyData(Encoding.UTF8.GetBytes(message), sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (Exception e) when (e is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
    }
}
