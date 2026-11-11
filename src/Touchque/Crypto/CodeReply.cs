using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Touchque.Internal;

namespace Touchque;

/// <summary>
/// A code the person types back on the phone (<see cref="LoginRequestOptions.Reply"/>): a sign-in
/// code another service sent them (a text message, WhatsApp, e-mail). Each request gets a one-time
/// P-256 key pair; its public key goes with the request, the phone encrypts what was typed to it,
/// and only you can open it: Touchque stores and hands back nothing but the ciphertext
/// (<see cref="LoginStatus.Reply"/>).
/// ECDH P-256, HKDF-SHA256 (salt: the request id, info <c>touchque-code-reply-v1</c>), AES-256-GCM
/// (additional data <c>touchque-code-reply:&lt;request id&gt;</c>), as
/// <c>v1.&lt;the phone's one-time key, x9.63&gt;.&lt;nonce|ciphertext|tag&gt;</c>, base64url.
/// </summary>
public static partial class CodeReply
{
    private static readonly byte[] Info = Encoding.UTF8.GetBytes("touchque-code-reply-v1");

    [GeneratedRegex("^v1\\.([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)$")]
    private static partial Regex CtRe();

    [GeneratedRegex("^[A-Za-z0-9 -]{4,20}$")]
    private static partial Regex CodeRe();

    /// <summary>
    /// A one-time key pair for one request: send <c>PublicKey</c> (the uncompressed P-256 point,
    /// base64url) as <see cref="LoginReplyRequest.Key"/>, keep <c>PrivateKey</c> (PKCS#8 DER,
    /// base64url) server-side, for this one request.
    /// </summary>
    public static (string PublicKey, string PrivateKey) NewKey()
    {
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var p = key.ExportParameters(false);
        var point = new byte[65];
        point[0] = 4;
        p.Q.X!.CopyTo(point, 1);
        p.Q.Y!.CopyTo(point, 33);
        return (Base64Url.Encode(point), Base64Url.Encode(key.ExportPkcs8PrivateKey()));
    }

    /// <summary>The code the person typed, or null when <paramref name="ct"/> does not open with this key for this request.</summary>
    public static string? Open(string privateKey, string requestId, string ct)
    {
        try
        {
            var m = CtRe().Match(ct ?? "");
            if (!m.Success) return null;
            var epk = Base64Url.Decode(m.Groups[1].Value);
            var box = Base64Url.Decode(m.Groups[2].Value);
            if (epk.Length != 65 || epk[0] != 4 || box.Length < 12 + 16 + 1) return null;
            using var priv = ECDiffieHellman.Create();
            priv.ImportPkcs8PrivateKey(Base64Url.Decode(privateKey), out _);
            using var peer = ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = epk[1..33], Y = epk[33..65] },
            });
            var shared = priv.DeriveRawSecretAgreement(peer.PublicKey);
            var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, Encoding.UTF8.GetBytes(requestId), Info);
            var cipher = box[12..^16];
            var plain = new byte[cipher.Length];
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(box[..12], cipher, box[^16..], plain, Encoding.UTF8.GetBytes("touchque-code-reply:" + requestId));
            var code = Encoding.UTF8.GetString(plain).Trim();
            return CodeRe().IsMatch(code) ? code : null;
        }
        catch (Exception e) when (e is CryptographicException or FormatException or ArgumentException)
        {
            return null;
        }
    }
}

/// <summary>
/// Ask the person to type back on the phone a sign-in code another service sent them.
/// <c>Key</c>: <see cref="CodeReply.NewKey"/>'s PublicKey. <c>Channel</c> (sms, whatsapp, email, app,
/// backup, other) and <c>Target</c> (the masked number or address, at most 40 characters) are shown on the phone.
/// </summary>
public sealed record LoginReplyRequest(string Key, string? Channel = null, string? Target = null)
{
    public string Kind { get; init; } = "code";
}

/// <summary>A request made with Reply, once the person typed it back: the ciphertext only (<see cref="CodeReply.Open"/>).</summary>
public sealed record LoginReply
{
    public string Ct { get; init; } = "";
    public string? At { get; init; }
}
