using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using TouchQue.Internal;

namespace TouchQue;

/// <summary>A new key pair for an AI agent: register <see cref="PublicJwk"/>; keep <see cref="PrivateJwk"/> where the agent runs.</summary>
public sealed record AgentKeyPair(JsonObject PrivateJwk, JsonObject PublicJwk);

/// <summary>Key helpers for AI agents (<see cref="TouchQueAgent"/>): new key pairs and RFC 7638 thumbprints.</summary>
public static class AgentKeys
{
    /// <summary>
    /// A new key pair: ES256 (P-256, default) or EdDSA (Ed25519). The kid is the
    /// RFC 7638 thumbprint.
    /// </summary>
    public static AgentKeyPair Generate(string alg = "ES256")
    {
        JsonObject pub;
        string d;
        if (alg == "EdDSA")
        {
            var priv = new Ed25519PrivateKeyParameters(new SecureRandom());
            pub = new JsonObject { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = Base64Url.Encode(priv.GeneratePublicKey().GetEncoded()) };
            d = Base64Url.Encode(priv.GetEncoded());
        }
        else if (alg == "ES256")
        {
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var p = ec.ExportParameters(true);
            pub = new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Base64Url.Encode(p.Q.X!), ["y"] = Base64Url.Encode(p.Q.Y!) };
            d = Base64Url.Encode(p.D!);
        }
        else
        {
            throw new TouchQueConfigException("alg must be ES256 or EdDSA");
        }
        var kid = Thumbprint(pub);
        var privateJwk = (JsonObject)pub.DeepClone();
        privateJwk["d"] = d;
        privateJwk["kid"] = kid;
        privateJwk["alg"] = alg;
        var publicJwk = (JsonObject)pub.DeepClone();
        publicJwk["kid"] = kid;
        publicJwk["alg"] = alg;
        return new AgentKeyPair(privateJwk, publicJwk);
    }

    /// <summary>RFC 7638 thumbprint of a P-256 or Ed25519 public key (the default kid).</summary>
    public static string Thumbprint(JsonObject jwk)
    {
        var kty = Json.Str(jwk, "kty") ?? "";
        var canonical = kty == "EC"
            ? "{\"crv\":" + Json.JsString(Json.Str(jwk, "crv") ?? "") + ",\"kty\":\"EC\",\"x\":" + Json.JsString(Json.Str(jwk, "x") ?? "") + ",\"y\":" + Json.JsString(Json.Str(jwk, "y") ?? "") + "}"
            : "{\"crv\":" + Json.JsString(Json.Str(jwk, "crv") ?? "") + ",\"kty\":" + Json.JsString(kty) + ",\"x\":" + Json.JsString(Json.Str(jwk, "x") ?? "") + "}";
        return Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>base64url SHA-256 of an access token, as a DPoP proof carries it (<c>ath</c>).</summary>
    public static string AccessTokenHash(string accessToken) => Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(accessToken)));
}

/// <summary>An ES256 or EdDSA private key that signs JWS (agent assertions, DPoP proofs).</summary>
internal sealed class SigningKey : IDisposable
{
    private readonly ECDsa? _ec;
    private readonly Ed25519PrivateKeyParameters? _ed;

    private SigningKey(ECDsa ec, JsonObject publicJwk)
    {
        _ec = ec;
        Alg = "ES256";
        PublicJwk = publicJwk;
    }

    private SigningKey(Ed25519PrivateKeyParameters ed, JsonObject publicJwk)
    {
        _ed = ed;
        Alg = "EdDSA";
        PublicJwk = publicJwk;
    }

    public string Alg { get; }

    /// <summary>kty, crv, x (and y): the public key only.</summary>
    public JsonObject PublicJwk { get; }

    public static SigningKey NewEs256()
    {
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ec.ExportParameters(false);
        return new SigningKey(ec, new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Base64Url.Encode(p.Q.X!), ["y"] = Base64Url.Encode(p.Q.Y!) });
    }

    /// <summary>A JWK (JsonObject or its JSON text) or an EC P-256 PEM.</summary>
    public static SigningKey Load(object key, string who)
    {
        JsonObject? jwk = key switch
        {
            JsonObject o => o,
            string s when s.TrimStart().StartsWith('{') => Json.Parse(s) as JsonObject,
            _ => null,
        };
        if (jwk is not null) return FromJwk(jwk);
        if (key is string pem) return FromPem(pem, who);
        throw new TouchQueConfigException($"{who}: the private key must be a JWK (JsonObject or JSON) or an EC PEM");
    }

    private static SigningKey FromJwk(JsonObject jwk)
    {
        var dText = Json.Str(jwk, "d");
        if (string.IsNullOrEmpty(dText)) throw new TouchQueConfigException("The agent key must be the PRIVATE key (it has no d)");
        var d = Base64Url.Decode(dText);
        var kty = Json.Str(jwk, "kty");
        var crv = Json.Str(jwk, "crv");
        if (kty == "OKP" && crv == "Ed25519" && d.Length == 32)
        {
            var ed = new Ed25519PrivateKeyParameters(d, 0);
            return new SigningKey(ed, new JsonObject { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = Base64Url.Encode(ed.GeneratePublicKey().GetEncoded()) });
        }
        var x = Json.Str(jwk, "x");
        var y = Json.Str(jwk, "y");
        if (kty == "EC" && crv == "P-256" && x is not null && y is not null)
        {
            var ec = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = Pad32(d),
                Q = new ECPoint { X = Pad32(Base64Url.Decode(x)), Y = Pad32(Base64Url.Decode(y)) },
            });
            return new SigningKey(ec, new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = x, ["y"] = y });
        }
        throw new TouchQueConfigException("The agent key must be EC P-256 or Ed25519");
    }

    private static SigningKey FromPem(string pem, string who)
    {
        var ec = ECDsa.Create();
        try
        {
            ec.ImportFromPem(pem);
        }
        catch (Exception e) when (e is ArgumentException or CryptographicException)
        {
            ec.Dispose();
            throw new TouchQueConfigException($"{who}: the private key must be a JWK (JsonObject or JSON) or an EC P-256 PEM");
        }
        var p = ec.ExportParameters(false);
        var oid = p.Curve.Oid;
        var isP256 = oid?.Value == "1.2.840.10045.3.1.7" || oid?.FriendlyName is "nistP256" or "ECDSA_P256" or "prime256v1" or "secp256r1";
        if (!isP256 || p.Q.X?.Length != 32)
        {
            ec.Dispose();
            throw new TouchQueConfigException("An EC agent key must be on P-256");
        }
        return new SigningKey(ec, new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Base64Url.Encode(p.Q.X!), ["y"] = Base64Url.Encode(p.Q.Y!) });
    }

    internal static byte[] Pad32(byte[] b)
    {
        if (b.Length >= 32) return b;
        var o = new byte[32];
        Buffer.BlockCopy(b, 0, o, 32 - b.Length, b.Length);
        return o;
    }

    public byte[] Sign(byte[] input)
    {
        if (_ec is not null) return _ec.SignData(input, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var signer = new Ed25519Signer();
        signer.Init(true, _ed);
        signer.BlockUpdate(input, 0, input.Length);
        return signer.GenerateSignature();
    }

    /// <summary>A compact JWS: <c>alg</c> is added to the header.</summary>
    public string Jws(JsonObject header, JsonObject payload)
    {
        header["alg"] = Alg;
        var input = Base64Url.Encode(Json.Serialize(header)) + "." + Base64Url.Encode(Json.Serialize(payload));
        return input + "." + Base64Url.Encode(Sign(Encoding.ASCII.GetBytes(input)));
    }

    public void Dispose() => _ec?.Dispose();
}

/// <summary>JWS signature checks for the algorithms TouchQue uses.</summary>
internal static class JwsVerify
{
    public static bool Verify(string alg, JsonObject jwk, byte[] input, byte[] signature)
    {
        try
        {
            var kty = Json.Str(jwk, "kty");
            if (alg == "ES256" && kty == "EC" && Json.Str(jwk, "crv") == "P-256")
            {
                if (signature.Length != 64) return false;
                using var ec = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = SigningKey.Pad32(Base64Url.Decode(Json.Str(jwk, "x") ?? "")), Y = SigningKey.Pad32(Base64Url.Decode(Json.Str(jwk, "y") ?? "")) },
                });
                return ec.VerifyData(input, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            if (alg == "RS256" && kty == "RSA")
            {
                using var rsa = RSA.Create(new RSAParameters
                {
                    Modulus = Base64Url.Decode(Json.Str(jwk, "n") ?? ""),
                    Exponent = Base64Url.Decode(Json.Str(jwk, "e") ?? ""),
                });
                return rsa.VerifyData(input, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            if (alg == "EdDSA" && kty == "OKP" && Json.Str(jwk, "crv") == "Ed25519")
            {
                if (signature.Length != 64) return false;
                var pub = Base64Url.Decode(Json.Str(jwk, "x") ?? "");
                if (pub.Length != 32) return false;
                var verifier = new Ed25519Signer();
                verifier.Init(false, new Ed25519PublicKeyParameters(pub, 0));
                verifier.BlockUpdate(input, 0, input.Length);
                return verifier.VerifySignature(signature);
            }
        }
        catch (Exception e) when (e is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
        return false;
    }

    /// <summary>Header and claims of a compact JWS, or null when it is not one.</summary>
    public static (JsonObject Header, JsonObject Claims, byte[] Input, byte[] Signature)? Split(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) return null;
        try
        {
            var header = Json.Parse(Encoding.UTF8.GetString(Base64Url.Decode(parts[0]))) as JsonObject;
            var claims = Json.Parse(Encoding.UTF8.GetString(Base64Url.Decode(parts[1]))) as JsonObject;
            if (header is null || claims is null) return null;
            return (header, claims, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Base64Url.Decode(parts[2]));
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
