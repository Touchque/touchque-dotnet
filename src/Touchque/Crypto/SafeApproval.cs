using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Touchque;

/// <summary>
/// A Safe transaction: the fields the owners sign (Safe v1.3+ EIP-712 <c>SafeTx</c>). Integers are decimal
/// strings (null = 0); <c>Data</c> is 0x hex (null = <c>0x</c>); <c>GasToken</c> and <c>RefundReceiver</c>
/// default to the zero address.
/// </summary>
public sealed record SafeTxCall
{
    public string To { get; init; } = "";
    public string? Value { get; init; }
    public string? Data { get; init; }
    /// <summary>0 call, 1 delegatecall.</summary>
    public int Operation { get; init; }
    public string? SafeTxGas { get; init; }
    public string? BaseGas { get; init; }
    public string? GasPrice { get; init; }
    public string? GasToken { get; init; }
    public string? RefundReceiver { get; init; }
    public string Nonce { get; init; } = "";
}

/// <summary>Where the transaction runs: what the approval hashes cover. <c>Guard</c> is the TouchqueSafeGuard on the Safe.</summary>
public record SafeTxTarget
{
    /// <summary>A decimal string.</summary>
    public string ChainId { get; init; } = "";
    public string Safe { get; init; } = "";
    public string Guard { get; init; } = "";
    public SafeTxCall Tx { get; init; } = new();
}

/// <summary>One row the phone showed, in order.</summary>
public sealed record SafeDisplayRow(string Label, string Value);

/// <summary>Narrows what <see cref="SafeApproval.Verify"/> accepts.</summary>
public sealed record VerifySafeApprovalOptions
{
    /// <summary>
    /// The purpose you act on: <c>approve</c> (the default) or <c>schedule</c>. Without it only an ordinary approval
    /// is accepted; an approval to schedule a governance change covers no Safe nonce or gas fields, so name
    /// <c>schedule</c> to accept one.
    /// </summary>
    public string? Purpose { get; init; }
    /// <summary>The approver's index in the guard: the approval must name it.</summary>
    public int? ApproverIndex { get; init; }
    /// <summary>The digest of the rows the phone must have shown (from your own decoding).</summary>
    public string? DisplayDigest { get; init; }
    /// <summary>Or the rows themselves; their digest is compared.</summary>
    public IReadOnlyList<SafeDisplayRow>? Rows { get; init; }
    /// <summary>The time to check the expiry against (default: now).</summary>
    public DateTimeOffset? Now { get; init; }
}

/// <summary>
/// <see cref="SafeApproval.Verify"/>'s verdict. <c>Reason</c> is null when valid, else <c>approval_malformed</c>,
/// <c>public_key_invalid</c>, <c>approver_index_mismatch</c>, <c>approval_expired</c>, <c>rows_differ</c>,
/// <c>high_s</c> or <c>signature_invalid</c>. <c>ExpiresAt</c> is Unix seconds.
/// </summary>
public sealed record SafeApprovalVerification(
    bool Valid, string? Reason, string? Purpose, int? ApproverIndex, ulong? ExpiresAt, string? DisplayDigest, string SafeTxHash, string GovernanceHash);

/// <summary>
/// Safe Guard approvals, checked without trusting Touchque. The approver's phone decodes the raw Safe
/// transaction itself and signs, with a P-256 key only its biometrics unlock, a 105-byte approval that
/// TouchqueSafeGuard checks on chain: <c>index (1) | expiresAt (8) | displayDigest (32) | r (32) | s (32)</c>,
/// over the SHA-256 of the 149-byte message <c>"TQG1" | purpose (1) | chainId (32) | guard (20) | Safe (20) |
/// subject (32) | expiresAt (8) | displayDigest (32)</c>, where subject is the Safe transaction hash (EIP-712,
/// purpose 1 <c>approve</c>) or, for a change the guard schedules, the governance hash (purpose 2
/// <c>schedule</c>). <see cref="Verify"/> makes the guard's check off chain: both hashes are computed here from
/// the raw fields, so a co-signer (or your own server) refuses an approval of anything else, whoever relayed it.
/// </summary>
public static partial class SafeApproval
{
    private static readonly byte[] Magic = "TQG1"u8.ToArray();
    // The guard (MAX_APPROVAL_TTL) refuses an approval valid for longer than a day.
    private const ulong MaxApprovalTtl = 86400;
    // OpenZeppelin P256 (the guard) refuses s above N/2.
    private static readonly BigInteger HalfN = BigInteger.Parse("07fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", NumberStyles.HexNumber);
    private static readonly BigInteger P = BigInteger.Parse("0ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", NumberStyles.HexNumber);
    private static readonly BigInteger B = BigInteger.Parse("05ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", NumberStyles.HexNumber);
    private static readonly BigInteger MaxUint256 = (BigInteger.One << 256) - 1;
    private static readonly BigInteger MaxUint64 = ulong.MaxValue;
    private const string ZeroAddress = "0x0000000000000000000000000000000000000000";

    // Keccak-256 constants first: the type hashes below are computed with them.
    private static readonly ulong[] RoundConstants =
    [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];

    // Rotation of lane x + 5y.
    private static readonly int[] Rotations = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

    private static readonly byte[] DomainTypeHash = Keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"u8.ToArray());
    private static readonly byte[] SafeTxTypeHash = Keccak256(Encoding.ASCII.GetBytes(
        "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"));
    // The guard contract and the phone hash this exact type string, so its spelling never changes.
    private static readonly byte[] GovernanceTypeHash = Keccak256(Encoding.ASCII.GetBytes(
        "TouchQueGovernance(uint256 chainId,address safe,address to,uint256 value,bytes32 dataHash,uint8 operation)"));
    private static readonly byte[] ScheduleSelector = Keccak256("schedule(address,bytes32,bytes)"u8.ToArray())[..4];

    [GeneratedRegex("^0x[0-9a-fA-F]{40}$")]
    private static partial Regex AddressRe();

    [GeneratedRegex("^0x([0-9a-fA-F]{2})*$")]
    private static partial Regex HexRe();

    [GeneratedRegex("^(0|[1-9][0-9]*)$")]
    private static partial Regex DecimalRe();

    [GeneratedRegex("^(0x)?[0-9a-fA-F]{210}$")]
    private static partial Regex ApprovalRe();

    [GeneratedRegex("^[0-9a-fA-F]{128}$")]
    private static partial Regex KeyRe();

    /// <summary>The Safe transaction hash (EIP-712, domain = chainId + the Safe): what the owners sign and an ordinary approval covers.</summary>
    public static string SafeTxHash(SafeTxTarget target)
    {
        var t = Parse(target);
        var domain = Keccak256([.. DomainTypeHash, .. t.ChainId, .. t.Safe]);
        var structHash = Keccak256([
            .. SafeTxTypeHash, .. t.To, .. t.Value, .. Keccak256(t.Data), .. Word(t.Operation), .. t.SafeTxGas, .. t.BaseGas,
            .. t.GasPrice, .. t.GasToken, .. t.RefundReceiver, .. t.Nonce,
        ]);
        return Hex(Keccak256([0x19, 0x01, .. domain, .. structHash]));
    }

    /// <summary>What the guard schedules a governance change under: the change itself, without the nonce or gas fields.</summary>
    public static string GovernanceHash(SafeTxTarget target)
    {
        var t = Parse(target);
        return Hex(Keccak256([.. GovernanceTypeHash, .. t.ChainId, .. t.Safe, .. t.To, .. t.Value, .. Keccak256(t.Data), .. Word(t.Operation)]));
    }

    /// <summary>The 149-byte message the phone signs (its SHA-256 is what the guard verifies), as 0x hex.</summary>
    /// <param name="purpose"><c>approve</c> or <c>schedule</c>.</param>
    /// <param name="chainId">A decimal string.</param>
    /// <param name="expiresAt">Unix seconds.</param>
    public static string Message(string purpose, string chainId, string guard, string safe, string subject, ulong expiresAt, string displayDigest)
    {
        byte code = purpose switch
        {
            "approve" => 1,
            "schedule" => 2,
            _ => throw new TouchqueConfigException("SafeApproval: purpose is 'approve' or 'schedule'."),
        };
        var expires = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(expires, expiresAt);
        return Hex([
            .. Magic, code, .. Uint(chainId, "chainId", MaxUint64), .. Address(guard, "guard")[12..], .. Address(safe, "safe")[12..],
            .. Bytes(subject, "subject", 32), .. expires, .. Bytes(displayDigest, "displayDigest", 32),
        ]);
    }

    /// <summary>SHA-256 of the rows as "label\x1Fvalue" joined by "\x1E" (UTF-8), as 0x hex: the digest an approval carries.</summary>
    public static string DisplayDigest(IEnumerable<SafeDisplayRow> rows) =>
        Hex(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\u001E', rows.Select(r => r.Label + '\u001F' + r.Value)))));

    /// <summary>
    /// Checks a phone's Safe Guard approval the way TouchqueSafeGuard does, without trusting the server that
    /// relayed it: the Safe and governance hashes come from <paramref name="target"/>, the key from the guard's
    /// approver list on chain (<c>x || y</c>, 128 hex characters). Throws only when the target is not a Safe
    /// transaction; a refused approval is a verdict. Without <see cref="VerifySafeApprovalOptions.Purpose"/> only
    /// purpose <c>approve</c> is checked: pass <c>schedule</c> to accept an approval for a governance change.
    /// <code>
    /// var status = await tq.SafeGuard.StatusAsync(requestId);
    /// var check = SafeApproval.Verify(myTx, status.SafeTx!.Approval!, approverKeyFromChain, new() { ApproverIndex = 0 });
    /// if (!check.Valid) throw new InvalidOperationException($"approval refused: {check.Reason}");
    /// </code>
    /// </summary>
    public static SafeApprovalVerification Verify(SafeTxTarget target, string approval, string publicKey, VerifySafeApprovalOptions? options = null)
    {
        options ??= new VerifySafeApprovalOptions();
        var t = Parse(target);
        var safeTxHash = SafeTxHash(target);
        var governanceHash = GovernanceHash(target);
        int? index = null;
        ulong? expiresAt = null;
        string? digest = null;
        SafeApprovalVerification Refuse(string reason) => new(false, reason, null, index, expiresAt, digest, safeTxHash, governanceHash);

        if (approval is null || !ApprovalRe().IsMatch(approval)) return Refuse("approval_malformed");
        var b = Convert.FromHexString(Strip0x(approval));
        index = b[0];
        expiresAt = BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(1, 8));
        digest = Hex(b[9..41]);
        using var key = PublicKey(publicKey);
        if (key is null) return Refuse("public_key_invalid");
        if (options.ApproverIndex is { } want && want != index) return Refuse("approver_index_mismatch");
        var now = (options.Now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        if (now < 0 || expiresAt < (ulong)now || expiresAt > (ulong)now + MaxApprovalTtl) return Refuse("approval_expired");
        var expected = options.DisplayDigest ?? (options.Rows is { } rows ? DisplayDigest(rows) : null);
        if (expected is not null && "0x" + Strip0x(expected.ToLowerInvariant()) != digest) return Refuse("rows_differ");
        if (new BigInteger(b.AsSpan(73, 32), isUnsigned: true, isBigEndian: true) > HalfN) return Refuse("high_s");

        var chainId = new BigInteger(t.ChainId, isUnsigned: true, isBigEndian: true).ToString(CultureInfo.InvariantCulture);
        // Never both: a schedule approval is not permission to execute, so it must be asked for by name.
        var purpose = options.Purpose ?? "approve";
        var message = Message(purpose, chainId, Hex(t.Guard[12..]), Hex(t.Safe[12..]), purpose == "approve" ? safeTxHash : governanceHash, expiresAt.Value, digest);
        if (key.VerifyData(Convert.FromHexString(message[2..]), b.AsSpan(41, 64), HashAlgorithmName.SHA256))
        {
            return new SafeApprovalVerification(true, null, purpose, index, expiresAt, digest, safeTxHash, governanceHash);
        }
        return Refuse("signature_invalid");
    }

    /// <summary>
    /// The owners' Safe signatures with the approvals appended (approvals by index | count | "TQG1"): the
    /// <c>signatures</c> argument of <c>execTransaction</c> for an ordinary transaction.
    /// </summary>
    public static string WithApprovals(string ownerSignatures, IEnumerable<string> approvals)
    {
        var items = Approvals(approvals);
        return Hex([.. Bytes(ownerSignatures, "ownerSignatures", null), .. items.SelectMany(a => a), (byte)items.Count, .. Magic]);
    }

    /// <summary>The call data of <c>guard.schedule(safe, governanceHash, approvals)</c>, which starts a governance change's waiting time.</summary>
    public static string ScheduleCall(string safe, string governanceHash, IEnumerable<string> approvals)
    {
        byte[] joined = [.. Approvals(approvals).SelectMany(a => a)];
        return Hex([
            .. ScheduleSelector, .. Address(safe, "safe"), .. Bytes(governanceHash, "governanceHash", 32), .. Word(96),
            .. Uint(joined.Length.ToString(CultureInfo.InvariantCulture), "length", MaxUint256), .. joined, .. new byte[(32 - joined.Length % 32) % 32],
        ]);
    }

    // ── Keccak-256 (the Ethereum hash: Keccak padding, not SHA3-256) ──

    private static void KeccakF(ulong[] a)
    {
        var c = new ulong[5];
        var b = new ulong[25];
        foreach (var rc in RoundConstants)
        {
            for (var x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (var x = 0; x < 5; x++)
            {
                var d = c[(x + 4) % 5] ^ BitOperations.RotateLeft(c[(x + 1) % 5], 1);
                for (var y = 0; y < 25; y += 5) a[x + y] ^= d;
            }
            for (var x = 0; x < 5; x++)
            {
                for (var y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = BitOperations.RotateLeft(a[x + 5 * y], Rotations[x + 5 * y]);
            }
            for (var y = 0; y < 25; y += 5)
            {
                for (var x = 0; x < 5; x++) a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]);
            }
            a[0] ^= rc;
        }
    }

    private static byte[] Keccak256(byte[] data)
    {
        const int rate = 136;
        var padded = new byte[data.Length / rate * rate + rate];
        data.CopyTo(padded, 0);
        padded[data.Length] ^= 0x01;
        padded[^1] ^= 0x80;
        var a = new ulong[25];
        for (var off = 0; off < padded.Length; off += rate)
        {
            for (var k = 0; k < rate / 8; k++) a[k] ^= BinaryPrimitives.ReadUInt64LittleEndian(padded.AsSpan(off + 8 * k, 8));
            KeccakF(a);
        }
        var out32 = new byte[32];
        for (var k = 0; k < 4; k++) BinaryPrimitives.WriteUInt64LittleEndian(out32.AsSpan(8 * k, 8), a[k]);
        return out32;
    }

    // ── Field parsing: the partner's own data, so a wrong field throws ──

    private sealed record Fields(
        byte[] ChainId, byte[] Safe, byte[] Guard, byte[] To, byte[] Value, byte[] Data, byte Operation, byte[] SafeTxGas, byte[] BaseGas,
        byte[] GasPrice, byte[] GasToken, byte[] RefundReceiver, byte[] Nonce);

    private static Fields Parse(SafeTxTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        var tx = target.Tx ?? throw new TouchqueConfigException("SafeApproval: the target needs Tx.");
        if (tx.Operation is not (0 or 1)) throw new TouchqueConfigException("SafeApproval: Tx.Operation must be 0 (call) or 1 (delegatecall).");
        if (string.IsNullOrEmpty(tx.Nonce)) throw new TouchqueConfigException("SafeApproval: Tx.Nonce is required.");
        return new Fields(
            Uint(target.ChainId, "ChainId", MaxUint64), Address(target.Safe, "Safe"), Address(target.Guard, "Guard"), Address(tx.To, "Tx.To"),
            Uint(tx.Value ?? "0", "Tx.Value", MaxUint256), Bytes(tx.Data ?? "0x", "Tx.Data", null), (byte)tx.Operation,
            Uint(tx.SafeTxGas ?? "0", "Tx.SafeTxGas", MaxUint256), Uint(tx.BaseGas ?? "0", "Tx.BaseGas", MaxUint256),
            Uint(tx.GasPrice ?? "0", "Tx.GasPrice", MaxUint256), Address(tx.GasToken ?? ZeroAddress, "Tx.GasToken"),
            Address(tx.RefundReceiver ?? ZeroAddress, "Tx.RefundReceiver"), Uint(tx.Nonce, "Tx.Nonce", MaxUint256));
    }

    private static byte[] Uint(string? value, string field, BigInteger max)
    {
        var v = value is not null && DecimalRe().IsMatch(value) ? BigInteger.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture) : BigInteger.MinusOne;
        if (v.Sign < 0 || v > max)
            throw new TouchqueConfigException($"SafeApproval: {field} must be a non-negative integer as a decimal string.");
        var raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        var word = new byte[32];
        if (!v.IsZero) raw.CopyTo(word, 32 - raw.Length);
        return word;
    }

    private static byte[] Word(byte value)
    {
        var word = new byte[32];
        word[31] = value;
        return word;
    }

    private static byte[] Address(string? value, string field)
    {
        if (value is null || !AddressRe().IsMatch(value)) throw new TouchqueConfigException($"SafeApproval: {field} must be an address (0x and 40 hex characters).");
        return [.. new byte[12], .. Convert.FromHexString(value[2..])];
    }

    private static byte[] Bytes(string? value, string field, int? size)
    {
        if (value is null || !HexRe().IsMatch(value) || (size is { } n && value.Length != 2 + 2 * n))
            throw new TouchqueConfigException($"SafeApproval: {field} must be 0x-prefixed hex{(size is { } m ? $" of {m} bytes" : "")}.");
        return Convert.FromHexString(value[2..]);
    }

    private static List<byte[]> Approvals(IEnumerable<string> approvals)
    {
        var items = approvals.Select((a, i) => Bytes(a.StartsWith("0x", StringComparison.Ordinal) ? a : "0x" + a, $"approvals[{i}]", 105)).ToList();
        if (items.Count is < 1 or > 255) throw new TouchqueConfigException("SafeApproval: pass 1 to 255 approvals.");
        return [.. items.OrderBy(a => a[0])];
    }

    private static ECDsa? PublicKey(string? key)
    {
        var xy = Strip0x(key ?? "");
        if (!KeyRe().IsMatch(xy)) return null;
        var raw = Convert.FromHexString(xy);
        var x = new BigInteger(raw.AsSpan(0, 32), isUnsigned: true, isBigEndian: true);
        var y = new BigInteger(raw.AsSpan(32, 32), isUnsigned: true, isBigEndian: true);
        // On the curve: y^2 = x^3 - 3x + b (mod p).
        if (x >= P || y >= P || BigInteger.ModPow(y, 2, P) != ((BigInteger.ModPow(x, 3, P) - 3 * x + B) % P + P) % P) return null;
        try
        {
            return ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = raw[..32], Y = raw[32..] } });
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static string Strip0x(string s) => s.StartsWith("0x", StringComparison.Ordinal) ? s[2..] : s;

    private static string Hex(byte[] b) => "0x" + Convert.ToHexString(b).ToLowerInvariant();
}
