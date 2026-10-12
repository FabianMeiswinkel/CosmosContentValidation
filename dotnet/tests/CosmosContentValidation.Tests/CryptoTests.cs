using System.Buffers;
using System.Formats.Asn1;
using System.Security.Cryptography;
using CosmosContentValidation.Sample.Providers;
using Xunit;

namespace CosmosContentValidation.Tests;

public sealed class CryptoTests
{
    [Fact]
    public void HasherHonorsSegmentOffsetsEmptySegmentsAndLogicalLength()
    {
        byte[] firstBytes = [0xEE, (byte)'a'];
        byte[] lastBytes = [(byte)'b', (byte)'c', 0xFF];
        Segment first = new(firstBytes);
        Segment last = first.Append(ReadOnlyMemory<byte>.Empty).Append(lastBytes);
        ReadOnlySequence<byte> sequence = new(first, 1, last, 2);
        IContentHasher hasher = new UnsafeSha256ContentHasher();

        byte[] digest = hasher.ComputeHash(sequence);

        Assert.Equal("SHA-256", hasher.AlgorithmId);
        Assert.Equal(32, hasher.HashSizeInBytes);
        Assert.Equal(32, digest.Length);
        Assert.Equal(Convert.FromHexString("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"), digest);
        Assert.Equal(new byte[] { 0xEE, (byte)'a' }, firstBytes);
        Assert.Equal(new byte[] { (byte)'b', (byte)'c', 0xFF }, lastBytes);

        // The returned digest is independent of the borrowed storage and later calls.
        firstBytes[1] = (byte)'z';
        byte[] changed = hasher.ComputeHash(sequence);
        Assert.Equal(SHA256.HashData("zbc"u8), changed);
        Assert.Equal(SHA256.HashData("abc"u8), digest);
        Assert.NotSame(digest, changed);
    }

    [Fact]
    public void HasherHandlesEmptyAndSingleSegmentInputWithFreshResults()
    {
        UnsafeSha256ContentHasher hasher = new();
        byte[] empty = hasher.ComputeHash(ReadOnlySequence<byte>.Empty);
        byte[] otherEmpty = hasher.ComputeHash(ReadOnlySequence<byte>.Empty);
        Assert.Equal(SHA256.HashData(Array.Empty<byte>()), empty);
        Assert.Equal(empty, otherEmpty);
        Assert.NotSame(empty, otherEmpty);

        byte[] storage = [0xEE, 1, 2, 3, 0xFF];
        ReadOnlySequence<byte> sequence = new(storage.AsMemory(1, 3));
        Assert.Equal(SHA256.HashData(storage.AsSpan(1, 3)), hasher.ComputeHash(sequence));
        empty[0] ^= 0xFF;
        Assert.Equal(SHA256.HashData(Array.Empty<byte>()), otherEmpty);
    }

    [Fact]
    public void HasherBorrowsPooledSegmentsWithoutTakingOwnership()
    {
        PooledJsonBufferPool pool = new();
        UnsafeSha256ContentHasher hasher = new();
        byte[] payload = RandomNumberGenerator.GetBytes(100_000);
        byte[] digest;
        using (var stream = pool.Rent())
        {
            stream.Write(payload);
            stream.Position = 17;
            digest = hasher.ComputeHash(stream.GetReadOnlySequence());
            Assert.Equal(17L, stream.Position);
            Assert.True(stream.CanRead);
            Assert.Equal(SHA256.HashData(payload), digest);
        }

        Assert.Equal(0L, pool.InUseBytes);
        Assert.Equal(SHA256.HashData(payload), digest);
    }

    [Fact]
    public async Task HasherSupportsIndependentConcurrentCalls()
    {
        IContentHasher hasher = new UnsafeSha256ContentHasher();
        await Task.WhenAll(Enumerable.Range(0, 32).Select(index => Task.Run(() =>
        {
            byte[] payload = Enumerable.Repeat((byte)index, 1024 + index).ToArray();
            Segment first = new(payload.AsMemory(0, 13));
            Segment last = first.Append(payload.AsMemory(13));
            ReadOnlySequence<byte> sequence = new(first, 0, last, last.Memory.Length);
            Assert.Equal(SHA256.HashData(payload), hasher.ComputeHash(sequence));
        })));
    }

    [Fact]
    public void ProvidersInteroperateWithIndependentPrehashedP1363Crypto()
    {
        using ECDsa independent = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using UnsafeEcdsaContentSigner signer = new("writer-1", independent.ExportPkcs8PrivateKeyPem());
        using UnsafeEcdsaContentVerifier verifier = new("writer-1", independent.ExportSubjectPublicKeyInfoPem());
        byte[] hash = SHA256.HashData("content to authenticate"u8);
        byte[] originalHash = (byte[])hash.Clone();

        Assert.Equal("writer-1", signer.KeyId);
        Assert.Equal("writer-1", verifier.KeyId);
        Assert.Equal("ECDSA-P256-SHA256-P1363", signer.AlgorithmId);
        Assert.Equal("ECDSA-P256-SHA256-P1363", verifier.AlgorithmId);

        byte[] signature = signer.SignHash(hash);
        byte[] originalSignature = (byte[])signature.Clone();
        Assert.Equal(64, signature.Length);
        Assert.True(verifier.VerifyHash(hash, signature));
        Assert.True(independent.VerifyHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Assert.False(independent.VerifyData(hash, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        byte[] independentSignature = independent.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.True(verifier.VerifyHash(hash, independentSignature));
        byte[] doubleHashed = independent.SignData(hash, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.False(verifier.VerifyHash(hash, doubleHashed));
        byte[] derSignature = independent.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
        Assert.False(verifier.VerifyHash(hash, derSignature));

        Assert.Equal(originalHash, hash);
        Assert.Equal(originalSignature, signature);
        byte[] laterSignature = signer.SignHash(hash);
        Assert.NotSame(signature, laterSignature);
        Array.Clear(laterSignature);
        Assert.True(verifier.VerifyHash(hash, signature));
    }

    [Fact]
    public void ProvidersOwnImportedKeysAndAcceptSurroundingWhitespace()
    {
        // The generating ECDsa is already disposed by CreateKeyPair.
        var pair = CreateKeyPair();
        using UnsafeEcdsaContentSigner signer = new("key", "\r\n\t " + pair.PrivateKeyPem + " \n");
        using UnsafeEcdsaContentVerifier verifier = new("key", "\n " + pair.PublicKeyPem + "\r\n\t");
        byte[] hash = new byte[32];
        Assert.True(verifier.VerifyHash(hash, signer.SignHash(hash)));
    }

    [Fact]
    public void VerificationRejectsWrongKeyDigestAndSignature()
    {
        var pair = CreateKeyPair();
        var other = CreateKeyPair();
        using UnsafeEcdsaContentSigner signer = new("key", pair.PrivateKeyPem);
        using UnsafeEcdsaContentVerifier verifier = new("key", pair.PublicKeyPem);
        using UnsafeEcdsaContentVerifier wrongKey = new("key", other.PublicKeyPem);
        byte[] hash = SHA256.HashData("document"u8);
        byte[] signature = signer.SignHash(hash);
        Assert.False(wrongKey.VerifyHash(hash, signature));
        byte[] changedHash = (byte[])hash.Clone();
        changedHash[0] ^= 1;
        Assert.False(verifier.VerifyHash(changedHash, signature));
        byte[] changedSignature = (byte[])signature.Clone();
        changedSignature[^1] ^= 1;
        Assert.False(verifier.VerifyHash(hash, changedSignature));
        Assert.False(verifier.VerifyHash(hash, new byte[64]));
        Assert.False(verifier.VerifyHash(hash, Enumerable.Repeat((byte)0xFF, 64).ToArray()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(48)]
    [InlineData(64)]
    public void DigestMustBeExactly32Bytes(int length)
    {
        var pair = CreateKeyPair();
        using UnsafeEcdsaContentSigner signer = new("key", pair.PrivateKeyPem);
        using UnsafeEcdsaContentVerifier verifier = new("key", pair.PublicKeyPem);
        byte[] hash = new byte[length];
        Assert.Throws<ArgumentException>("hash", () => signer.SignHash(hash));
        Assert.Throws<ArgumentException>("hash", () => verifier.VerifyHash(hash, new byte[64]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(65)]
    [InlineData(72)]
    [InlineData(128)]
    public void NonP1363SignatureLengthsReturnFalse(int length)
    {
        var pair = CreateKeyPair();
        using UnsafeEcdsaContentVerifier verifier = new("key", pair.PublicKeyPem);
        Assert.False(verifier.VerifyHash(new byte[32], new byte[length]));
    }

    [Fact]
    public void ConstructorsRejectNullArguments()
    {
        var pair = CreateKeyPair();
        Assert.Throws<ArgumentNullException>("keyId", () => new UnsafeEcdsaContentSigner(null!, pair.PrivateKeyPem));
        Assert.Throws<ArgumentNullException>("keyId", () => new UnsafeEcdsaContentVerifier(null!, pair.PublicKeyPem));
        Assert.Throws<ArgumentNullException>("privateKeyPem", () => new UnsafeEcdsaContentSigner("key", null!));
        Assert.Throws<ArgumentNullException>("publicKeyPem", () => new UnsafeEcdsaContentVerifier("key", null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" \r\n\t")]
    public void ConstructorsRejectBlankKeyIdsAndPem(string blank)
    {
        var pair = CreateKeyPair();
        Assert.Throws<ArgumentException>("keyId", () => new UnsafeEcdsaContentSigner(blank, pair.PrivateKeyPem));
        Assert.Throws<ArgumentException>("keyId", () => new UnsafeEcdsaContentVerifier(blank, pair.PublicKeyPem));
        Assert.Throws<ArgumentException>("privateKeyPem", () => new UnsafeEcdsaContentSigner("key", blank));
        Assert.Throws<ArgumentException>("publicKeyPem", () => new UnsafeEcdsaContentVerifier("key", blank));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ImportRejectsMalformedAndAmbiguousPem(bool privateKey)
    {
        var pair = CreateKeyPair();
        string valid = privateKey ? pair.PrivateKeyPem : pair.PublicKeyPem;
        string label = privateKey ? "PRIVATE KEY" : "PUBLIC KEY";
        string malformed = $"-----BEGIN {label}-----\n%%%\n-----END {label}-----";
        string unrelated = PemEncoding.WriteString("UNRELATED", new byte[] { 1, 2, 3 });
        string[] invalid =
        [
            "not PEM",
            malformed,
            $"-----BEGIN {label}-----\nAAAA",
            valid + "\n" + valid,
            pair.PrivateKeyPem + "\n" + pair.PublicKeyPem,
            pair.PublicKeyPem + "\n" + pair.PrivateKeyPem,
            malformed + "\n" + valid,
            valid + "\n" + malformed,
            unrelated + "\n" + valid,
            valid + "\n" + unrelated,
            "unexpected prefix\n" + valid,
            valid + "\nunexpected suffix"
        ];

        foreach (string pem in invalid)
            AssertKeyRejected<ArgumentException>(privateKey, pem);
    }

    [Fact]
    public void ImportEnforcesPrivatePkcs8VersusPublicSpkiLabels()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string privatePem = key.ExportPkcs8PrivateKeyPem();
        string publicPem = key.ExportSubjectPublicKeyInfoPem();
        string sec1Pem = key.ExportECPrivateKeyPem();
        string password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        string encryptedPem = key.ExportEncryptedPkcs8PrivateKeyPem(password,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000));

        AssertKeyRejected<ArgumentException>(true, publicPem);
        AssertKeyRejected<ArgumentException>(true, sec1Pem);
        AssertKeyRejected<ArgumentException>(true, encryptedPem);
        AssertKeyRejected<ArgumentException>(false, privatePem);
        AssertKeyRejected<ArgumentException>(false, sec1Pem);
        AssertKeyRejected<ArgumentException>(false, encryptedPem);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ImportRejectsMalformedDerRelabeledKeysAndTrailingDer(bool privateKey)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string label = privateKey ? "PRIVATE KEY" : "PUBLIC KEY";
        byte[] valid = privateKey ? key.ExportPkcs8PrivateKey() : key.ExportSubjectPublicKeyInfo();
        byte[] wrongType = privateKey ? key.ExportSubjectPublicKeyInfo() : key.ExportPkcs8PrivateKey();
        try
        {
            AssertKeyRejected<CryptographicException>(privateKey, PemEncoding.WriteString(label, new byte[] { 0, 1, 2 }));
            AssertKeyRejected<CryptographicException>(privateKey, PemEncoding.WriteString(label, wrongType));
            byte[] trailing = [.. valid, 0];
            try
            {
                AssertKeyRejected<CryptographicException>(privateKey, PemEncoding.WriteString(label, trailing));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(trailing);
            }

            AssertKeyRejected<CryptographicException>(privateKey, PemEncoding.WriteString(label, valid.AsSpan(0, valid.Length - 1)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(valid);
            CryptographicOperations.ZeroMemory(wrongType);
        }
    }

    [Fact]
    public void ImportRejectsP384AndNonEcAlgorithms()
    {
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        AssertKeyRejected<CryptographicException>(true, p384.ExportPkcs8PrivateKeyPem());
        AssertKeyRejected<CryptographicException>(false, p384.ExportSubjectPublicKeyInfoPem());
        using RSA rsa = RSA.Create(2048);
        AssertKeyRejected<CryptographicException>(true, rsa.ExportPkcs8PrivateKeyPem());
        AssertKeyRejected<CryptographicException>(false, rsa.ExportSubjectPublicKeyInfoPem());
    }

    [Theory]
    [InlineData(true, "1.3.132.0.10")]
    [InlineData(false, "1.3.132.0.10")]
    [InlineData(true, "1.3.36.3.3.2.8.1.1.7")]
    [InlineData(false, "1.3.36.3.3.2.8.1.1.7")]
    [InlineData(true, null)]
    [InlineData(false, null)]
    public void ImportChecksEncodedCurveOidRatherThan256BitSize(bool privateKey, string? curveOid)
    {
        // Alter the AlgorithmIdentifier on an ephemeral 256-bit key. This needs
        // no OS support for secp256k1/brainpool, and must fail before native import.
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string pem = RewriteCurveParameters(key, privateKey, curveOid);
        CryptographicException exception = AssertKeyRejected<CryptographicException>(privateKey, pem);
        Assert.Contains("named NIST P-256", exception.Message);
    }

    [Fact]
    public void ResolverUsesCopiedOrdinalMappingsAndCallerOwnedProviders()
    {
        var pair = CreateKeyPair();
        using UnsafeEcdsaContentSigner signer = new("key", pair.PrivateKeyPem);
        using UnsafeEcdsaContentVerifier lower = new("key", pair.PublicKeyPem);
        using UnsafeEcdsaContentVerifier upper = new("KEY", pair.PublicKeyPem);
        using UnsafeEcdsaContentVerifier replacement = new("replacement", pair.PublicKeyPem);
        List<IContentVerifier> input = [lower, upper];
        IVerificationKeyResolver resolver = new UnsafeInMemoryVerificationKeyResolver(input);
        input[0] = replacement;
        input.Clear();

        Assert.Same(lower, resolver.Resolve("key"));
        Assert.Same(upper, resolver.Resolve("KEY"));
        Assert.Null(resolver.Resolve("Key"));
        Assert.Null(resolver.Resolve("replacement"));
        Assert.Null(resolver.Resolve("unknown"));
        Assert.Null(resolver.Resolve("https://example.invalid/never-fetch-this-key"));
        Assert.Null(resolver.Resolve(string.Empty));
        byte[] hash = SHA256.HashData("ownership"u8);
        byte[] signature = signer.SignHash(hash);
        Assert.True(resolver.Resolve("key")!.VerifyHash(hash, signature));

        // The resolver retains the same borrowed provider, not a cloned key.
        lower.Dispose();
        Assert.Same(lower, resolver.Resolve("key"));
        Assert.Throws<ObjectDisposedException>(() => resolver.Resolve("key")!.VerifyHash(hash, signature));
        Assert.True(upper.VerifyHash(hash, signature));
    }

    [Fact]
    public void ResolverSnapshotsKeyIdsEvenForMutableCustomProviders()
    {
        MutableVerifier provider = new("before");
        UnsafeInMemoryVerificationKeyResolver resolver = new(new[] { provider });
        provider.KeyId = "after";
        Assert.Same(provider, resolver.Resolve("before"));
        Assert.Null(resolver.Resolve("after"));
    }

    [Fact]
    public void ResolverRejectsDuplicatesNullAndInvalidProviders()
    {
        var pair = CreateKeyPair();
        using UnsafeEcdsaContentVerifier first = new("key", pair.PublicKeyPem);
        using UnsafeEcdsaContentVerifier second = new("key", pair.PublicKeyPem);
        Assert.Throws<ArgumentNullException>("verifiers", () => new UnsafeInMemoryVerificationKeyResolver(null!));
        Assert.Throws<ArgumentException>("verifiers", () => new UnsafeInMemoryVerificationKeyResolver(new IContentVerifier[] { null! }));
        Assert.Throws<ArgumentException>("verifiers", () => new UnsafeInMemoryVerificationKeyResolver(new[] { first, second }));
        Assert.Throws<ArgumentException>("verifiers", () => new UnsafeInMemoryVerificationKeyResolver(new[] { first, first }));
        Assert.Throws<ArgumentException>("verifiers", () => new UnsafeInMemoryVerificationKeyResolver(new[] { new MutableVerifier(" ") }));
        Assert.Throws<ArgumentNullException>("verifiers", () => new UnsafeInMemoryVerificationKeyResolver(new[] { new MutableVerifier(null!) }));

        UnsafeInMemoryVerificationKeyResolver empty = new(Array.Empty<IContentVerifier>());
        Assert.Null(empty.Resolve("key"));
        Assert.Throws<ArgumentNullException>("keyId", () => empty.Resolve(null!));

        // Even failed construction must not dispose the caller's provider.
        using UnsafeEcdsaContentSigner signer = new("key", pair.PrivateKeyPem);
        byte[] hash = new byte[32];
        Assert.True(first.VerifyHash(hash, signer.SignHash(hash)));
    }

    [Fact]
    public async Task SharedSignerVerifierAndResolverSupportConcurrentOperations()
    {
        var pair = CreateKeyPair();
        using UnsafeEcdsaContentSigner signer = new("key", pair.PrivateKeyPem);
        using UnsafeEcdsaContentVerifier verifier = new("key", pair.PublicKeyPem);
        UnsafeInMemoryVerificationKeyResolver resolver = new(new[] { verifier });
        await Task.WhenAll(Enumerable.Range(0, 16).Select(index => Task.Run(() =>
        {
            byte[] hash = SHA256.HashData(BitConverter.GetBytes(index));
            for (int iteration = 0; iteration < 32; iteration++)
            {
                byte[] signature = signer.SignHash(hash);
                Assert.Equal(64, signature.Length);
                Assert.Same(verifier, resolver.Resolve("key"));
                Assert.Null(resolver.Resolve("KEY"));
                Assert.True(verifier.VerifyHash(hash, signature));
            }
        })));
    }

    [Fact]
    public void DisposeIsIdempotentAndProviderFailuresRemainDistinct()
    {
        var pair = CreateKeyPair();
        using UnsafeEcdsaContentSigner signer = new("key", pair.PrivateKeyPem);
        using UnsafeEcdsaContentVerifier verifier = new("key", pair.PublicKeyPem);
        byte[] hash = new byte[32];
        byte[] signature = signer.SignHash(hash);
        signer.Dispose();
        signer.Dispose();
        Assert.Throws<ObjectDisposedException>(() => signer.SignHash(hash));
        Assert.True(verifier.VerifyHash(hash, signature));
        verifier.Dispose();
        verifier.Dispose();
        Assert.Throws<ObjectDisposedException>(() => verifier.VerifyHash(hash, signature));
        // A disposed verifier cannot silently return false from the length fast path.
        Assert.Throws<ObjectDisposedException>(() => verifier.VerifyHash(hash, Array.Empty<byte>()));
        Assert.Throws<ObjectDisposedException>(() => signer.SignHash(Array.Empty<byte>()));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OperationsCanRaceWithRepeatedDisposal(bool signing)
    {
        var pair = CreateKeyPair();
        using UnsafeEcdsaContentSigner signer = new("key", pair.PrivateKeyPem);
        using UnsafeEcdsaContentVerifier verifier = new("key", pair.PublicKeyPem);
        byte[] hash = SHA256.HashData("dispose race"u8);
        byte[] signature = signer.SignHash(hash);
        Action operation = signing
            ? () => Assert.True(verifier.VerifyHash(hash, signer.SignHash(hash)))
            : () => Assert.True(verifier.VerifyHash(hash, signature));
        Action dispose = signing ? signer.Dispose : verifier.Dispose;
        operation();

        TaskCompletionSource<bool> start = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task[] workers = Enumerable.Range(0, 16).Select(_ => Task.Run(async () =>
        {
            await start.Task;
            for (int iteration = 0; iteration < 64; iteration++)
            {
                try
                {
                    operation();
                }
                catch (ObjectDisposedException)
                {
                    // Disposal wins the lock: expected provider failure, not a
                    // cryptographic failure, false verification, or document error.
                    return;
                }
            }
        })).ToArray();
        Task[] disposers = Enumerable.Range(0, 4).Select(_ => Task.Run(async () =>
        {
            await start.Task;
            for (int iteration = 0; iteration < 16; iteration++) dispose();
        })).ToArray();

        start.SetResult(true);
        await Task.WhenAll(workers.Concat(disposers)).WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Throws<ObjectDisposedException>(operation);
    }

    private static (string PrivateKeyPem, string PublicKeyPem) CreateKeyPair()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (key.ExportPkcs8PrivateKeyPem(), key.ExportSubjectPublicKeyInfoPem());
    }

    private static T AssertKeyRejected<T>(bool privateKey, string pem) where T : Exception
    {
        return Assert.Throws<T>(() =>
        {
            // Dispose even if a regression unexpectedly accepts the key.
            using IDisposable provider = privateKey
                ? new UnsafeEcdsaContentSigner("key", pem)
                : new UnsafeEcdsaContentVerifier("key", pem);
        });
    }

    private static string RewriteCurveParameters(ECDsa key, bool privateKey, string? curveOid)
    {
        byte[] original = privateKey ? key.ExportPkcs8PrivateKey() : key.ExportSubjectPublicKeyInfo();
        AsnWriter writer = new(AsnEncodingRules.DER);
        try
        {
            AsnReader reader = new(original, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            writer.PushSequence();
            if (privateKey) writer.WriteInteger(sequence.ReadInteger());
            AsnReader algorithm = sequence.ReadSequence();
            writer.PushSequence();
            writer.WriteObjectIdentifier(algorithm.ReadObjectIdentifier());
            if (curveOid is null)
                writer.WriteNull(); // Implicit parameters are not a named curve.
            else
                writer.WriteObjectIdentifier(curveOid);
            writer.PopSequence();
            while (sequence.HasData) writer.WriteEncodedValue(sequence.ReadEncodedValue().Span);
            writer.PopSequence();
            byte[] changed = writer.Encode();
            try
            {
                return PemEncoding.WriteString(privateKey ? "PRIVATE KEY" : "PUBLIC KEY", changed);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(changed);
            }
        }
        finally
        {
            writer.Reset();
            CryptographicOperations.ZeroMemory(original);
        }
    }

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public Segment(ReadOnlyMemory<byte> memory) => Memory = memory;

        public Segment Append(ReadOnlyMemory<byte> memory)
        {
            Segment next = new(memory) { RunningIndex = RunningIndex + Memory.Length };
            Next = next;
            return next;
        }
    }

    private sealed class MutableVerifier(string keyId) : IContentVerifier
    {
        public string KeyId { get; set; } = keyId;
        public string AlgorithmId => "test-only";
        public bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature) => true;
    }
}