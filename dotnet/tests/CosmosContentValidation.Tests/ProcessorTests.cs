using System.Buffers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CosmosContentValidation.Sample.Providers;
using Microsoft.IO;
using Xunit;

namespace CosmosContentValidation.Tests;

public sealed class ProcessorTests
{
    private const string Profile = "rfc8785-binary64-v1";
    private const string HashAlgorithm = "SHA-256";
    private const string SignatureAlgorithm = "ECDSA-P256-SHA256-P1363";
    private const string EnvelopeName = "_contentValidation";
    private const string Document = "{\"id\":\"item\",\"pk\":\"tenant\",\"value\":1}";
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private static readonly string[] EnvelopeFields =
        ["v", "canonicalization", "hashAlgorithm", "signatureAlgorithm", "exclusionPolicyHash", "kid", "signature"];
    private static readonly string[] ServiceFields = ["_rid", "_self", "_etag", "_attachments", "_ts"];

    [Theory]
    [InlineData("default-policy.json")]
    [InlineData("custom-policy.json")]
    public void CommittedPublicFixturesFreezeCanonicalBytesPolicyDigestAndBothProcessorDirections(string filename)
    {
        using JsonDocument fixture = JsonDocument.Parse(File.ReadAllBytes(FindFixture(filename)));
        JsonElement vector = fixture.RootElement;
        string[] ignored = vector.GetProperty("additionalIgnoredRootProperties").EnumerateArray().Select(item => item.GetString()!).ToArray();
        string[] paths = vector.GetProperty("partitionKeyPaths").EnumerateArray().Select(item => item.GetString()!).ToArray();
        JsonObject document = Object(vector.GetProperty("document").GetRawText());
        JsonObject filtered = (JsonObject)document.DeepClone();
        foreach (string name in ServiceFields.Concat(ignored)) filtered.Remove(name);
        AssertFixtureCanonical(vector, "canonicalDocument", filtered.ToJsonString());
        JsonObject envelope = Object(vector.GetProperty("signedDocument").GetRawText())[EnvelopeName]!.AsObject();
        JsonObject header = (JsonObject)envelope.DeepClone();
        header.Remove("signature");
        AssertFixtureCanonical(vector, "canonicalHeader", header.ToJsonString());
        AssertFixtureCanonical(vector, "policyCanonical", vector.GetProperty("policyCanonical").GetString()!);
        Assert.Equal(vector.GetProperty("exclusionPolicyHash").GetString(),
            Encode(SHA256.HashData(Encoding.UTF8.GetBytes(vector.GetProperty("policyCanonical").GetString()!))));
        AssertFixtureCanonical(vector, "canonicalSignedContent", new JsonObject
        {
            ["domain"] = "CosmosContentValidation", ["header"] = header, ["document"] = filtered
        }.ToJsonString());

        string canonical = vector.GetProperty("canonicalSignedContent").GetString()!;
        byte[] digest = Decode(vector.GetProperty("sha256Base64Url").GetString()!);
        byte[] signature = Decode(envelope["signature"]!.GetValue<string>());
        Assert.Equal(digest, SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        string keyId = envelope["kid"]!.GetValue<string>();
        string pem = vector.GetProperty("publicKeyPem").GetString()!;
        using UnsafeEcdsaContentVerifier verifier = new(keyId, pem);
        using ECDsa independent = ECDsa.Create();
        independent.ImportFromPem(pem);
        Assert.True(independent.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Assert.False(independent.VerifyData(digest, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        ContentValidationProcessor processor = new(new() { PartitionKeyPaths = paths, AdditionalIgnoredRootProperties = ignored },
            new UnsafeInMemoryVerificationKeyResolver([verifier]), new UnsafeJcsCanonicalizer(),
            new GoldenHasher(canonical, digest, vector.GetProperty("policyCanonical").GetString()!,
                Decode(vector.GetProperty("exclusionPolicyHash").GetString()!)), new GoldenSigner(keyId, digest, signature));
        Assert.Equal(vector.GetProperty("exclusionPolicyHash").GetString(), processor.ExclusionPolicyHash);
        ReadOnlySequence<byte> signed = Raw(vector.GetProperty("signedDocument").GetRawText());
        processor.Validate(signed);
        using (RecyclableMemoryStream stripped = processor.ValidateAndStrip(signed))
            Assert.True(JsonNode.DeepEquals(document, Object(stripped.GetReadOnlySequence().ToArray())));
        using (RecyclableMemoryStream produced = processor.Sign(Raw(document.ToJsonString())))
        {
            processor.Validate(produced.GetReadOnlySequence());
            Assert.Equal(signature, Decode(Object(produced.GetReadOnlySequence().ToArray())[EnvelopeName]!["signature"]!.GetValue<string>()));
        }
        Assert.Equal(0, processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(14000)]
    [InlineData(15500)]
    public void LargeWriterReservationHintsDoNotRejectRepresentationsThatFitTheBuffer(int characters)
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create(new() { MaxDocumentBytes = 16384, MaxBufferedBytes = 16384 });
        JsonObject document = Object(Document);
        document["text"] = new string('a', characters);
        byte[] signed = SignBytes(processor, document.ToJsonString());
        Assert.True(signed.Length <= processor.MaxDocumentBytes);
        processor.Validate(new(signed));
        using (RecyclableMemoryStream stripped = processor.ValidateAndStrip(new(signed)))
            Assert.True(JsonNode.DeepEquals(document, Object(stripped.GetReadOnlySequence().ToArray())));
        Assert.Equal(0, processor.Buffers.InUseBytes);
    }

    private static string FindFixture(string filename)
    {
        string outputPath = Path.Combine(AppContext.BaseDirectory, "test-vectors", filename);
        if (File.Exists(outputPath)) return outputPath;
        // Also support explicitly running the fixture regression from a checkout.
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, "shared", "test-vectors", filename);
            if (File.Exists(candidate)) return candidate;
        }
        throw new FileNotFoundException("The committed interoperability fixture was not found.", filename);
    }

    private static void AssertFixtureCanonical(JsonElement vector, string property, string json)
    {
        using JsonDocument parsed = JsonDocument.Parse(json);
        ArrayBufferWriter<byte> destination = new();
        new UnsafeJcsCanonicalizer().Canonicalize(parsed.RootElement, destination);
        Assert.Equal(Encoding.UTF8.GetBytes(vector.GetProperty(property).GetString()!), destination.WrittenSpan.ToArray());
    }

    private sealed class GoldenHasher(string canonical, byte[] digest, string policyCanonical, byte[] policyDigest) : IContentHasher
    {
        public string AlgorithmId => HashAlgorithm;
        public int HashSizeInBytes => 32;
        public byte[] ComputeHash(ReadOnlySequence<byte> input)
        {
            byte[] bytes = input.ToArray();
            bool policy = bytes.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(policyCanonical));
            Assert.Equal(Encoding.UTF8.GetBytes(policy ? policyCanonical : canonical), bytes);
            byte[] expectedDigest = policy ? policyDigest : digest;
            Assert.Equal(expectedDigest, new UnsafeSha256ContentHasher().ComputeHash(input));
            return (byte[])expectedDigest.Clone();
        }
    }

    // A fixed public test signature can only be replayed for the fixture's one exact digest.
    private sealed class GoldenSigner(string keyId, byte[] digest, byte[] signature) : IContentSigner
    {
        public string KeyId => keyId;
        public string AlgorithmId => SignatureAlgorithm;
        public byte[] SignHash(ReadOnlySpan<byte> hash)
        {
            Assert.Equal(digest, hash.ToArray());
            return (byte[])signature.Clone();
        }
    }

    [Fact]
    public void SignValidateAndStripUseExactEnvelopeAndLeaveBorrowedBytesUnchanged()
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        byte[] input = Encoding.UTF8.GetBytes(" { \"pk\" : \"tenant\", \"id\":\"item\", \"value\":1.0, \"_etag\":\"service\","
            + "\"nested\":{\"_contentValidation\":{\"application\":true}} } ");
        byte[] snapshot = (byte[])input.Clone();
        using (RecyclableMemoryStream signed = processor.Sign(new(input)))
        {
            Assert.Equal(0L, signed.Position);
            Assert.True(signed.CanRead);
            Assert.True(signed.CanSeek);
            Assert.NotEqual(0L, processor.Buffers.InUseBytes);
            byte[] signedSnapshot = signed.GetReadOnlySequence().ToArray();
            JsonObject root = Object(signedSnapshot);
            JsonObject envelope = root[EnvelopeName]!.AsObject();
            Assert.Equal(EnvelopeFields.Order(StringComparer.Ordinal), envelope.Select(property => property.Key).Order(StringComparer.Ordinal));
            Assert.Equal(1, envelope["v"]!.GetValue<int>());
            Assert.Equal(Profile, envelope["canonicalization"]!.GetValue<string>());
            Assert.Equal(HashAlgorithm, envelope["hashAlgorithm"]!.GetValue<string>());
            Assert.Equal(SignatureAlgorithm, envelope["signatureAlgorithm"]!.GetValue<string>());
            Assert.Equal(processor.ExclusionPolicyHash, envelope["exclusionPolicyHash"]!.GetValue<string>());
            Assert.Equal(keys.Signer.KeyId, envelope["kid"]!.GetValue<string>());
            AssertCanonicalEncoding(envelope["signature"]!.GetValue<string>(), 64);
            AssertCanonicalEncoding(processor.ExclusionPolicyHash, 32);
            Assert.Equal("service", root["_etag"]!.GetValue<string>());

            signed.Position = 11;
            processor.Validate(signed.GetReadOnlySequence());
            Assert.Equal(11L, signed.Position);
            using (RecyclableMemoryStream stripped = processor.ValidateAndStrip(signed.GetReadOnlySequence()))
            {
                Assert.Equal(0L, stripped.Position);
                JsonObject result = Object(stripped.GetReadOnlySequence().ToArray());
                Assert.False(result.ContainsKey(EnvelopeName));
                Assert.True(result["nested"]![EnvelopeName]!["application"]!.GetValue<bool>());
                Assert.True(JsonNode.DeepEquals(Object(input), result));
                Assert.Equal(signedSnapshot, signed.GetReadOnlySequence().ToArray());
            }
            Assert.True(signed.CanRead);
            Assert.Equal(11L, signed.Position);
        }
        Assert.Equal(snapshot, input);
        Assert.Equal(0L, processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OffsetAndSegmentedInputsOver16KHonorLogicalBoundsAndOwnership(bool segmented)
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        JsonObject document = Object(Document);
        document["payload"] = string.Concat(Enumerable.Repeat("é🚀0123456789", 4000));
        byte[] payload = Encoding.UTF8.GetBytes(document.ToJsonString());
        byte[] backing = [0xFF, .. payload, 0xFE];
        byte[] snapshot = (byte[])backing.Clone();
        ReadOnlySequence<byte> input = Borrow(backing, segmented);
        Assert.True(input.Length > 16 * 1024);
        Assert.Equal(!segmented, input.IsSingleSegment);
        byte[] signed = SignBytes(processor, input);
        Assert.Equal(snapshot, backing);
        Array.Fill(backing, (byte)0xCC); // A returned output must not borrow the original input.

        byte[] signedBacking = [0xFF, .. signed, 0xFE];
        byte[] signedSnapshot = (byte[])signedBacking.Clone();
        ReadOnlySequence<byte> signedInput = Borrow(signedBacking, segmented);
        processor.Validate(signedInput);
        using (RecyclableMemoryStream stripped = processor.ValidateAndStrip(signedInput))
        {
            Assert.Equal(0L, stripped.Position);
            Assert.False(stripped.GetReadOnlySequence().IsSingleSegment);
            Assert.Equal(signedSnapshot, signedBacking);
            Array.Fill(signedBacking, (byte)0xCC);
            Assert.True(JsonNode.DeepEquals(document, Object(stripped.GetReadOnlySequence().ToArray())));
        }
        Assert.Equal(0L, processor.Buffers.InUseBytes);

        byte[] tampered = Encoding.UTF8.GetBytes(Edit(signed, root => root["payload"] = "changed"));
        byte[] badBacking = [0xFF, .. tampered, 0xFE];
        byte[] badSnapshot = (byte[])badBacking.Clone();
        AssertInvalidSigned(processor, Borrow(badBacking, segmented), ContentValidationFailure.InvalidSignature);
        Assert.Equal(badSnapshot, badBacking);
    }

    [Fact]
    public void PooledInputRemainsCallerOwnedOnSuccessAndFailure()
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        PooledJsonBufferPool inputPool = new();
        RecyclableMemoryStream output;
        using (RecyclableMemoryStream input = inputPool.Rent())
        {
            input.Write(Encoding.UTF8.GetBytes(Document));
            input.Position = 7;
            output = processor.Sign(input.GetReadOnlySequence());
            Assert.Equal(7L, input.Position);
            Assert.Equal(Encoding.UTF8.GetBytes(Document), input.GetReadOnlySequence().ToArray());
        }
        Assert.Equal(0L, inputPool.InUseBytes);
        using (output)
        {
            processor.Validate(output.GetReadOnlySequence());
            Assert.Equal(0L, output.Position);
        }
        Assert.Equal(0L, processor.Buffers.InUseBytes);

        using (RecyclableMemoryStream invalid = inputPool.Rent())
        {
            invalid.Write("{\"id\":\"item\",\"pk\":\"tenant\",\"_etag\":{\"x\":1,\"x\":2}}"u8);
            invalid.Position = 5;
            byte[] snapshot = invalid.GetReadOnlySequence().ToArray();
            Failure(processor, ContentValidationFailure.InvalidDocument, () => SignBytes(processor, invalid.GetReadOnlySequence()));
            Assert.True(invalid.CanRead);
            Assert.Equal(5L, invalid.Position);
            Assert.Equal(snapshot, invalid.GetReadOnlySequence().ToArray());
        }
        Assert.Equal(0L, inputPool.InUseBytes);
    }

    [Theory]
    [InlineData("_rid")]
    [InlineData("_self")]
    [InlineData("_etag")]
    [InlineData("_attachments")]
    [InlineData("_ts")]
    public void DefaultServiceExclusionsAllowRootAddChangeRemoveButProtectNestedNames(string name)
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        JsonObject document = Object(Document);
        document["nested"] = new JsonObject { [name] = "protected" };
        byte[] signed = SignBytes(processor, document.ToJsonString());
        string added = Edit(signed, root => root[name] = JsonNode.Parse("{\"arbitrary\":[1,true,null]}"));
        processor.Validate(Raw(added));
        string changed = Edit(added, root => root[name] = 123);
        processor.Validate(Raw(changed));
        string removed = Edit(changed, root => root.Remove(name));
        processor.Validate(Raw(removed));
        using (RecyclableMemoryStream stripped = processor.ValidateAndStrip(Raw(changed)))
            Assert.Equal(123, Object(stripped.GetReadOnlySequence().ToArray())[name]!.GetValue<int>());
        AssertInvalidSigned(processor, Raw(Edit(signed, root => root["nested"]![name] = "tampered")), ContentValidationFailure.InvalidSignature);
        AssertInvalidSigned(processor, Raw(Edit(signed, root => root[name.ToUpperInvariant()] = "not ignored")), ContentValidationFailure.InvalidSignature);
    }

    [Fact]
    public void DefaultPolicyProtectsTtlCustomUnknownPropertiesNullPresenceAndArrayOrder()
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        byte[] signed = SignBytes(processor, "{\"id\":\"item\",\"pk\":\"tenant\",\"ttl\":30,\"_custom\":1,\"optional\":null,\"items\":[1,2]}");
        Action<JsonObject>[] changes =
        [
            root => root["ttl"] = 31,
            root => root.Remove("ttl"),
            root => root["_custom"] = 2,
            root => root.Remove("_custom"),
            root => root["unknownApplicationField"] = true,
            root => root.Remove("optional"),
            root => root["missing"] = null,
            root => root["items"] = JsonNode.Parse("[2,1]"),
            root => root["items"] = JsonNode.Parse("[1,2,null]"),
            root => root["id"] = "another",
            root => root["pk"] = "another"
        ];
        foreach (Action<JsonObject> change in changes)
            AssertInvalidSigned(processor, Raw(Edit(signed, change)), ContentValidationFailure.InvalidSignature);

        // Canonicalization, unlike byte-for-byte signing, permits member reordering and equivalent numbers.
        string reordered = Edit(signed, root =>
        {
            JsonNode? value = root["ttl"];
            root.Remove("ttl");
            root["ttl"] = value;
        }).Replace("\"ttl\":30", "\"ttl\":3e1", StringComparison.Ordinal);
        processor.Validate(Raw(reordered));
    }

    [Fact]
    public void CustomExclusionsAreCaseSensitiveRootNamesAndExcludeTheirEntireSubtrees()
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create(new() { AdditionalIgnoredRootProperties = ["scratch", "a/b"] });
        byte[] signed = SignBytes(processor, "{\"id\":\"item\",\"pk\":\"tenant\",\"scratch\":{\"deep\":[1,2]},\"nested\":{\"scratch\":1},\"a\":{\"b\":1}}");
        string changed = Edit(signed, root =>
        {
            root["scratch"] = JsonNode.Parse("[null,{\"completelyDifferent\":true}]");
            root["a/b"] = "literal root name, not a path";
        });
        processor.Validate(Raw(changed));
        string removed = Edit(changed, root => root.Remove("scratch"));
        processor.Validate(Raw(removed));
        processor.Validate(Raw(Edit(removed, root => root["scratch"] = null)));
        foreach (string name in new[] { "Scratch", "SCRATCH" })
            AssertInvalidSigned(processor, Raw(Edit(signed, root => root[name] = 1)), ContentValidationFailure.InvalidSignature);
        AssertInvalidSigned(processor, Raw(Edit(signed, root => root["nested"]!["scratch"] = 2)), ContentValidationFailure.InvalidSignature);
        AssertInvalidSigned(processor, Raw(Edit(signed, root => root["a"]!["b"] = 2)), ContentValidationFailure.InvalidSignature);
    }

    [Fact]
    public void OptionsAreCopiedPartitionPathsAreReadOnlyAndPolicyIsOrderIndependent()
    {
        using Keys keys = new();
        List<string> paths = ["/tenant/code"];
        List<string> ignored = ["scratch", "memo", "scratch", "_etag"];
        ContentValidationProcessor processor = keys.Create(new()
        {
            PartitionKeyPaths = paths,
            AdditionalIgnoredRootProperties = ignored,
            MaxDocumentBytes = 4096,
            MaxBufferedBytes = 16384
        });
        string originalPolicy = processor.ExclusionPolicyHash;
        paths[0] = "/other";
        ignored.Clear();
        ignored.Add("value");
        Assert.Equal(new[] { "/tenant/code" }, processor.PartitionKeyPaths);
        IList<string> exposed = Assert.IsAssignableFrom<IList<string>>(processor.PartitionKeyPaths);
        Assert.True(exposed.IsReadOnly);
        Assert.Throws<NotSupportedException>(() => exposed[0] = "/other");
        Assert.Throws<NotSupportedException>(() => exposed.Add("/other"));
        Assert.Equal(4096, processor.MaxDocumentBytes);
        Assert.Equal(16384, processor.Buffers.MaxBufferBytes);
        Assert.Equal(originalPolicy, processor.ExclusionPolicyHash);

        ContentValidationProcessor equivalent = keys.Create(new()
        {
            PartitionKeyPaths = ["/pk", "/another"],
            AdditionalIgnoredRootProperties = ["memo", "scratch"]
        });
        Assert.Equal(originalPolicy, equivalent.ExclusionPolicyHash);
        Assert.NotEqual(originalPolicy, keys.Create(new() { AdditionalIgnoredRootProperties = ["Memo", "scratch"] }).ExclusionPolicyHash);
        byte[] signed = SignBytes(processor, "{\"id\":\"item\",\"tenant\":{\"code\":1},\"value\":1}");
        processor.Validate(Raw(Edit(signed, root => root["scratch"] = "still ignored")));
        AssertInvalidSigned(processor, Raw(Edit(signed, root => root["value"] = 2)), ContentValidationFailure.InvalidSignature);
        Failure(processor, ContentValidationFailure.InvalidDocument,
            () => SignBytes(processor, "{\"id\":\"item\",\"other\":1}"));

        ContentValidationProcessor defaults = keys.Create();
        const string descriptor = "{\"ignoredProperties\":[\"_attachments\",\"_etag\",\"_rid\",\"_self\",\"_ts\"],\"scope\":\"root\",\"version\":1}";
        Assert.Equal(Encode(SHA256.HashData(Encoding.UTF8.GetBytes(descriptor))), defaults.ExclusionPolicyHash);
        Assert.Equal(defaults.ExclusionPolicyHash, keys.Create(new() { AdditionalIgnoredRootProperties = ServiceFields.Reverse().Concat(ServiceFields).ToArray() }).ExclusionPolicyHash);
    }

    [Theory]
    [InlineData("id", "/pk")]
    [InlineData("_contentValidation", "/pk")]
    [InlineData("pk", "/pk")]
    [InlineData("tenant", "/tenant/code")]
    [InlineData("tenant", "/tenant/nested/code")]
    public void IdentityReservedAndPartitionKeyRootsCannotBeIgnored(string ignored, string path)
    {
        using Keys keys = new();
        Assert.Throws<ArgumentException>(() => keys.Create(new() { PartitionKeyPaths = [path], AdditionalIgnoredRootProperties = [ignored] }));
    }

    [Theory]
    [InlineData("/_rid")]
    [InlineData("/_self")]
    [InlineData("/_etag")]
    [InlineData("/_attachments")]
    [InlineData("/_ts")]
    [InlineData("/_etag/nested")]
    [InlineData("/_contentValidation")]
    [InlineData("/_contentValidation/nested")]
    public void ServiceAndReservedRootsCannotBePartitionKeys(string path)
    {
        using Keys keys = new();
        Assert.Throws<ArgumentException>(() => keys.Create(new() { PartitionKeyPaths = [path] }));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("pk")]
    [InlineData("/")]
    [InlineData("/pk/")]
    [InlineData("/a//b")]
    [InlineData("/\"pk\"")]
    [InlineData("/'pk'")]
    [InlineData("/a~1b")]
    [InlineData("/a~0b")]
    [InlineData("/a\\b")]
    [InlineData("/a/*")]
    [InlineData("/a/?")]
    [InlineData("/a/[0]")]
    [InlineData("/a b")]
    [InlineData("/a/%2F")]
    public void PartitionPathsRejectEmptyQuotedEscapedAndWildcardSegments(string? path)
    {
        using Keys keys = new();
        Assert.Throws<ArgumentException>(() => keys.Create(new() { PartitionKeyPaths = [path!] }));
    }

    [Fact]
    public void ConfigurationRejectsInvalidCollectionsCountsNamesAndLimits()
    {
        using Keys keys = new();
        Assert.Throws<ArgumentNullException>("options", () => new ContentValidationProcessor(null!, keys.Resolver, new UnsafeJcsCanonicalizer(), new UnsafeSha256ContentHasher()));
        Assert.Throws<ArgumentNullException>("verificationKeys", () => new ContentValidationProcessor(new(), null!, new UnsafeJcsCanonicalizer(), new UnsafeSha256ContentHasher()));
        Assert.Throws<ArgumentNullException>(() => keys.Create(new() { PartitionKeyPaths = null! }));
        Assert.Throws<ArgumentNullException>(() => keys.Create(new() { AdditionalIgnoredRootProperties = null! }));
        Assert.Throws<ArgumentException>(() => keys.Create(new() { PartitionKeyPaths = [] }));
        Assert.Throws<ArgumentException>(() => keys.Create(new() { PartitionKeyPaths = ["/pk", "/pk"] }));
        Assert.Throws<ArgumentException>(() => keys.Create(new() { PartitionKeyPaths = ["/a", "/b", "/c", "/d"] }));
        Assert.Throws<ArgumentException>(() => keys.Create(new() { PartitionKeyPaths = ["/" + string.Join('/', Enumerable.Repeat("a", 64))] }));
        foreach (string? name in new[] { null, "", "\uD800", "\uDC00", "x\uD800y" })
            Assert.Throws<ArgumentException>(() => keys.Create(new() { AdditionalIgnoredRootProperties = [name!] }));
        Assert.Throws<ArgumentOutOfRangeException>(() => keys.Create(new() { MaxDocumentBytes = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => keys.Create(new() { MaxDocumentBytes = -1 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => keys.Create(new() { MaxDocumentBytes = 1, MaxBufferedBytes = 1023 }));
        Assert.Throws<ArgumentException>(() => keys.Create(new() { MaxDocumentBytes = 2048, MaxBufferedBytes = 1024 }));
    }

    [Theory]
    [InlineData("canonicalizer")]
    [InlineData("hasher")]
    public void RequiredProviderNullIsRejectedBeforeAnyProviderInvocation(string parameter)
    {
        using Keys keys = new();
        Probe probe = new(keys);
        Assert.Throws<ArgumentNullException>(parameter, () => new ContentValidationProcessor(new(), keys.Resolver,
            parameter == "canonicalizer" ? null! : probe,
            parameter == "hasher" ? null! : probe, keys.Signer));
        Assert.Empty(probe.Calls);
        Assert.Empty(probe.ValidatedInputs);
    }

    [Fact]
    public void InjectedRawValidatorSeesExcludedSubtreeBeforeCanonicalizingOrSigning()
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(new() { AdditionalIgnoredRootProperties = ["scratch"] }, providers: probe);
        const string document = "{\"id\":\"item\",\"pk\":\"tenant\",\"scratch\":{\"entire\":[1,true,null]},\"_etag\":\"service\"}";
        probe.AfterValidation = value =>
        {
            Assert.Empty(probe.Calls);
            Assert.Equal(document, value.GetRawText());
            Assert.Equal(3, value.GetProperty("scratch").GetProperty("entire").GetArrayLength());
            Assert.Equal("service", value.GetProperty("_etag").GetString());
        };

        _ = SignBytes(processor, document);

        Assert.Equal(document, Assert.Single(probe.ValidatedInputs));
        Assert.Equal(new[] { "canonicalize-document", "canonicalize-header", "hash", "sign" }, probe.Calls);
        Assert.DoesNotContain(probe.CanonicalInputs, input => Object(input).ContainsKey("scratch") || Object(input).ContainsKey("_etag"));
        Assert.Equal(0L, processor.Buffers.InUseBytes);
    }

    [Theory]
    [InlineData("sign")]
    [InlineData("validate")]
    [InlineData("strip")]
    public void InjectedRawValidatorFailureStopsProcessingWithoutFallbackAndSanitizesDiagnostics(string operation)
    {
        using Keys keys = new();
        Probe probe = new(keys) { ValidationFault = new JsonException("sensitive validator input") };
        ContentValidationProcessor processor = keys.Create(providers: probe);
        byte[] signed = SignBytes(keys.Create(), Document);
        ContentValidationException failure = Failure(processor, ContentValidationFailure.InvalidDocument, () =>
        {
            if (operation == "sign") _ = SignBytes(processor, Document);
            else if (operation == "validate") processor.Validate(new(signed));
            else
            {
                using RecyclableMemoryStream result = processor.ValidateAndStrip(new(signed));
            }
        });
        Assert.Single(probe.ValidatedInputs);
        Assert.Empty(probe.Calls); // No canonicalization, hashing, signing, resolution or verification.
        Assert.DoesNotContain("sensitive validator input", failure.ToString());
        Assert.IsType<JsonException>(failure.InnerException);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("false")]
    [InlineData("0")]
    [InlineData("-12.5")]
    [InlineData("9007199254740991")]
    [InlineData("\"\"")]
    [InlineData("\"tenant\"")]
    public void PartitionKeyLeavesSupportAllJsonScalars(string scalar)
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create(new()
        {
            PartitionKeyPaths = ["/tenant/code", "/region", "/v-1.é/_leaf"],
            AdditionalIgnoredRootProperties = ["code"] // A leaf name is not its ancestor root.
        });
        byte[] signed = SignBytes(processor, "{\"id\":\"item\",\"tenant\":{\"code\":" + scalar
            + "},\"region\":true,\"v-1.é\":{\"_leaf\":null}}");
        processor.Validate(new(signed));
        processor.Validate(Raw(Edit(signed, root => root["code"] = "ignored only at root")));
        AssertInvalidSigned(processor, Raw(Edit(signed, root => root["tenant"]!["code"] = "different")), ContentValidationFailure.InvalidSignature);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"tenant\":null}")]
    [InlineData("{\"tenant\":1}")]
    [InlineData("{\"tenant\":{}}")]
    [InlineData("{\"Tenant\":{\"code\":1}}")]
    [InlineData("{\"tenant\":{\"Code\":1}}")]
    [InlineData("{\"tenant\":{\"code\":{}}}")]
    [InlineData("{\"tenant\":{\"code\":[]}}")]
    public void MissingNonScalarAndWrongCasePartitionKeysFailBeforeProviders(string body)
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(new() { PartitionKeyPaths = ["/tenant/code"] }, providers: probe);
        JsonObject document = Object(body);
        document["id"] = "item";
        Failure(processor, ContentValidationFailure.InvalidDocument, () => SignBytes(processor, document.ToJsonString()));
        AssertInvalidSigned(processor, Raw(document.ToJsonString()), ContentValidationFailure.InvalidDocument);
        Assert.Empty(probe.Calls);
    }

    [Fact]
    public void PartitionPathsAreOrdinalAndNestedServiceNamesRemainProtected()
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create(new() { PartitionKeyPaths = ["/pk", "/Pk", "/tenant/_etag"] });
        byte[] signed = SignBytes(processor, "{\"id\":\"item\",\"pk\":1,\"Pk\":2,\"tenant\":{\"_etag\":3}}");
        processor.Validate(new(signed));
        processor.Validate(Raw(Edit(signed, root => root["_etag"] = "root service metadata")));
        AssertInvalidSigned(processor, Raw(Edit(signed, root => root["Pk"] = 3)), ContentValidationFailure.InvalidSignature);
        AssertInvalidSigned(processor, Raw(Edit(signed, root => root["tenant"]!["_etag"] = 4)), ContentValidationFailure.InvalidSignature);
        AssertInvalidSigned(processor, Raw(Edit(signed, root => root.Remove("Pk"))), ContentValidationFailure.InvalidDocument);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("1")]
    [InlineData("true")]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("\"\"")]
    [InlineData("\"a/b\"")]
    [InlineData("\"a\\\\b\"")]
    [InlineData("\"a?b\"")]
    [InlineData("\"a#b\"")]
    public void InvalidIdsAreRejected(string id)
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        string document = "{\"pk\":\"tenant\",\"id\":" + id + "}";
        Failure(processor, ContentValidationFailure.InvalidDocument, () => SignBytes(processor, document));
        AssertInvalidSigned(processor, Raw(document), ContentValidationFailure.InvalidDocument);
    }

    [Fact]
    public void IdIsRequiredAndIts1023ByteLimitIsUtf8NotCharacterCount()
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        Failure(processor, ContentValidationFailure.InvalidDocument, () => SignBytes(processor, "{\"pk\":1}"));
        foreach (string id in new[] { new string('a', 1023), new string('é', 511) + "a", "日本語-🚀" })
        {
            JsonObject document = Object(Document);
            document["id"] = id;
            processor.Validate(new(SignBytes(processor, document.ToJsonString())));
        }
        foreach (string id in new[] { new string('a', 1024), new string('é', 512) })
        {
            JsonObject document = Object(Document);
            document["id"] = id;
            Failure(processor, ContentValidationFailure.InvalidDocument, () => SignBytes(processor, document.ToJsonString()));
        }
    }

    [Fact]
    public void MissingSignaturesAndVerifyOnlySigningHaveDistinctFailures()
    {
        using Keys keys = new();
        ContentValidationProcessor writer = keys.Create();
        ContentValidationProcessor reader = keys.Create(canSign: false);
        Assert.True(writer.CanSign);
        Assert.False(reader.CanSign);
        AssertInvalidSigned(reader, Raw(Document), ContentValidationFailure.MissingSignature);
        Failure(reader, ContentValidationFailure.SigningUnavailable, () => SignBytes(reader, Document));
        Failure(reader, ContentValidationFailure.SigningUnavailable, () => SignBytes(reader, "not json"));
        byte[] signed = SignBytes(writer, Document);
        reader.Validate(new(signed));
        using (RecyclableMemoryStream stripped = reader.ValidateAndStrip(new(signed)))
            Assert.True(JsonNode.DeepEquals(Object(Document), Object(stripped.GetReadOnlySequence().ToArray())));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("0")]
    [InlineData("\"text\"")]
    [InlineData("[]")]
    [InlineData("{}")]
    public void NormalSigningRejectsAnyReservedRootProperty(string envelope)
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(providers: probe);
        string document = Edit(Document, root => root[EnvelopeName] = JsonNode.Parse(envelope));
        Failure(processor, ContentValidationFailure.ReservedProperty, () => SignBytes(processor, document));
        Assert.Empty(probe.Calls);
    }

    [Fact]
    public void ReplacementSignsEditedContentWithoutResolvingOrVerifyingOldSignature()
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(providers: probe);
        byte[] original = SignBytes(processor, Document);
        string changed = Edit(original, root =>
        {
            root["value"] = 2;
            root[EnvelopeName]!["kid"] = "retired-and-unknown";
            root[EnvelopeName]!["signature"] = Encode(new byte[64]);
        });
        Failure(processor, ContentValidationFailure.ReservedProperty, () => SignBytes(processor, changed));
        probe.Clear();
        byte[] replacement = SignBytes(processor, Raw(changed), replace: true);
        Assert.Equal(new[] { "canonicalize-document", "canonicalize-header", "hash", "sign" }, probe.Calls);
        processor.Validate(new(replacement));
        Assert.Equal(2, Object(replacement)["value"]!.GetValue<int>());
        Assert.Equal(keys.Signer.KeyId, Object(replacement)[EnvelopeName]!["kid"]!.GetValue<string>());
        AssertInvalidSigned(processor, Raw(Edit(replacement, root => root["value"] = 1)), ContentValidationFailure.InvalidSignature);
        // The explicit replacement option also accepts a document that has no old envelope.
        processor.Validate(new(SignBytes(processor, Raw(Document), replace: true)));
    }

    [Fact]
    public void StrictMetadataRejectsEveryMissingFieldExtraFieldAndMalformedStringType()
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(providers: probe);
        byte[] signed = SignBytes(processor, Document);
        foreach (string field in EnvelopeFields)
        {
            AssertBadEnvelope(processor, probe, EditEnvelope(signed, envelope => envelope.Remove(field)), ContentValidationFailure.InvalidSignature);
            foreach (string invalid in new[] { "null", "true", "[]", "{}", "\"\"", "\" \"" })
                AssertBadEnvelope(processor, probe, EditEnvelope(signed, envelope => envelope[field] = JsonNode.Parse(invalid)), ContentValidationFailure.InvalidSignature);
            if (field != "v")
                AssertBadEnvelope(processor, probe, EditEnvelope(signed, envelope => envelope[field] = 1), ContentValidationFailure.InvalidSignature);
        }
        AssertBadEnvelope(processor, probe, EditEnvelope(signed, envelope => envelope["extra"] = true), ContentValidationFailure.InvalidSignature);
        AssertBadEnvelope(processor, probe, EditEnvelope(signed, envelope =>
        {
            envelope.Remove("kid");
            envelope["Kid"] = keys.Signer.KeyId; // Still seven fields, but not the seven required names.
        }), ContentValidationFailure.InvalidSignature);
        foreach (string invalid in new[] { "null", "0", "true", "\"text\"", "[]", "{}" })
            AssertBadEnvelope(processor, probe, Edit(signed, root => root[EnvelopeName] = JsonNode.Parse(invalid)), ContentValidationFailure.InvalidSignature);
    }

    [Theory]
    [InlineData("v", "0", ContentValidationFailure.UnsupportedProfile)]
    [InlineData("v", "2", ContentValidationFailure.UnsupportedProfile)]
    [InlineData("v", "-1", ContentValidationFailure.UnsupportedProfile)]
    [InlineData("v", "1.5", ContentValidationFailure.InvalidSignature)]
    [InlineData("v", "2147483648", ContentValidationFailure.InvalidSignature)]
    [InlineData("v", "\"1\"", ContentValidationFailure.InvalidSignature)]
    [InlineData("canonicalization", "\"rfc8785\"", ContentValidationFailure.UnsupportedProfile)]
    [InlineData("canonicalization", "\"RFC8785-binary64-v1\"", ContentValidationFailure.UnsupportedProfile)]
    [InlineData("hashAlgorithm", "\"SHA-512\"", ContentValidationFailure.UnsupportedProfile)]
    [InlineData("hashAlgorithm", "\"sha-256\"", ContentValidationFailure.UnsupportedProfile)]
    [InlineData("signatureAlgorithm", "\"ECDSA-P256-SHA256-DER\"", ContentValidationFailure.UnsupportedProfile)]
    public void UnknownProfilesVersionsAndWrongVersionTypesAreNotAccepted(string field, string value, ContentValidationFailure expected)
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(providers: probe);
        byte[] signed = SignBytes(processor, Document);
        AssertBadEnvelope(processor, probe, EditEnvelope(signed, envelope => envelope[field] = JsonNode.Parse(value)), expected);
    }

    [Fact]
    public void LocalPolicyMismatchFailsEvenWhenAllExcludedFieldsAreAbsent()
    {
        using Keys keys = new();
        ContentValidationProcessor writer = keys.Create();
        Probe probe = new(keys);
        ContentValidationProcessor otherPolicy = keys.Create(new() { AdditionalIgnoredRootProperties = ["notInTheDocument"] }, providers: probe);
        byte[] signed = SignBytes(writer, Document);
        AssertBadEnvelope(otherPolicy, probe, Encoding.UTF8.GetString(signed), ContentValidationFailure.PolicyMismatch);
        string changedPolicy = EditEnvelope(signed, envelope => envelope["exclusionPolicyHash"] = Encode(new byte[32]));
        AssertInvalidSigned(writer, Raw(changedPolicy), ContentValidationFailure.PolicyMismatch);
    }

    [Fact]
    public void UnknownKeysAreResolvedLocallyAndKeyIdIsAuthenticatedEvenForTheSamePublicKey()
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(providers: probe);
        byte[] signed = SignBytes(processor, Document);
        foreach (string keyId in new[] { "unknown", keys.Signer.KeyId.ToUpperInvariant(), "https://example.invalid/untrusted-key" })
        {
            probe.Clear();
            Failure(processor, ContentValidationFailure.UnknownKey,
                () => processor.Validate(Raw(EditEnvelope(signed, envelope => envelope["kid"] = keyId))));
            Assert.Equal(new[] { "resolve" }, probe.Calls);
            Assert.Equal(keyId, probe.ResolvedKeyId);
        }
        probe.ResolveAnyKey = true;
        probe.VerifierKeyId = "alias-for-same-public-key";
        string alias = EditEnvelope(signed, envelope => envelope["kid"] = probe.VerifierKeyId);
        AssertInvalidSigned(processor, Raw(alias), ContentValidationFailure.InvalidSignature);
    }

    [Theory]
    [InlineData("signature", 64)]
    [InlineData("exclusionPolicyHash", 32)]
    public void Base64UrlRequiresExactLengthAlphabetNoPaddingAndCanonicalUnusedBits(string field, int byteLength)
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(providers: probe);
        byte[] signed = SignBytes(processor, Document);
        string valid = Object(signed)[EnvelopeName]![field]!.GetValue<string>();
        AssertCanonicalEncoding(valid, byteLength);
        string unusedBits = valid[..^1] + Alphabet[Alphabet.IndexOf(valid[^1]) + 1];
        Assert.Equal(Decode(valid), Decode(unusedBits)); // Same bytes are insufficient: the text must be canonical.
        string[] invalid =
        [
            valid + "=", valid + "==", valid[..^1], valid + "A", "+" + valid[1..], "/" + valid[1..],
            " " + valid[1..], valid[..^1] + "\n", "é" + valid[1..], "=" + valid[1..], unusedBits,
            Encode(new byte[byteLength - 1]), Encode(new byte[byteLength + 1])
        ];
        foreach (string value in invalid)
            AssertBadEnvelope(processor, probe, EditEnvelope(signed, envelope => envelope[field] = value), ContentValidationFailure.InvalidSignature);
    }

    [Fact]
    public void CanonicallyEncodedButIncorrectSignaturesFailCryptographicVerification()
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        byte[] signed = SignBytes(processor, Document);
        byte[] altered = Decode(Object(signed)[EnvelopeName]!["signature"]!.GetValue<string>());
        altered[0] ^= 1;
        foreach (byte[] signature in new[] { altered, new byte[64], Enumerable.Repeat((byte)0xFF, 64).ToArray() })
            AssertInvalidSigned(processor, Raw(EditEnvelope(signed, envelope => envelope["signature"] = Encode(signature))), ContentValidationFailure.InvalidSignature);
        using Keys wrongKeys = new();
        AssertInvalidSigned(wrongKeys.Create(canSign: false), new(signed), ContentValidationFailure.InvalidSignature);
    }

    [Fact]
    public void RawDuplicatesAndInvalidUnicodeAreRejectedBeforeFilteringOrCanonicalization()
    {
        using Keys keys = new();
        Probe probe = new(keys) { PermissiveCanonicalizer = true };
        ContentValidationProcessor processor = keys.Create(new() { AdditionalIgnoredRootProperties = ["scratch"] }, providers: probe);
        string[] invalid =
        [
            "{\"id\":\"item\",\"pk\":1,\"pk\":2}",
            "{\"id\":\"item\",\"pk\":1,\"\\u0070k\":2}",
            "{\"id\":\"item\",\"pk\":1,\"_etag\":0,\"\\u005fetag\":1}",
            "{\"id\":\"item\",\"pk\":1,\"_etag\":{\"x\":0,\"\\u0078\":1}}",
            "{\"id\":\"item\",\"pk\":1,\"scratch\":[{\"x\":0,\"x\":1}]}",
            "{\"id\":\"item\",\"pk\":1,\"_contentValidation\":{\"v\":1,\"\\u0076\":1}}",
            "{\"id\":\"item\",\"pk\":1,\"_etag\":\"\\uD800\"}",
            "{\"id\":\"item\",\"pk\":1,\"scratch\":\"\\uDC00\"}",
            "{\"id\":\"item\",\"pk\":1,\"scratch\":{\"\\uD800\":1}}",
            "{\"id\":\"item\",\"pk\":1,\"_etag\":\"\\uD800x\"}",
            "{\"id\":\"item\",\"pk\":1,\"_etag\":\"\\uDC00\\uD800\"}"
        ];
        foreach (string document in invalid)
            AssertRawRejected(processor, probe, Encoding.UTF8.GetBytes(document));
        foreach (byte[] malformed in new byte[][] { [0xFF], [0xC0, 0xAF], [0xE2, 0x82], [0xED, 0xA0, 0x80] })
        {
            AssertRawRejected(processor, probe, [.. Encoding.UTF8.GetBytes("{\"id\":\"item\",\"pk\":1,\"_etag\":\""), .. malformed, .. "\"}"u8.ToArray()]);
            AssertRawRejected(processor, probe, [.. Encoding.UTF8.GetBytes("{\"id\":\"item\",\"pk\":1,\"scratch\":{\""), .. malformed, .. "\":1}}"u8.ToArray()]);
        }
    }

    [Fact]
    public void ValidUnicodeEscapesAndCaseDistinctNamesRemainSupported()
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        const string document = "{\"id\":\"item-\\uD83D\\uDE80\",\"pk\":1,\"name\":1,\"Name\":2,\"é\":3,\"e\\u0301\":4,\"value\":\"\\uFFFD\"}";
        byte[] signed = SignBytes(processor, document);
        processor.Validate(new(signed));
        string escapedName = Encoding.UTF8.GetString(signed).Replace("\"name\"", "\"\\u006eame\"", StringComparison.Ordinal);
        processor.Validate(Raw(escapedName));
        AssertInvalidSigned(processor, Raw(Edit(signed, root => root["Name"] = 1)), ContentValidationFailure.InvalidSignature);
    }

    [Theory]
    [InlineData("9007199254740992")]
    [InlineData("-9007199254740992")]
    [InlineData("9007199254740992.0")]
    [InlineData("9.007199254740992e15")]
    [InlineData("9007199254740991.9")]
    [InlineData("1e100")]
    [InlineData("1e309")]
    [InlineData("-1e309")]
    [InlineData("1e-999")]
    [InlineData("-1e-999")]
    [InlineData("0.00001e-999")]
    public void UnsafeNumericNotationsFailBeforeCanonicalizationEvenInExcludedSubtrees(string number)
    {
        using Keys keys = new();
        Probe probe = new(keys) { PermissiveCanonicalizer = true };
        ContentValidationProcessor processor = keys.Create(new() { AdditionalIgnoredRootProperties = ["scratch"] }, providers: probe);
        foreach (string property in new[] { "value", "_etag", "scratch" })
            AssertRawRejected(processor, probe, Encoding.UTF8.GetBytes("{\"id\":\"item\",\"pk\":1,\"" + property + "\":[{\"number\":" + number + "}]}"));
    }

    [Fact]
    public void DecimalUnderflowWithoutAnExponentIsStillRejected()
    {
        using Keys keys = new();
        Probe probe = new(keys) { PermissiveCanonicalizer = true };
        ContentValidationProcessor processor = keys.Create(providers: probe);
        string number = "0." + new string('0', 400) + "1";
        AssertRawRejected(processor, probe, Encoding.UTF8.GetBytes("{\"id\":\"item\",\"pk\":1,\"_etag\":" + number + "}"));
    }

    [Theory]
    [InlineData("9007199254740991")]
    [InlineData("-9007199254740991")]
    [InlineData("9007199254740991.0")]
    [InlineData("9.007199254740991e15")]
    [InlineData("0e-999")]
    [InlineData("-0.000e999")]
    [InlineData("5e-324")]
    [InlineData("1.234567890123456789")]
    public void SupportedBinary64NumbersRoundTrip(string number)
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        processor.Validate(new(SignBytes(processor, "{\"id\":\"item\",\"pk\":1,\"value\":" + number + "}")));
    }

    [Theory]
    [InlineData("value")]
    [InlineData("_etag")]
    public void Depth64IncludesTheWholeDocumentAndDepth65FailsEvenWhenIgnored(string property)
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        string deepest = DeepDocument(64, property);
        byte[] signed = SignBytes(processor, deepest);
        processor.Validate(new(signed));
        using (RecyclableMemoryStream stripped = processor.ValidateAndStrip(new(signed)))
        using (JsonDocument tree = JsonDocument.Parse(stripped.GetReadOnlySequence(), new JsonDocumentOptions { MaxDepth = 64 }))
            Assert.Equal(JsonValueKind.Object, tree.RootElement.ValueKind);
        using (RecyclableMemoryStream strippedArray = processor.ValidateAndStrip(Raw("[" + Encoding.UTF8.GetString(signed) + "]"), allowArray: true))
        using (JsonDocument tree = JsonDocument.Parse(strippedArray.GetReadOnlySequence(), new JsonDocumentOptions { MaxDepth = 65 }))
            Assert.Equal(JsonValueKind.Array, tree.RootElement.ValueKind);
        Failure(processor, ContentValidationFailure.InvalidDocument, () => SignBytes(processor, DeepDocument(65, property)));
        AssertInvalidSigned(processor, Raw(DeepDocument(65, property)), ContentValidationFailure.InvalidDocument);
        Failure(processor, ContentValidationFailure.InvalidDocument, () =>
        {
            using RecyclableMemoryStream result = processor.ValidateAndStrip(Raw("[" + DeepDocument(65, property) + "]"), allowArray: true);
        });
    }

    [Theory]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("1")]
    [InlineData("true")]
    [InlineData("\"text\"")]
    [InlineData("[]")]
    [InlineData("{}")] // Object syntax alone does not supply identity.
    [InlineData("{\"id\":\"item\",\"pk\":1,}")]
    [InlineData("{\"id\":\"item\",/*comment*/\"pk\":1}")]
    [InlineData("{\"id\":\"item\",\"pk\":1} {}")]
    public void NonDocumentsAndUnsupportedJsonSyntaxAreRejected(string json)
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        Failure(processor, ContentValidationFailure.InvalidDocument, () => SignBytes(processor, json));
        AssertInvalidSigned(processor, Raw(json), ContentValidationFailure.InvalidDocument);
        if (json != "[]")
            Failure(processor, ContentValidationFailure.InvalidDocument, () =>
            {
                using RecyclableMemoryStream result = processor.ValidateAndStrip(Raw(json), allowArray: true);
            });
    }

    [Fact]
    public void ArraysRequireExplicitOptInValidateEveryItemAndPreserveOrder()
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(providers: probe);
        byte[] first = SignBytes(processor, Document);
        byte[] second = SignBytes(processor, "{\"id\":\"second\",\"pk\":null,\"_etag\":\"service\"}");
        byte[] array = Encoding.UTF8.GetBytes("[" + Encoding.UTF8.GetString(first) + "," + Encoding.UTF8.GetString(second) + "]");
        byte[] snapshot = (byte[])array.Clone();
        AssertInvalidSigned(processor, new(array), ContentValidationFailure.InvalidDocument);
        Failure(processor, ContentValidationFailure.InvalidDocument, () => SignBytes(processor, new ReadOnlySequence<byte>(array)));
        probe.Clear();
        using (RecyclableMemoryStream stripped = processor.ValidateAndStrip(new(array), allowArray: true))
        {
            Assert.Equal(0L, stripped.Position);
            JsonArray documents = JsonNode.Parse(stripped.GetReadOnlySequence().ToArray())!.AsArray();
            Assert.Collection(documents,
                item => Assert.True(JsonNode.DeepEquals(Object(Document), item)),
                item => Assert.True(JsonNode.DeepEquals(Object("{\"id\":\"second\",\"pk\":null,\"_etag\":\"service\"}"), item)));
            Assert.Equal(new[] { "resolve", "canonicalize-document", "canonicalize-header", "hash", "verify",
                "resolve", "canonicalize-document", "canonicalize-header", "hash", "verify" }, probe.Calls);
        }
        Assert.Equal(snapshot, array);
        using (RecyclableMemoryStream empty = processor.ValidateAndStrip(Raw("[]"), allowArray: true))
            Assert.Equal("[]", Encoding.UTF8.GetString(empty.GetReadOnlySequence().ToArray()));
        using (RecyclableMemoryStream single = processor.ValidateAndStrip(new(first), allowArray: true))
            Assert.True(JsonNode.DeepEquals(Object(Document), Object(single.GetReadOnlySequence().ToArray())));
    }

    [Fact]
    public void AnInvalidLaterArrayItemProducesNoPartialResultAndLeaksNoBuffers()
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(providers: probe);
        byte[] first = SignBytes(processor, Document);
        string later = Edit(first, root => root["value"] = 2);
        probe.Clear();
        Failure(processor, ContentValidationFailure.InvalidSignature, () =>
        {
            using RecyclableMemoryStream result = processor.ValidateAndStrip(Raw("[" + Encoding.UTF8.GetString(first) + "," + later + "]"), allowArray: true);
        });
        Assert.Equal(new[] { "resolve", "canonicalize-document", "canonicalize-header", "hash", "verify",
            "resolve", "canonicalize-document", "canonicalize-header", "hash", "verify" }, probe.Calls);

        foreach (string invalid in new[] { "null", "1", "[]", "\"text\"", "{\"id\":\"item\",\"pk\":1,\"_etag\":{\"x\":1,\"x\":2}}" })
        {
            probe.Clear();
            Failure(processor, ContentValidationFailure.InvalidDocument, () =>
            {
                using RecyclableMemoryStream result = processor.ValidateAndStrip(Raw("[" + Encoding.UTF8.GetString(first) + "," + invalid + "]"), allowArray: true);
            });
            Assert.Empty(probe.Calls); // Raw validation of the entire array precedes even the first resolver call.
        }
        Failure(processor, ContentValidationFailure.MissingSignature, () =>
        {
            using RecyclableMemoryStream result = processor.ValidateAndStrip(Raw("[" + Encoding.UTF8.GetString(first) + "," + Document + "]"), allowArray: true);
        });
    }

    [Fact]
    public void DocumentLimitsIncludeTheEnvelopeAndRawWhitespaceWithExactBoundarySuccess()
    {
        using Keys keys = new();
        byte[] signed = SignBytes(keys.Create(), Document);
        ContentValidationProcessor exact = keys.Create(new() { MaxDocumentBytes = signed.Length, MaxBufferedBytes = 16384 });
        byte[] exactSigned = SignBytes(exact, Document);
        Assert.Equal(signed.Length, exactSigned.Length);
        exact.Validate(new(signed));
        using (RecyclableMemoryStream stripped = exact.ValidateAndStrip(new(signed)))
            Assert.Equal(0L, stripped.Position);
        AssertInvalidSigned(exact, Raw(" " + Encoding.UTF8.GetString(signed)), ContentValidationFailure.PayloadTooLarge);

        ContentValidationProcessor tooSmall = keys.Create(new() { MaxDocumentBytes = signed.Length - 1, MaxBufferedBytes = 16384 });
        Failure(tooSmall, ContentValidationFailure.PayloadTooLarge, () => SignBytes(tooSmall, Document));
        AssertInvalidSigned(tooSmall, new(signed), ContentValidationFailure.PayloadTooLarge);
        ContentValidationProcessor inputLimit = keys.Create(new() { MaxDocumentBytes = Encoding.UTF8.GetByteCount(Document) - 1, MaxBufferedBytes = 16384 });
        Failure(inputLimit, ContentValidationFailure.PayloadTooLarge, () => SignBytes(inputLimit, Document));
    }

    [Fact]
    public void StripOutputLimitIsCheckedAfterVerificationEvenWhenEscapingExpandsTheOutput()
    {
        using Keys keys = new();
        JsonObject document = Object(Document);
        document["text"] = new string('\u2028', 300);
        byte[] signed = SignBytes(keys.Create(), document.ToJsonString());
        // U+2028 is valid raw JSON but Utf8JsonWriter escapes it even with UnsafeRelaxedJsonEscaping.
        string compact = Encoding.UTF8.GetString(signed).Replace("\\u2028", "\u2028", StringComparison.Ordinal);
        int wireLength = Encoding.UTF8.GetByteCount(compact);
        Assert.True(wireLength < signed.Length);
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(new() { MaxDocumentBytes = wireLength, MaxBufferedBytes = 16384 }, providers: probe);
        processor.Validate(Raw(compact));
        probe.Clear();
        Failure(processor, ContentValidationFailure.PayloadTooLarge, () =>
        {
            using RecyclableMemoryStream result = processor.ValidateAndStrip(Raw(compact));
        });
        Assert.Equal(new[] { "resolve", "canonicalize-document", "canonicalize-header", "hash", "verify" }, probe.Calls);
    }

    [Fact]
    public void ArraysEnforcePerDocumentAndAggregateBufferLimitsSeparately()
    {
        using Keys keys = new();
        JsonObject document = Object(Document);
        document["payload"] = new string('x', 500);
        byte[] signed = SignBytes(keys.Create(), document.ToJsonString());
        string array = "[" + Encoding.UTF8.GetString(signed) + "," + Encoding.UTF8.GetString(signed) + "]";
        ContentValidationProcessor perDocument = keys.Create(new() { MaxDocumentBytes = signed.Length, MaxBufferedBytes = 16384 });
        using (RecyclableMemoryStream stripped = perDocument.ValidateAndStrip(Raw(array), allowArray: true))
            Assert.True(stripped.Length > perDocument.MaxDocumentBytes);
        Failure(perDocument, ContentValidationFailure.PayloadTooLarge, () =>
        {
            // Whitespace inside an item belongs to that item's raw size budget.
            using RecyclableMemoryStream result = perDocument.ValidateAndStrip(Raw("[{ " + Encoding.UTF8.GetString(signed)[1..] + "]"), allowArray: true);
        });
        ContentValidationProcessor aggregate = keys.Create(new() { MaxDocumentBytes = signed.Length, MaxBufferedBytes = 16384 });
        string oversizedArray = "[" + string.Join(',', Enumerable.Repeat(Encoding.UTF8.GetString(signed), 32)) + "]";
        Assert.True(Encoding.UTF8.GetByteCount(oversizedArray) > aggregate.Buffers.MaxBufferBytes);
        Failure(aggregate, ContentValidationFailure.PayloadTooLarge, () =>
        {
            using RecyclableMemoryStream result = aggregate.ValidateAndStrip(Raw(oversizedArray), allowArray: true);
        });
    }

    [Fact]
    public void Tiny1024ByteBufferLimitDoesNotRejectValidSmallOperationsBecauseOfPoolBlockSize()
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create(new() { MaxDocumentBytes = 1024, MaxBufferedBytes = 1024 });
        for (int iteration = 0; iteration < 8; iteration++)
        {
            byte[] signed = SignBytes(processor, Document);
            processor.Validate(new(signed));
            using (RecyclableMemoryStream stripped = processor.ValidateAndStrip(new(signed)))
                Assert.True(JsonNode.DeepEquals(Object(Document), Object(stripped.GetReadOnlySequence().ToArray())));
            Assert.Equal(0L, processor.Buffers.InUseBytes);
        }
    }

    [Theory]
    [InlineData("canonicalize-document")]
    [InlineData("canonicalize-header")]
    public void CanonicalIntermediateLimitStopsProvidersAndReleasesAllLeases(string stage)
    {
        using Keys keys = new();
        Probe probe = new(keys) { ExpansionStage = stage, ExpansionBytes = 16385 };
        ContentValidationProcessor processor = keys.Create(new() { MaxDocumentBytes = 4096, MaxBufferedBytes = 16384 }, providers: probe);
        Failure(processor, ContentValidationFailure.PayloadTooLarge, () => SignBytes(processor, Document));
        Assert.DoesNotContain("hash", probe.Calls);
        Assert.DoesNotContain("sign", probe.Calls);
        byte[] signed = SignBytes(keys.Create(), Document);
        Failure(processor, ContentValidationFailure.PayloadTooLarge, () => processor.Validate(new(signed)));
        Assert.DoesNotContain("verify", probe.Calls);
    }

    [Fact]
    public void ProtocolWrapperCountsAgainstTheIntermediateBudget()
    {
        using Keys keys = new();
        Probe probe = new(keys) { ExpansionStage = "canonicalize-document", ExpansionBytes = 16384 };
        ContentValidationProcessor processor = keys.Create(new() { MaxDocumentBytes = 16384, MaxBufferedBytes = 16384 }, providers: probe);
        Failure(processor, ContentValidationFailure.PayloadTooLarge, () => SignBytes(processor, Document));
        Assert.DoesNotContain("hash", probe.Calls);
    }

    [Fact]
    public void OversizedHeaderIsBoundedBeforeCanonicalizationHashingOrSigning()
    {
        using Keys keys = new();
        Probe probe = new(keys) { SignerKeyId = new string('k', 17000) };
        ContentValidationProcessor processor = keys.Create(new() { MaxDocumentBytes = 4096, MaxBufferedBytes = 16384 }, providers: probe);
        Failure(processor, ContentValidationFailure.PayloadTooLarge, () => SignBytes(processor, Document));
        Assert.Empty(probe.Calls);
    }

    [Theory]
    [InlineData("canonicalization")]
    [InlineData("hash-algorithm")]
    [InlineData("hash-size")]
    [InlineData("signing-algorithm")]
    public void IncompatibleTrustedProfilesAreRejectedAtConstructionAndWhenTheyChange(string member)
    {
        using Keys keys = new();
        Probe incompatible = new(keys);
        BreakProfile(incompatible, member);
        ContentValidationException construction = Assert.Throws<ContentValidationException>(() => keys.Create(providers: incompatible));
        Assert.Equal(ContentValidationFailure.UnsupportedProfile, construction.Failure);
        Assert.Empty(incompatible.Calls);

        Probe mutable = new(keys);
        ContentValidationProcessor processor = keys.Create(providers: mutable);
        byte[] signed = SignBytes(processor, Document);
        mutable.Clear();
        BreakProfile(mutable, member);
        Failure(processor, ContentValidationFailure.UnsupportedProfile, () => SignBytes(processor, Document));
        AssertInvalidSigned(processor, new(signed), ContentValidationFailure.UnsupportedProfile);
        Assert.Empty(mutable.Calls);
    }

    [Fact]
    public void SigningKeyIdentityIsValidatedAndFrozen()
    {
        using Keys keys = new();
        foreach (string? keyId in new[] { null, "", " \t", "\uD800" })
        {
            Probe invalid = new(keys) { SignerKeyId = keyId! };
            Assert.Throws<ArgumentException>(() => keys.Create(providers: invalid));
        }
        Probe mutable = new(keys);
        ContentValidationProcessor processor = keys.Create(providers: mutable);
        mutable.SignerKeyId = "changed-after-construction";
        Failure(processor, ContentValidationFailure.UnsupportedProfile, () => SignBytes(processor, Document));
        Assert.Empty(mutable.Calls);
    }

    [Fact]
    public void ResolverProviderKeyMismatchAndAlgorithmMismatchHaveDistinctFailures()
    {
        using Keys keys = new();
        byte[] signed = SignBytes(keys.Create(), Document);
        Probe wrongKey = new(keys) { VerifierKeyId = "wrong-key-id" };
        ContentValidationProcessor wrongKeyProcessor = keys.Create(canSign: false, providers: wrongKey);
        Assert.Throws<InvalidOperationException>(() => wrongKeyProcessor.Validate(new(signed)));
        Assert.Equal(0L, wrongKeyProcessor.Buffers.InUseBytes);
        Assert.Equal(new[] { "resolve" }, wrongKey.Calls);
        Probe wrongAlgorithm = new(keys) { VerificationAlgorithm = "ECDSA-P384" };
        ContentValidationProcessor wrongAlgorithmProcessor = keys.Create(canSign: false, providers: wrongAlgorithm);
        Failure(wrongAlgorithmProcessor, ContentValidationFailure.UnsupportedProfile, () => wrongAlgorithmProcessor.Validate(new(signed)));
        Assert.Equal(new[] { "resolve" }, wrongAlgorithm.Calls);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void InvalidPolicyDigestFailsConstructionWithoutImplementationFallback(int length)
    {
        using Keys keys = new();
        Probe probe = new(keys) { OverrideDigest = true, DigestResult = length < 0 ? null : new byte[length] };
        Assert.Throws<InvalidOperationException>(() => keys.Create(providers: probe));
        Assert.Equal(new[] { "canonicalize-policy", "hash" }, probe.Calls);
        Assert.Single(probe.CanonicalInputs);
        Assert.Empty(probe.ValidatedInputs);
    }

    [Theory]
    [InlineData("canonicalize-policy")]
    [InlineData("hash")]
    public void PolicyProviderFailuresAbortConstructionWithoutWrappingOrFallback(string stage)
    {
        using Keys keys = new();
        Exception[] faults =
        [
            new InvalidOperationException("policy provider sentinel"), new JsonException("policy provider sentinel"),
            new FormatException("policy provider sentinel"), new CryptographicException("policy provider sentinel"),
            new ObjectDisposedException("policy provider sentinel")
        ];
        foreach (Exception fault in faults)
        {
            Probe probe = new(keys) { FaultStage = stage, Fault = fault };
            Assert.Same(fault, Record.Exception(() => keys.Create(providers: probe)));
            Assert.Equal(stage == "hash" ? new[] { "canonicalize-policy", "hash" } : new[] { "canonicalize-policy" }, probe.Calls);
            Assert.Empty(probe.ValidatedInputs);
        }
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void InvalidHasherResultsAreProviderErrorsNotDocumentFailures(int length)
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(providers: probe);
        // Policy hashing already completed successfully; exercise document hashing failures separately.
        probe.OverrideDigest = true;
        probe.DigestResult = length < 0 ? null : new byte[length];
        Assert.Throws<InvalidOperationException>(() => SignBytes(processor, Document));
        Assert.Equal(0L, processor.Buffers.InUseBytes);
        Assert.DoesNotContain("sign", probe.Calls);
        byte[] signed = SignBytes(keys.Create(), Document);
        Assert.Throws<InvalidOperationException>(() => processor.Validate(new(signed)));
        Assert.Throws<InvalidOperationException>(() =>
        {
            using RecyclableMemoryStream result = processor.ValidateAndStrip(new(signed));
        });
        Assert.Equal(0L, processor.Buffers.InUseBytes);
        Assert.DoesNotContain("verify", probe.Calls);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(65)]
    [InlineData(72)]
    public void InvalidSignerResultsAreProviderErrorsAndDoNotLeak(int length)
    {
        using Keys keys = new();
        Probe probe = new(keys) { OverrideSignature = true, SignatureResult = length < 0 ? null : new byte[length] };
        ContentValidationProcessor processor = keys.Create(providers: probe);
        Assert.Throws<InvalidOperationException>(() => SignBytes(processor, Document));
        Assert.Equal(0L, processor.Buffers.InUseBytes);
        Assert.Equal(new[] { "canonicalize-document", "canonicalize-header", "hash", "sign" }, probe.Calls);
    }

    [Theory]
    [InlineData("canonicalize-document")]
    [InlineData("canonicalize-header")]
    [InlineData("hash")]
    [InlineData("sign")]
    [InlineData("resolve")]
    [InlineData("verify")]
    public void TrustedProviderExceptionsPropagateUnwrappedAndDisposeIntermediateBuffers(string stage)
    {
        using Keys keys = new();
        byte[] signed = SignBytes(keys.Create(), Document);
        Exception[] faults =
        [
            new InvalidOperationException("provider sentinel"), new JsonException("provider sentinel"),
            new FormatException("provider sentinel"), new CryptographicException("provider sentinel"),
            new ObjectDisposedException("provider sentinel")
        ];
        foreach (Exception fault in faults)
        {
            Probe probe = new(keys);
            ContentValidationProcessor processor = keys.Create(providers: probe);
            probe.FaultStage = stage;
            probe.Fault = fault;
            if (stage is not ("resolve" or "verify"))
            {
                Exception? actual = Record.Exception(() => SignBytes(processor, Document));
                Assert.Same(fault, actual);
                Assert.Equal(0L, processor.Buffers.InUseBytes);
            }
            if (stage != "sign")
            {
                Assert.Same(fault, Record.Exception(() => processor.Validate(new(signed))));
                Assert.Equal(0L, processor.Buffers.InUseBytes);
                Assert.Same(fault, Record.Exception(() =>
                {
                    using RecyclableMemoryStream result = processor.ValidateAndStrip(new(signed));
                }));
                Assert.Equal(0L, processor.Buffers.InUseBytes);
            }
        }
    }

    [Fact]
    public void ActualDisposedProvidersRemainCallerOwnedAndThrowProviderFailures()
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        byte[] signed = SignBytes(processor, Document);
        keys.Signer.Dispose();
        Assert.Throws<ObjectDisposedException>(() => SignBytes(processor, Document));
        processor.Validate(new(signed)); // A disposed signer does not disable independent verification.
        keys.Verifier.Dispose();
        Assert.Throws<ObjectDisposedException>(() => processor.Validate(new(signed)));
        Assert.Equal(0L, processor.Buffers.InUseBytes);
    }

    [Fact]
    public void StagesCanonicalizeFilteredDocumentThenHeaderHashOnceAndPassDigestToCrypto()
    {
        using Keys keys = new();
        Probe probe = new(keys);
        ContentValidationProcessor processor = keys.Create(new() { AdditionalIgnoredRootProperties = ["scratch"] }, providers: probe, recordConstruction: true);
        Assert.Equal(new[] { "canonicalize-policy", "hash" }, probe.Calls);
        Assert.Empty(probe.ValidatedInputs); // No raw document has been submitted yet.
        JsonObject policy = Object(Assert.Single(probe.CanonicalInputs));
        Assert.Equal("root", policy["scope"]!.GetValue<string>());
        Assert.Equal(1, policy["version"]!.GetValue<int>());
        Assert.Equal(ServiceFields.Append("scratch").Order(StringComparer.Ordinal),
            policy["ignoredProperties"]!.AsArray().Select(name => name!.GetValue<string>()));
        const string expectedPolicy = "{\"ignoredProperties\":[\"_attachments\",\"_etag\",\"_rid\",\"_self\",\"_ts\",\"scratch\"],\"scope\":\"root\",\"version\":1}";
        Assert.Equal(Encoding.UTF8.GetBytes(expectedPolicy), probe.HashedBytes);
        Assert.Equal(Encode(SHA256.HashData(probe.HashedBytes!)), processor.ExclusionPolicyHash);
        probe.Clear(); // Document operations start after the one-time injected policy computation.
        byte[] signed = SignBytes(processor, "{\"value\":1,\"pk\":\"tenant\",\"id\":\"item\",\"_etag\":\"ignored\",\"scratch\":{\"x\":2},\"nested\":{\"_etag\":\"protected\"}}");
        Assert.Equal(new[] { "canonicalize-document", "canonicalize-header", "hash", "sign" }, probe.Calls);
        Assert.Collection(probe.CanonicalInputs,
            input => Assert.True(JsonNode.DeepEquals(Object("{\"id\":\"item\",\"pk\":\"tenant\",\"value\":1,\"nested\":{\"_etag\":\"protected\"}}"), Object(input))),
            input => Assert.Equal(EnvelopeFields.Where(field => field != "signature").Order(StringComparer.Ordinal), Object(input).Select(property => property.Key).Order(StringComparer.Ordinal)));
        string expected = "{\"document\":{\"id\":\"item\",\"nested\":{\"_etag\":\"protected\"},\"pk\":\"tenant\",\"value\":1},\"domain\":\"CosmosContentValidation\",\"header\":{\"canonicalization\":\""
            + Profile + "\",\"exclusionPolicyHash\":\"" + processor.ExclusionPolicyHash + "\",\"hashAlgorithm\":\"SHA-256\",\"kid\":\""
            + keys.Signer.KeyId + "\",\"signatureAlgorithm\":\"" + SignatureAlgorithm + "\",\"v\":1}}";
        Assert.Equal(Encoding.UTF8.GetBytes(expected), probe.HashedBytes);
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
        Assert.Equal(digest, probe.SignedDigest);
        byte[] signature = Decode(Object(signed)[EnvelopeName]!["signature"]!.GetValue<string>());

        probe.Clear();
        processor.Validate(new(signed));
        Assert.Equal(new[] { "resolve", "canonicalize-document", "canonicalize-header", "hash", "verify" }, probe.Calls);
        Assert.Equal(Encoding.UTF8.GetBytes(expected), probe.HashedBytes);
        Assert.Equal(digest, probe.VerifiedDigest);
        Assert.Equal(signature, probe.VerifiedSignature);
        Assert.Equal(0L, processor.Buffers.InUseBytes);
        // Independent prehashed/P1363 versus double-hashed crypto interoperability is covered in CryptoTests.
    }

    [Fact]
    public async Task SharedProcessorSupportsConcurrentSigningValidationAndFailureWithoutLeaks()
    {
        using Keys keys = new();
        ContentValidationProcessor processor = keys.Create();
        await Task.WhenAll(Enumerable.Range(0, 16).Select(index => Task.Run(() =>
        {
            for (int iteration = 0; iteration < 8; iteration++)
            {
                JsonObject document = Object(Document);
                document["id"] = $"item-{index}-{iteration}";
                document["payload"] = new string((char)('a' + index), 18000 + iteration);
                byte[] signed = SignBytes(processor, document.ToJsonString());
                processor.Validate(new(signed));
                using (RecyclableMemoryStream stripped = processor.ValidateAndStrip(new(signed)))
                {
                    Assert.Equal(0L, stripped.Position);
                    Assert.True(JsonNode.DeepEquals(document, Object(stripped.GetReadOnlySequence().ToArray())));
                }
                ContentValidationException exception = Assert.Throws<ContentValidationException>(
                    () => processor.Validate(Raw(Edit(signed, root => root["value"] = 2))));
                Assert.Equal(ContentValidationFailure.InvalidSignature, exception.Failure);
            }
        })));
        // Only assert pool quiescence after every worker has returned its leases.
        Assert.Equal(0L, processor.Buffers.InUseBytes);
    }

    [Fact]
    public void PublicProcessorApiIsSynchronousAndUsesBorrowedSequences()
    {
        Type type = typeof(ContentValidationProcessor);
        ConstructorInfo constructor = Assert.Single(type.GetConstructors());
        Assert.Equal(new[] { typeof(ContentValidationOptions), typeof(IVerificationKeyResolver), typeof(IJsonCanonicalizer), typeof(IContentHasher), typeof(IContentSigner) },
            constructor.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.All(constructor.GetParameters().Take(4), parameter => Assert.False(parameter.IsOptional));
        Assert.True(constructor.GetParameters()[4].IsOptional);
        Assert.Null(constructor.GetParameters()[4].DefaultValue);
        MethodInfo validation = typeof(IJsonCanonicalizer).GetMethod(nameof(IJsonCanonicalizer.ValidateInput))!;
        Assert.True(validation.IsAbstract); // A provider cannot inherit a permissive default implementation.
        Assert.Equal(typeof(void), validation.ReturnType);
        Assert.Equal(typeof(JsonElement), Assert.Single(validation.GetParameters()).ParameterType);
        MethodInfo[] operations = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(method => !method.IsSpecialName).OrderBy(method => method.Name, StringComparer.Ordinal).ToArray();
        Assert.Equal(new[] { "Sign", "Validate", "ValidateAndStrip" }, operations.Select(method => method.Name));
        Assert.All(operations, method =>
        {
            Assert.Equal(typeof(ReadOnlySequence<byte>), method.GetParameters()[0].ParameterType);
            Assert.Null(method.GetCustomAttribute<System.Runtime.CompilerServices.AsyncStateMachineAttribute>());
            Assert.Equal(method.Name == "Validate" ? typeof(void) : typeof(RecyclableMemoryStream), method.ReturnType);
        });
        foreach (MethodInfo method in operations.Where(method => method.Name != "Validate"))
        {
            ParameterInfo flag = method.GetParameters()[1];
            Assert.Equal(typeof(bool), flag.ParameterType);
            Assert.True(flag.IsOptional);
            Assert.False(Assert.IsType<bool>(flag.DefaultValue));
        }
    }

    private static ReadOnlySequence<byte> Raw(string json) => new(Encoding.UTF8.GetBytes(json));
    private static JsonObject Object(string json) => JsonNode.Parse(json)!.AsObject();
    private static JsonObject Object(byte[] json) => JsonNode.Parse(json)!.AsObject();
    private static byte[] SignBytes(ContentValidationProcessor processor, string json) => SignBytes(processor, Raw(json));

    private static byte[] SignBytes(ContentValidationProcessor processor, ReadOnlySequence<byte> json, bool replace = false)
    {
        using RecyclableMemoryStream signed = processor.Sign(json, replace);
        Assert.Equal(0L, signed.Position);
        return signed.GetReadOnlySequence().ToArray(); // Never call the pool's deliberately disabled Stream.ToArray().
    }

    private static string Edit(byte[] json, Action<JsonObject> change) => Edit(Encoding.UTF8.GetString(json), change);

    private static string Edit(string json, Action<JsonObject> change)
    {
        JsonObject root = Object(json);
        change(root);
        return root.ToJsonString();
    }

    private static string EditEnvelope(byte[] signed, Action<JsonObject> change) => Edit(signed, root => change(root[EnvelopeName]!.AsObject()));
    private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));

    private static void AssertCanonicalEncoding(string value, int byteLength)
    {
        Assert.Equal((byteLength * 8 + 5) / 6, value.Length);
        Assert.All(value, character => Assert.Contains(character, Alphabet));
        byte[] decoded = Decode(value);
        Assert.Equal(byteLength, decoded.Length);
        Assert.Equal(value, Encode(decoded));
    }

    private static ContentValidationException Failure(ContentValidationProcessor processor, ContentValidationFailure expected, Action action)
    {
        ContentValidationException exception = Assert.Throws<ContentValidationException>(action);
        Assert.Equal(expected, exception.Failure);
        Assert.Equal(0L, processor.Buffers.InUseBytes);
        return exception;
    }

    private static void AssertInvalidSigned(ContentValidationProcessor processor, ReadOnlySequence<byte> json, ContentValidationFailure expected)
    {
        byte[] snapshot = json.ToArray();
        Failure(processor, expected, () => processor.Validate(json));
        Failure(processor, expected, () =>
        {
            using RecyclableMemoryStream result = processor.ValidateAndStrip(json);
        });
        Assert.Equal(snapshot, json.ToArray());
    }

    private static void AssertBadEnvelope(ContentValidationProcessor processor, Probe probe, string json, ContentValidationFailure expected)
    {
        probe.Clear();
        AssertInvalidSigned(processor, Raw(json), expected);
        Failure(processor, expected, () => SignBytes(processor, Raw(json), replace: true));
        Assert.Empty(probe.Calls); // Replacement skips old crypto, but not envelope/policy compatibility checks.
    }

    private static void AssertRawRejected(ContentValidationProcessor processor, Probe probe, byte[] json)
    {
        probe.Clear();
        byte[] snapshot = (byte[])json.Clone();
        Failure(processor, ContentValidationFailure.InvalidDocument, () => SignBytes(processor, new ReadOnlySequence<byte>(json), replace: true));
        AssertInvalidSigned(processor, new(json), ContentValidationFailure.InvalidDocument);
        Assert.Equal(snapshot, json);
        Assert.Empty(probe.Calls);
    }

    private static string DeepDocument(int depth, string property) => "{\"id\":\"item\",\"pk\":1,\"" + property + "\":"
        + new string('[', depth - 1) + "0" + new string(']', depth - 1) + "}";

    private static ReadOnlySequence<byte> Borrow(byte[] backing, bool segmented)
    {
        if (!segmented) return new(backing.AsMemory(1, backing.Length - 2));
        int firstLength = Math.Min(17, backing.Length - 1);
        Segment first = new(backing.AsMemory(0, firstLength));
        Segment last = first.Append(ReadOnlyMemory<byte>.Empty);
        for (int offset = firstLength; offset < backing.Length;)
        {
            int length = Math.Min(4093, backing.Length - offset);
            last = last.Append(backing.AsMemory(offset, length));
            offset += length;
        }
        return new(first, 1, last, last.Memory.Length - 1);
    }

    private static void BreakProfile(Probe probe, string member)
    {
        switch (member)
        {
            case "canonicalization": probe.CanonicalizationProfile = "other-profile"; break;
            case "hash-algorithm": probe.HashAlgorithmId = "SHA-512"; break;
            case "hash-size": probe.HashSize = 31; break;
            case "signing-algorithm": probe.SigningAlgorithm = "ECDSA-P384"; break;
            default: throw new ArgumentOutOfRangeException(nameof(member));
        }
    }

    // Per-test ownership, not an xUnit shared fixture: no persistent keys, manifests, or fixture files.
    private sealed class Keys : IDisposable
    {
        private readonly List<ContentValidationProcessor> processors = [];
        public UnsafeEcdsaContentSigner Signer { get; }
        public UnsafeEcdsaContentVerifier Verifier { get; }
        public UnsafeInMemoryVerificationKeyResolver Resolver { get; }

        public Keys()
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            Signer = new("test-key", key.ExportPkcs8PrivateKeyPem());
            try
            {
                Verifier = new("test-key", key.ExportSubjectPublicKeyInfoPem());
                Resolver = new(new[] { Verifier });
            }
            catch
            {
                Signer.Dispose();
                throw;
            }
        }

        public ContentValidationProcessor Create(ContentValidationOptions? options = null, bool canSign = true,
            Probe? providers = null, bool recordConstruction = false)
        {
            IVerificationKeyResolver resolver = providers is null ? Resolver : providers;
            IContentSigner? signer = canSign ? providers is null ? Signer : providers : null;
            ContentValidationProcessor processor = UnsafeSampleProviders.CreateProcessor(options ?? new(), resolver, signer, providers, providers);
            processors.Add(processor);
            if (providers is not null)
            {
                // Construction invokes these same providers once for the policy. Most tests inspect
                // only subsequent document calls; assert construction before resetting instrumentation.
                Assert.Equal(new[] { "canonicalize-policy", "hash" }, providers.Calls);
                if (!recordConstruction) providers.Clear();
            }
            return processor;
        }

        public void Dispose()
        {
            try
            {
                Assert.All(processors, processor => Assert.Equal(0L, processor.Buffers.InUseBytes));
            }
            finally
            {
                Signer.Dispose();
                Verifier.Dispose();
            }
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

    // Intentionally single-threaded instrumentation. The concurrency test uses the real thread-safe providers.
    private sealed class Probe : IJsonCanonicalizer, IContentHasher, IContentSigner, IContentVerifier, IVerificationKeyResolver
    {
        private readonly Keys keys;

        public Probe(Keys keys)
        {
            this.keys = keys;
            SignerKeyId = keys.Signer.KeyId;
            VerifierKeyId = keys.Verifier.KeyId;
        }

        public List<string> Calls { get; } = [];
        public List<string> CanonicalInputs { get; } = [];
        public List<string> ValidatedInputs { get; } = [];
        public Exception? ValidationFault { get; set; }
        public Action<JsonElement>? AfterValidation { get; set; }
        public string CanonicalizationProfile { get; set; } = Profile;
        public string HashAlgorithmId { get; set; } = HashAlgorithm;
        public int HashSize { get; set; } = 32;
        public string SigningAlgorithm { get; set; } = SignatureAlgorithm;
        public string VerificationAlgorithm { get; set; } = SignatureAlgorithm;
        public string SignerKeyId { get; set; }
        public string VerifierKeyId { get; set; }
        public bool ResolveAnyKey { get; set; }
        public bool PermissiveCanonicalizer { get; set; }
        public string? FaultStage { get; set; }
        public Exception? Fault { get; set; }
        public string? ExpansionStage { get; set; }
        public int ExpansionBytes { get; set; }
        public bool OverrideDigest { get; set; }
        public byte[]? DigestResult { get; set; }
        public bool OverrideSignature { get; set; }
        public byte[]? SignatureResult { get; set; }
        public string? ResolvedKeyId { get; private set; }
        public byte[]? HashedBytes { get; private set; }
        public byte[]? SignedDigest { get; private set; }
        public byte[]? VerifiedDigest { get; private set; }
        public byte[]? VerifiedSignature { get; private set; }
        string IJsonCanonicalizer.ProfileId => CanonicalizationProfile;
        string IContentHasher.AlgorithmId => HashAlgorithmId;
        int IContentHasher.HashSizeInBytes => HashSize;
        string IContentSigner.KeyId => SignerKeyId;
        string IContentSigner.AlgorithmId => SigningAlgorithm;
        string IContentVerifier.KeyId => VerifierKeyId;
        string IContentVerifier.AlgorithmId => VerificationAlgorithm;

        public void ValidateInput(JsonElement value)
        {
            ValidatedInputs.Add(value.GetRawText());
            // Even a deliberately permissive Canonicalize must still validate the whole raw tree.
            // Keep this separate from canonical call recording so pre-filter ordering remains visible.
            new UnsafeJcsCanonicalizer().ValidateInput(value);
            if (ValidationFault is not null) throw ValidationFault;
            AfterValidation?.Invoke(value);
        }

        public void Canonicalize(JsonElement value, IBufferWriter<byte> destination)
        {
            string stage = value.TryGetProperty("id", out _) ? "canonicalize-document"
                : value.TryGetProperty("ignoredProperties", out _) ? "canonicalize-policy" : "canonicalize-header";
            Before(stage);
            CanonicalInputs.Add(value.GetRawText()); // Capture owned text, never retain the borrowed JsonElement.
            if (ExpansionStage == stage)
            {
                // Small writes test logical bounds rather than an implementation-specific reservation hint.
                byte[] chunk = new byte[128];
                for (int remaining = ExpansionBytes; remaining > 0; remaining -= Math.Min(remaining, chunk.Length))
                    destination.Write(chunk.AsSpan(0, Math.Min(remaining, chunk.Length)));
            }
            else if (PermissiveCanonicalizer)
                destination.Write("{}"u8);
            else
                new UnsafeJcsCanonicalizer().Canonicalize(value, destination);
        }

        public byte[] ComputeHash(ReadOnlySequence<byte> canonicalUtf8)
        {
            Before("hash");
            HashedBytes = canonicalUtf8.ToArray();
            return OverrideDigest ? DigestResult! : new UnsafeSha256ContentHasher().ComputeHash(canonicalUtf8);
        }

        public byte[] SignHash(ReadOnlySpan<byte> hash)
        {
            Before("sign");
            SignedDigest = hash.ToArray();
            return OverrideSignature ? SignatureResult! : keys.Signer.SignHash(hash);
        }

        public bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature)
        {
            Before("verify");
            VerifiedDigest = hash.ToArray();
            VerifiedSignature = signature.ToArray();
            return keys.Verifier.VerifyHash(hash, signature);
        }

        public IContentVerifier? Resolve(string keyId)
        {
            Before("resolve");
            ResolvedKeyId = keyId;
            return ResolveAnyKey || keyId == keys.Signer.KeyId ? this : null;
        }

        public void Clear()
        {
            Calls.Clear();
            CanonicalInputs.Clear();
            ValidatedInputs.Clear();
            ResolvedKeyId = null;
            HashedBytes = null;
            SignedDigest = null;
            VerifiedDigest = null;
            VerifiedSignature = null;
        }

        private void Before(string stage)
        {
            Calls.Add(stage);
            if (FaultStage == stage) throw Fault ?? new InvalidOperationException("No provider fault configured.");
        }
    }
}