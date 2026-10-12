using System.Buffers;
using System.Collections.Frozen;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using CosmosContentValidation.Internal;
using Microsoft.IO;

namespace CosmosContentValidation;

/// <summary>Synchronous, I/O-free content protection over borrowed raw UTF-8 JSON.</summary>
/// <remarks>
/// Providers and their lifetimes belong to the caller. Returned streams belong to the caller and
/// are rewound to zero. Inputs are neither changed nor retained. Structural/profile input validation
/// of the entire raw document, including excluded fields, is delegated to the trusted canonicalizer
/// before filtering. The v1 profile requires finite IEEE binary64 numbers: integral values outside
/// ±(2^53−1) and nonzero underflow must be rejected; fractional values may round.
/// Store exact decimals and large integers as strings. Excluded root fields remain unauthenticated.
/// A signature proves neither freshness nor completeness, and does not prevent document replay.
/// There are no built-in providers or fallbacks. Construction uses the supplied canonicalizer and
/// hasher to compute the exclusion-policy identity under the fixed v1 wire profile.
/// </remarks>
public sealed class ContentValidationProcessor
{
    public const string SignaturePropertyName = "_contentValidation";
    // Fixed v1 wire compatibility identifiers and lengths, not algorithm implementations.
    private const string CanonicalizationProfile = "rfc8785-binary64-v1";
    private const string HashAlgorithm = "SHA-256";
    private const string SignatureAlgorithm = "ECDSA-P256-SHA256-P1363";
    private const int HashSizeInBytes = 32;
    private const int SignatureSizeInBytes = 64;
    private static readonly string[] ServiceProperties = ["_rid", "_self", "_etag", "_attachments", "_ts"];
    private static readonly JsonWriterOptions WriterOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping, MaxDepth = 66 };
    private readonly FrozenSet<string> ignoredProperties;
    private readonly string[][] partitionKeySegments;
    private readonly IVerificationKeyResolver verificationKeys;
    private readonly IContentSigner? signer;
    private readonly IJsonCanonicalizer canonicalizer;
    private readonly IContentHasher hasher;
    private readonly string? signingKeyId;
    private readonly string profile;

    public ContentValidationProcessor(ContentValidationOptions options, IVerificationKeyResolver verificationKeys,
        IJsonCanonicalizer canonicalizer, IContentHasher hasher, IContentSigner? signer = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(verificationKeys);
        ArgumentNullException.ThrowIfNull(canonicalizer);
        ArgumentNullException.ThrowIfNull(hasher);
        ArgumentNullException.ThrowIfNull(options.PartitionKeyPaths);
        ArgumentNullException.ThrowIfNull(options.AdditionalIgnoredRootProperties);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MaxDocumentBytes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MaxBufferedBytes, 1024);
        if (options.MaxDocumentBytes > options.MaxBufferedBytes)
            throw new ArgumentException("The document limit cannot exceed the buffer limit.", nameof(options));

        string[] paths = options.PartitionKeyPaths.ToArray();
        if (paths.Length == 0 || paths.Length > 3 || paths.Distinct(StringComparer.Ordinal).Count() != paths.Length)
            throw new ArgumentException("Supply one to three distinct partition-key paths.", nameof(options));
        partitionKeySegments = paths.Select(ParsePartitionKeyPath).ToArray();
        HashSet<string> ignored = new(ServiceProperties, StringComparer.Ordinal);
        foreach (string name in options.AdditionalIgnoredRootProperties)
        {
            if (string.IsNullOrEmpty(name) || !IsValidUnicode(name))
                throw new ArgumentException("Ignored root names must be nonempty valid Unicode.", nameof(options));
            ignored.Add(name);
        }
        if (ignored.Contains("id") || ignored.Contains(SignaturePropertyName)
            || partitionKeySegments.Any(path => ignored.Contains(path[0]) || path[0] == SignaturePropertyName))
            throw new ArgumentException("Identity, partition keys and the signature envelope cannot be ignored or reserved.", nameof(options));

        ignoredProperties = ignored.ToFrozenSet(StringComparer.Ordinal);
        PartitionKeyPaths = Array.AsReadOnly(paths);
        MaxDocumentBytes = options.MaxDocumentBytes;
        Buffers = new(options.MaxBufferedBytes);
        this.verificationKeys = verificationKeys;
        this.signer = signer;
        this.canonicalizer = canonicalizer;
        this.hasher = hasher;
        profile = this.canonicalizer.ProfileId;
        signingKeyId = signer?.KeyId;
        CheckTrustedProfiles();
        if (signer is not null && (string.IsNullOrWhiteSpace(signingKeyId) || !IsValidUnicode(signingKeyId)))
            throw new ArgumentException("The signing key must have a valid nonempty identifier.", nameof(signer));
        ExclusionPolicyHash = ComputePolicyHash();
    }

    public PooledJsonBufferPool Buffers { get; }
    public IReadOnlyList<string> PartitionKeyPaths { get; }
    public int MaxDocumentBytes { get; }
    public bool CanSign => signer is not null;
    public string ExclusionPolicyHash { get; }

    public RecyclableMemoryStream Sign(ReadOnlySequence<byte> json, bool replaceExistingSignature = false)
    {
        if (signer is null)
            throw Failure(ContentValidationFailure.SigningUnavailable, "This processor has no signing capability.");
        using JsonDocument parsed = ParseInput(json, allowArray: false);
        JsonElement document = parsed.RootElement;
        ValidateIdentity(document);
        if (document.TryGetProperty(SignaturePropertyName, out JsonElement existing))
        {
            if (!replaceExistingSignature)
                throw Failure(ContentValidationFailure.ReservedProperty, "The document contains the reserved signature property.");
            // Deliberately do NOT verify the old signature: the caller may have edited the document.
            _ = ReadEnvelope(existing);
        }
        CheckTrustedProfiles();
        Header header = new(profile, HashAlgorithm, SignatureAlgorithm, ExclusionPolicyHash, signingKeyId!);
        byte[] digest = ComputeDocumentHash(document, header);
        byte[] signature = signer.SignHash(digest);
        if (signature is null || signature.Length != SignatureSizeInBytes)
            throw new InvalidOperationException("The signing provider returned an invalid signature length.");
        return WritePooled(writer => WriteDocument(writer, document, header, Encode(signature)), MaxDocumentBytes);
    }

    /// <summary>Validates the full raw document without changing a byte of the borrowed input.</summary>
    public void Validate(ReadOnlySequence<byte> json)
    {
        using JsonDocument parsed = ParseInput(json, allowArray: false);
        ValidateDocument(parsed.RootElement);
    }

    /// <summary>Validates all documents before copying them without their root envelopes.</summary>
    public RecyclableMemoryStream ValidateAndStrip(ReadOnlySequence<byte> json, bool allowArray = false)
    {
        using JsonDocument parsed = ParseInput(json, allowArray);
        JsonElement root = parsed.RootElement;
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement document in root.EnumerateArray()) ValidateDocument(document);
            return WritePooled(writer =>
            {
                writer.WriteStartArray();
                foreach (JsonElement document in root.EnumerateArray()) WriteDocument(writer, document);
                writer.WriteEndArray();
            }, Buffers.MaxBufferBytes);
        }
        ValidateDocument(root);
        return WritePooled(writer => WriteDocument(writer, root), MaxDocumentBytes);
    }

    private JsonDocument ParseInput(ReadOnlySequence<byte> json, bool allowArray)
    {
        CheckLength(json.Length, Buffers.MaxBufferBytes);
        JsonDocument? parsed = null;
        try
        {
            parsed = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = allowArray ? 65 : 64 });
            JsonElement root = parsed.RootElement;
            if (allowArray && root.ValueKind == JsonValueKind.Array)
            {
                // Measure each raw item without materializing its JSON as a string or byte array.
                Utf8JsonReader reader = new(json, new JsonReaderOptions { MaxDepth = 65 });
                reader.Read();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    long start = reader.TokenStartIndex;
                    reader.Skip();
                    CheckLength(reader.BytesConsumed - start, MaxDocumentBytes);
                }
                foreach (JsonElement document in root.EnumerateArray()) ValidateRawObject(document);
            }
            else
            {
                CheckLength(json.Length, MaxDocumentBytes);
                ValidateRawObject(root);
            }
            return parsed;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException or DecoderFallbackException)
        {
            parsed?.Dispose();
            // Parser diagnostics can echo untrusted tokens. Retain a sanitized cause, never payload text.
            throw Failure(ContentValidationFailure.InvalidDocument, "The input is not a supported JSON document.",
                new JsonException("Malformed JSON, duplicate names, invalid Unicode, depth or numeric domain."));
        }
        catch
        {
            parsed?.Dispose();
            throw;
        }
    }

    private void ValidateRawObject(JsonElement document)
    {
        if (document.ValueKind != JsonValueKind.Object)
            throw new JsonException("A document must be an object.");
        canonicalizer.ValidateInput(document);
    }

    private void ValidateIdentity(JsonElement document)
    {
        if (!document.TryGetProperty("id", out JsonElement idElement) || idElement.ValueKind != JsonValueKind.String)
            throw Failure(ContentValidationFailure.InvalidDocument, "The document requires a string id.");
        string id = idElement.GetString()!;
        if (id.Length == 0 || Encoding.UTF8.GetByteCount(id) > 1023 || id.IndexOfAny(['/', '\\', '?', '#']) >= 0)
            throw Failure(ContentValidationFailure.InvalidDocument, "The document id is invalid.");
        foreach (string[] path in partitionKeySegments)
        {
            JsonElement current = document;
            foreach (string segment in path)
            {
                if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(segment, out current))
                    throw Failure(ContentValidationFailure.InvalidDocument, "A configured partition-key path is missing.");
            }
            if (current.ValueKind is not (JsonValueKind.String or JsonValueKind.Number or JsonValueKind.Null or JsonValueKind.True or JsonValueKind.False))
                throw Failure(ContentValidationFailure.InvalidDocument, "A partition-key value must be a JSON primitive.");
        }
    }

    private void ValidateDocument(JsonElement document)
    {
        ValidateIdentity(document);
        if (!document.TryGetProperty(SignaturePropertyName, out JsonElement envelope))
            throw Failure(ContentValidationFailure.MissingSignature, "The document has no content signature.");
        (Header header, byte[] signature) = ReadEnvelope(envelope);
        IContentVerifier? verifier = verificationKeys.Resolve(header.KeyId);
        if (verifier is null)
            throw Failure(ContentValidationFailure.UnknownKey, "The signature key is not trusted locally.");
        if (!string.Equals(verifier.KeyId, header.KeyId, StringComparison.Ordinal))
            throw new InvalidOperationException("The key resolver returned a provider with a different key identifier.");
        if (!string.Equals(verifier.AlgorithmId, header.SignatureAlgorithm, StringComparison.Ordinal))
            throw Failure(ContentValidationFailure.UnsupportedProfile, "The trusted verification provider uses an incompatible algorithm.");
        byte[] digest = ComputeDocumentHash(document, header);
        if (!verifier.VerifyHash(digest, signature))
            throw Failure(ContentValidationFailure.InvalidSignature, "The content signature is invalid.");
    }

    private (Header Header, byte[] Signature) ReadEnvelope(JsonElement envelope)
    {
        CheckTrustedProfiles();
        if (envelope.ValueKind != JsonValueKind.Object || envelope.EnumerateObject().Count() != 7
            || !envelope.TryGetProperty("v", out JsonElement version) || version.ValueKind != JsonValueKind.Number
            || !version.TryGetInt32(out int number))
            throw Failure(ContentValidationFailure.InvalidSignature, "The signature envelope is malformed.");
        if (number != 1)
            throw Failure(ContentValidationFailure.UnsupportedProfile, "The signature version is not supported.");
        string canonicalization = ReadString(envelope, "canonicalization");
        string hashAlgorithm = ReadString(envelope, "hashAlgorithm");
        string signatureAlgorithm = ReadString(envelope, "signatureAlgorithm");
        string policy = ReadString(envelope, "exclusionPolicyHash");
        string keyId = ReadString(envelope, "kid");
        byte[] signature = Decode(ReadString(envelope, "signature"), SignatureSizeInBytes);
        _ = Decode(policy, HashSizeInBytes);
        if (canonicalization != profile || hashAlgorithm != HashAlgorithm || signatureAlgorithm != SignatureAlgorithm)
            throw Failure(ContentValidationFailure.UnsupportedProfile, "The signature profile is not supported locally.");
        if (!string.Equals(policy, ExclusionPolicyHash, StringComparison.Ordinal))
            throw Failure(ContentValidationFailure.PolicyMismatch, "The signature exclusion policy differs from the local policy.");
        return (new(canonicalization, hashAlgorithm, signatureAlgorithm, policy, keyId), signature);
    }

    private byte[] ComputeDocumentHash(JsonElement document, Header header)
    {
        CheckTrustedProfiles();
        using RecyclableMemoryStream filtered = WritePooled(writer =>
        {
            writer.WriteStartObject();
            foreach (JsonProperty property in document.EnumerateObject())
                if (property.Name != SignaturePropertyName && !ignoredProperties.Contains(property.Name)) property.WriteTo(writer);
            writer.WriteEndObject();
        }, Buffers.MaxBufferBytes);
        using JsonDocument filteredTree = JsonDocument.Parse(filtered.GetReadOnlySequence(), new JsonDocumentOptions { MaxDepth = 64 });
        using RecyclableMemoryStream headerJson = WritePooled(writer => WriteHeader(writer, header), Buffers.MaxBufferBytes);
        using JsonDocument headerTree = JsonDocument.Parse(headerJson.GetReadOnlySequence());
        using RecyclableMemoryStream canonical = Buffers.Rent();
        using BoundedBufferWriter destination = new(canonical, Buffers.MaxBufferBytes);
        // JCS sorts the three fixed keys as document/domain/header. Compose independently canonical
        // subtrees to avoid charging the protocol wrapper against the document's depth-64 budget.
        destination.Write("{\"document\":"u8);
        canonicalizer.Canonicalize(filteredTree.RootElement, destination);
        destination.Write(",\"domain\":\"CosmosContentValidation\",\"header\":"u8);
        canonicalizer.Canonicalize(headerTree.RootElement, destination);
        destination.Write("}"u8);
        byte[] digest = hasher.ComputeHash(canonical.GetReadOnlySequence());
        if (digest is null || digest.Length != HashSizeInBytes)
            throw new InvalidOperationException("The hashing provider returned an invalid digest length.");
        return digest;
    }

    private string ComputePolicyHash()
    {
        using RecyclableMemoryStream descriptor = WritePooled(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("version", 1);
            writer.WriteString("scope", "root");
            writer.WriteStartArray("ignoredProperties");
            foreach (string name in ignoredProperties.Order(StringComparer.Ordinal)) writer.WriteStringValue(name);
            writer.WriteEndArray();
            writer.WriteEndObject();
        }, Buffers.MaxBufferBytes);
        using JsonDocument tree = JsonDocument.Parse(descriptor.GetReadOnlySequence());
        using RecyclableMemoryStream canonical = Buffers.Rent();
        // Trusted providers must implement the fixed v1 profile for both policy and content.
        using BoundedBufferWriter destination = new(canonical, Buffers.MaxBufferBytes);
        canonicalizer.Canonicalize(tree.RootElement, destination);
        byte[] digest = hasher.ComputeHash(canonical.GetReadOnlySequence());
        if (digest is null || digest.Length != HashSizeInBytes)
            throw new InvalidOperationException("The hashing provider returned an invalid digest length.");
        return Encode(digest);
    }

    private RecyclableMemoryStream WritePooled(Action<Utf8JsonWriter> write, int limit)
    {
        RecyclableMemoryStream output = Buffers.Rent();
        try
        {
            using BoundedBufferWriter destination = new(output, limit);
            using (Utf8JsonWriter writer = new(destination, WriterOptions)) write(writer);
            output.Position = 0;
            return output;
        }
        catch
        {
            output.Dispose();
            throw;
        }
    }

    private static void WriteDocument(Utf8JsonWriter writer, JsonElement document, Header? header = null, string? signature = null)
    {
        writer.WriteStartObject();
        foreach (JsonProperty property in document.EnumerateObject())
            if (property.Name != SignaturePropertyName) property.WriteTo(writer);
        if (header is not null)
        {
            writer.WritePropertyName(SignaturePropertyName);
            WriteHeader(writer, header, signature);
        }
        writer.WriteEndObject();
    }

    private static void WriteHeader(Utf8JsonWriter writer, Header header, string? signature = null)
    {
        writer.WriteStartObject();
        writer.WriteNumber("v", 1);
        writer.WriteString("canonicalization", header.Canonicalization);
        writer.WriteString("hashAlgorithm", header.HashAlgorithm);
        writer.WriteString("signatureAlgorithm", header.SignatureAlgorithm);
        writer.WriteString("exclusionPolicyHash", header.PolicyHash);
        writer.WriteString("kid", header.KeyId);
        if (signature is not null) writer.WriteString("signature", signature);
        writer.WriteEndObject();
    }

    private void CheckTrustedProfiles()
    {
        if (profile != CanonicalizationProfile || canonicalizer.ProfileId != profile
            || hasher.AlgorithmId != HashAlgorithm || hasher.HashSizeInBytes != HashSizeInBytes
            || (signer is not null && (signer.AlgorithmId != SignatureAlgorithm || signer.KeyId != signingKeyId)))
            throw Failure(ContentValidationFailure.UnsupportedProfile, "A trusted provider uses an incompatible profile.");
    }

    private static string[] ParsePartitionKeyPath(string path)
    {
        // Deliberately support only unquoted property segments. Cosmos quoted paths and JSON Pointer
        // escaping are not interchangeable. Reject both rather than protect an unintended root.
        if (string.IsNullOrEmpty(path) || path[0] != '/')
            throw new ArgumentException("Partition-key paths must start with '/'.");
        string[] segments = path[1..].Split('/');
        if (segments.Length > 63 || segments.Any(segment => segment.Length == 0
            || segment.Any(character => !char.IsLetterOrDigit(character) && character is not ('_' or '-' or '.'))))
            throw new ArgumentException("Partition-key paths require simple, unescaped property segments.");
        return segments;
    }

    private static bool IsValidUnicode(string text)
    {
        for (int index = 0; index < text.Length; index++)
            if (char.IsSurrogate(text[index]) && (!char.IsHighSurrogate(text[index]) || ++index == text.Length || !char.IsLowSurrogate(text[index])))
                return false;
        return true;
    }

    private static string ReadString(JsonElement envelope, string name)
    {
        if (!envelope.TryGetProperty(name, out JsonElement value) || value.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(value.GetString()))
            throw Failure(ContentValidationFailure.InvalidSignature, "The signature envelope is malformed.");
        return value.GetString()!;
    }

    private static string Encode(ReadOnlySpan<byte> value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Decode(string value, int length)
    {
        if (value.Length != (length * 8 + 5) / 6 || value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')))
            throw Failure(ContentValidationFailure.InvalidSignature, "The signature envelope contains invalid base64url.");
        byte[] bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
        if (bytes.Length != length || Encode(bytes) != value)
            throw Failure(ContentValidationFailure.InvalidSignature, "The signature envelope contains noncanonical base64url.");
        return bytes;
    }

    private static void CheckLength(long length, int limit)
    {
        if (length > limit)
            throw Failure(ContentValidationFailure.PayloadTooLarge, "JSON exceeds the configured size limit.");
    }

    private static ContentValidationException Failure(ContentValidationFailure failure, string message, Exception? cause = null) => new(failure, message, cause);
    private sealed record Header(string Canonicalization, string HashAlgorithm, string SignatureAlgorithm, string PolicyHash, string KeyId);
}