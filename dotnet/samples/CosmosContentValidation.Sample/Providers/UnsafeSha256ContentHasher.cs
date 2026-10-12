using System.Buffers;
using System.Security.Cryptography;

namespace CosmosContentValidation.Sample.Providers;

/// <summary>Hashes borrowed segments without flattening or retaining their storage.</summary>
/// <remarks>
/// Illustrative only; NOT security reviewed. Must be replaced with the owning security team's
/// validated implementation. The Unsafe marker does NOT mean deliberately broken cryptography.
/// </remarks>
public sealed class UnsafeSha256ContentHasher : IContentHasher
{
    public UnsafeSha256ContentHasher() { }

    public string AlgorithmId => "SHA-256";
    public int HashSizeInBytes => 32;

    public byte[] ComputeHash(ReadOnlySequence<byte> canonicalUtf8)
    {
        // Per-call state makes concurrent calls independent, including empty input.
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (ReadOnlyMemory<byte> segment in canonicalUtf8)
            hash.AppendData(segment.Span);

        return hash.GetHashAndReset();
    }
}