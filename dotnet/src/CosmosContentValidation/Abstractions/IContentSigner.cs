namespace CosmosContentValidation;

/// <summary>Signs an already computed digest using a preloaded key; no hashing or I/O.</summary>
/// <remarks>Must be thread safe. The caller owns this provider and its lifetime.</remarks>
public interface IContentSigner
{
    string KeyId { get; }
    string AlgorithmId { get; }
    /// <summary>Returns a caller-owned signature; never retains the borrowed digest.</summary>
    byte[] SignHash(ReadOnlySpan<byte> hash);
}