namespace CosmosContentValidation;

/// <summary>Thread-safe, I/O-free verification of an already computed digest.</summary>
public interface IContentVerifier
{
    string KeyId { get; }
    string AlgorithmId { get; }
    /// <summary>Returns false for an invalid signature; provider failures may throw.</summary>
    bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature);
}