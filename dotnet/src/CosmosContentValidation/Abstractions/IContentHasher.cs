using System.Buffers;

namespace CosmosContentValidation;

/// <summary>Thread-safe, I/O-free hashing over borrowed, possibly segmented input.</summary>
public interface IContentHasher
{
    string AlgorithmId { get; }
    int HashSizeInBytes { get; }
    /// <summary>Returns a new, caller-owned digest. Does not retain input memory.</summary>
    byte[] ComputeHash(ReadOnlySequence<byte> canonicalUtf8);
}