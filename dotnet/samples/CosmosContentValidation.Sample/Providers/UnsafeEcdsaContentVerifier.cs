using System.Security.Cryptography;

namespace CosmosContentValidation.Sample.Providers;

/// <summary>Verifies SHA-256 digests with a preloaded, public-only SPKI named P-256 key.</summary>
/// <remarks>
/// Illustrative only; NOT security reviewed. Must be replaced with the owning security team's
/// validated implementation. The Unsafe marker does NOT mean deliberately broken cryptography.
/// The provider owns its key. Operations and disposal are mutually exclusive.
/// </remarks>
public sealed class UnsafeEcdsaContentVerifier : IContentVerifier, IDisposable
{
    private readonly object sync = new();
    private readonly ECDsa key;
    private bool disposed;

    public UnsafeEcdsaContentVerifier(string keyId, string publicKeyPem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        KeyId = keyId;
        key = UnsafeEcdsaKeyImport.Import(publicKeyPem, privateKey: false, nameof(publicKeyPem));
    }

    public string KeyId { get; }
    public string AlgorithmId => UnsafeEcdsaKeyImport.AlgorithmId;

    /// <summary>Verifies an already computed digest; non-64-byte or invalid signatures return false.</summary>
    /// <exception cref="ArgumentException">The digest is not 32 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The provider has been disposed.</exception>
    public bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature)
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (hash.Length != UnsafeEcdsaKeyImport.HashSizeInBytes)
                throw new ArgumentException("A SHA-256 digest must contain exactly 32 bytes.", nameof(hash));

            if (signature.Length != UnsafeEcdsaKeyImport.SignatureSizeInBytes) return false;
            return key.VerifyHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return;
            disposed = true;
            key.Dispose();
        }
    }
}