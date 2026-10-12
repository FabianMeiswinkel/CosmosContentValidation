using System.Security.Cryptography;

namespace CosmosContentValidation.Sample.Providers;

/// <summary>Signs SHA-256 digests with a preloaded PKCS#8 named P-256 private key.</summary>
/// <remarks>
/// Illustrative only; NOT security reviewed. Must be replaced with the owning security team's
/// validated implementation. The Unsafe marker does NOT mean deliberately broken cryptography.
/// The provider owns its key. Operations and disposal are mutually exclusive.
/// </remarks>
public sealed class UnsafeEcdsaContentSigner : IContentSigner, IDisposable
{
    private readonly object sync = new();
    private readonly ECDsa key;
    private bool disposed;

    public UnsafeEcdsaContentSigner(string keyId, string privateKeyPem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        KeyId = keyId;
        key = UnsafeEcdsaKeyImport.Import(privateKeyPem, privateKey: true, nameof(privateKeyPem));
    }

    public string KeyId { get; }
    public string AlgorithmId => UnsafeEcdsaKeyImport.AlgorithmId;

    /// <summary>Signs exactly 32 bytes without hashing again; returns a new 64-byte P1363 signature.</summary>
    /// <exception cref="ArgumentException">The digest is not 32 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The provider has been disposed.</exception>
    public byte[] SignHash(ReadOnlySpan<byte> hash)
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (hash.Length != UnsafeEcdsaKeyImport.HashSizeInBytes)
                throw new ArgumentException("A SHA-256 digest must contain exactly 32 bytes.", nameof(hash));

            return key.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
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