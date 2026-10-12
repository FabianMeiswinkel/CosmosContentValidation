using System.Security.Cryptography;
using CosmosContentValidation.Sample;
using CosmosContentValidation.Sample.Providers;

namespace CosmosContentValidation.LiveTests;

/// <summary>
/// One ephemeral P-256 signing key per xUnit class fixture. Construction performs no work,
/// reads no credentials, and never contacts Azure, including when every theory is skipped.
/// Per-test clients are disposed by LiveTestScope before xUnit disposes these providers.
/// </summary>
public sealed class LiveSigningFixture : IDisposable
{
    private readonly object sync = new();
    private UnsafeEcdsaContentSigner? signer;
    private UnsafeEcdsaContentVerifier? verifier;
    private bool disposed;

    internal (ContentValidationProcessor Writer, ContentValidationProcessor Reader) CreateProcessors(bool customPolicy)
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            LiveCheck.Require(LiveTheoryAttribute.IsEnabled, "Live tests were not explicitly enabled.");
            if (signer is null)
            {
                using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                const string keyId = "ephemeral-live-class-key";
                // Providers currently accept PEM strings. These temporary exports stay in memory;
                // no key material is logged or written to disk. Immutable PEM strings cannot be zeroed.
                UnsafeEcdsaContentSigner createdSigner = new(keyId, key.ExportPkcs8PrivateKeyPem());
                try
                {
                    verifier = new UnsafeEcdsaContentVerifier(keyId, key.ExportSubjectPublicKeyInfoPem());
                    signer = createdSigner;
                }
                catch
                {
                    createdSigner.Dispose();
                    throw;
                }
            }

            UnsafeInMemoryVerificationKeyResolver keys = new(new IContentVerifier[] { verifier! });
            ContentValidationOptions options = new()
            {
                PartitionKeyPaths = new[] { "/pk" },
                AdditionalIgnoredRootProperties = customPolicy ? new[] { "ttl", "customerTag" } : Array.Empty<string>(),
                MaxDocumentBytes = 64 * 1024,
                MaxBufferedBytes = 128 * 1024
            };
            // The reader receives ONLY the public verifier: no signing provider is supplied.
            return (UnsafeSampleProviders.CreateProcessor(options, keys, signer), UnsafeSampleProviders.CreateProcessor(options, keys));
        }
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return;
            disposed = true;
            LiveTestFailure? failure = null;
            try { signer?.Dispose(); }
            catch (Exception exception) { failure = LiveCheck.Sanitize(exception); }
            try { verifier?.Dispose(); }
            catch (Exception exception) { failure ??= LiveCheck.Sanitize(exception); }
            if (failure is not null) throw failure;
        }
    }
}