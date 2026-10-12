using System.Collections.Frozen;

namespace CosmosContentValidation.Sample.Providers;

/// <summary>Resolves an immutable, ordinal snapshot of preloaded verification keys without I/O.</summary>
/// <remarks>
/// Illustrative only; NOT security reviewed. Must be replaced with the owning security team's
/// validated implementation. The Unsafe marker does NOT mean deliberately broken cryptography.
/// Copies key-to-provider mappings, not providers. The caller owns provider lifetimes.
/// </remarks>
public sealed class UnsafeInMemoryVerificationKeyResolver : IVerificationKeyResolver
{
    private readonly FrozenDictionary<string, IContentVerifier> verifiers;

    public UnsafeInMemoryVerificationKeyResolver(IEnumerable<IContentVerifier> verifiers)
    {
        ArgumentNullException.ThrowIfNull(verifiers);
        Dictionary<string, IContentVerifier> snapshot = new(StringComparer.Ordinal);
        foreach (IContentVerifier verifier in verifiers)
        {
            if (verifier is null)
                throw new ArgumentException("Verification providers must not be null.", nameof(verifiers));

            string keyId = verifier.KeyId;
            ArgumentException.ThrowIfNullOrWhiteSpace(keyId, nameof(verifiers));
            if (!snapshot.TryAdd(keyId, verifier))
                throw new ArgumentException("Duplicate verification key ID.", nameof(verifiers));
        }

        this.verifiers = snapshot.ToFrozenDictionary(StringComparer.Ordinal);
    }

    public IContentVerifier? Resolve(string keyId)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        return verifiers.TryGetValue(keyId, out IContentVerifier? verifier) ? verifier : null;
    }
}