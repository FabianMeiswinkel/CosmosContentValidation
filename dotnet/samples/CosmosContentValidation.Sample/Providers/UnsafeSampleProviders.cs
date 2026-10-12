namespace CosmosContentValidation.Sample.Providers;

/// <summary>Sample-only composition root supplying illustrative canonicalization and hashing defaults.</summary>
/// <remarks>
/// Illustrative only; NOT security reviewed. Must be replaced with the owning security team's
/// validated implementation. The Unsafe marker does NOT mean deliberately broken cryptography.
/// Provider lifetimes remain caller-owned. No signer or verification keys are created implicitly.
/// </remarks>
public static class UnsafeSampleProviders
{
    public static ContentValidationProcessor CreateProcessor(ContentValidationOptions options,
        IVerificationKeyResolver verificationKeys, IContentSigner? signer = null,
        IJsonCanonicalizer? canonicalizer = null, IContentHasher? hasher = null) =>
        new(options, verificationKeys, canonicalizer ?? new UnsafeJcsCanonicalizer(),
            hasher ?? new UnsafeSha256ContentHasher(), signer);
}