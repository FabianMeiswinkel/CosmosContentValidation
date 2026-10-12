namespace CosmosContentValidation;

/// <summary>Resolves only preloaded trusted keys. Must be thread safe and perform no I/O.</summary>
public interface IVerificationKeyResolver
{
    /// <summary>Returns null for unknown IDs; must never fetch a key named by untrusted content.</summary>
    IContentVerifier? Resolve(string keyId);
}