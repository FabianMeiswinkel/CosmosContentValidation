# Sample-only providers — not security reviewed

**`Unsafe` means illustrative and NOT security reviewed; it does not mean deliberately flawed cryptography.**
The future owning security team must supply security-validated implementations of all five content-protection interfaces before production integration. User review and security-team approval are separate from build/test success.

All providers and their helpers below belong to namespace `CosmosContentValidation.Sample.Providers` and the console sample assembly, not the reusable library.

| Symbol | Responsibility / source |
| --- | --- |
| `UnsafeJcsCanonicalizer` | `IJsonCanonicalizer`; required whole-input checks and Jcs.Net canonicalization. [UnsafeJcsCanonicalizer.cs](UnsafeJcsCanonicalizer.cs) |
| `UnsafeSha256ContentHasher` | `IContentHasher`; per-call segmented SHA-256. [UnsafeSha256ContentHasher.cs](UnsafeSha256ContentHasher.cs) |
| `UnsafeEcdsaContentSigner` | `IContentSigner`; local prehashed P-256/P1363 signing. [UnsafeEcdsaContentSigner.cs](UnsafeEcdsaContentSigner.cs) |
| `UnsafeEcdsaContentVerifier` | `IContentVerifier`; public-key verification. [UnsafeEcdsaContentVerifier.cs](UnsafeEcdsaContentVerifier.cs) |
| `UnsafeInMemoryVerificationKeyResolver` | `IVerificationKeyResolver`; copied, ordinal, preloaded key mapping. [UnsafeInMemoryVerificationKeyResolver.cs](UnsafeInMemoryVerificationKeyResolver.cs) |
| `UnsafeEcdsaKeyImport` | Internal PEM/ASN.1 import helper. [UnsafeEcdsaKeyImport.cs](UnsafeEcdsaKeyImport.cs) |
| `UnsafeJsonInputValidation` | Internal duplicate-name, Unicode, number and depth checks. [UnsafeJsonInputValidation.cs](UnsafeJsonInputValidation.cs) |
| `UnsafeSampleProviders` | Sample composition root. [UnsafeSampleProviders.cs](UnsafeSampleProviders.cs) |

## Composition and dependency direction

The [console entry point](../Program.cs) and tests use `UnsafeSampleProviders.CreateProcessor` to supply illustrative canonicalizer/hasher defaults. It creates neither signing keys nor verification keys implicitly. The library constructor is `ContentValidationProcessor(options, verificationKeys, canonicalizer, hasher, signer = null)`; all four leading arguments are required, and omitting the signer produces a public-only processor. There are **no built-in content-protection providers, default providers or fallback providers in the library**. Ordinary configuration defaults, JSON processing and buffer utilities are not content-protection implementations.

The [sample project](../CosmosContentValidation.Sample.csproj) references the [library project](../../../src/CosmosContentValidation/CosmosContentValidation.csproj) and owns the Jcs.Net dependency. Both the [unit-test project](../../../tests/CosmosContentValidation.Tests/CosmosContentValidation.Tests.csproj) and [live-test project](../../../tests/CosmosContentValidation.LiveTests/CosmosContentValidation.LiveTests.csproj) reference the sample for these providers; the library never references the sample or tests. Test doubles are test-only, not shipped library providers.

The library has no direct content-crypto, ASN.1 or JCS package dependency and must emit no assembly references to `System.Security.Cryptography`, `System.Formats.Asn1`, Jcs.Net or the sample. This constraint does **not** make Cosmos SDK/Azure authentication dependencies crypto-free: transport/authentication still use cryptography. The library's [internal bounded writer](../../../src/CosmosContentValidation/Internal/BoundedBufferWriter.cs) remains a buffer utility, not a provider.

## Security-team replacement contract

- Preserve the [fixed v1 wire protocol](../../../../docs/content-validation-protocol.md), profile/algorithm identifiers, canonical bytes, 32-byte digests and 64-byte P1363 signatures. Provider substitution is not implemented crypto agility.
- Implement `IJsonCanonicalizer.ValidateInput` separately from `Canonicalize`. The processor calls validation on the entire raw tree **before** excluded fields are filtered; ignored subtrees must still satisfy the input profile. Matching an identifier alone is not evidence of correct implementation.
- The injected canonicalizer and hasher also compute the exclusion-policy fingerprint at processor construction. Preserve the v1 descriptor and fixture bytes; there is no hidden library implementation for policy hashing.
- Keep hooks synchronous, thread-safe and I/O-free, with no remote signing, on-demand key loading or sync-over-async. Preload keys and preserve signing/public-verification capability separation.
- Do not retain or dispose borrowed JSON, destinations, spans or sequences. Caller-owned provider lifetimes must outlive operations; dispose clients before providers. Review key import, private-key custody, zeroing limitations and concurrency/disposal.
- Security-team review must validate all replacement providers and their dependencies, not just signer/verifier primitives. User review must also approve interfaces, exclusions, ownership and the supported-operation boundary. Tests and fixtures support these reviews but are not certification.

Architecture and wrapper guard tests verify source/project boundaries and emitted assembly references; consult the [latest recorded validation report](../../../../docs/pr2-validation.md) for executed evidence. These checks do not grant security approval. PR3–PR5 must retain this boundary; Java equivalents remain future work.
