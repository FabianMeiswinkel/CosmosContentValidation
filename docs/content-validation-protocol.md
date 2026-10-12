# Content-validation protocol v1 (PR1)

This is the implemented .NET PR1 wire contract, not a claim that later PRs are available.
See the [approved plan](implementation-plan.md) and [security/API boundary](security-and-supported-operations.md).
The implementation is in [ContentValidationProcessor](../dotnet/src/CosmosContentValidation/ContentValidationProcessor.cs) and
[ContentValidationSerializer](../dotnet/src/CosmosContentValidation/ContentValidationSerializer.cs).
All concrete content-protection providers are in the console sample, not the library; see the
[sample provider inventory](../dotnet/samples/CosmosContentValidation.Sample/Providers/README.md).
**`Unsafe` means illustrative and NOT security reviewed, not deliberately flawed cryptography.**
The future owning security team must supply validated replacements for all five interfaces; user review remains a separate gate.

## 1. Document and exact envelope

A document is a UTF-8 JSON object. Its reserved, exact-case root property is `_contentValidation`.
The envelope is an object with **exactly these seven fields**, with no additional or duplicate fields:

| Field | Required v1 value/encoding |
| --- | --- |
| `v` | JSON integer `1`. |
| `canonicalization` | String `rfc8785-binary64-v1` (the canonicalizer's `ProfileId`; there is no `profileId` wire field). |
| `hashAlgorithm` | String `SHA-256`. |
| `signatureAlgorithm` | String `ECDSA-P256-SHA256-P1363`. |
| `exclusionPolicyHash` | Canonical unpadded base64url of the 32-byte trusted exclusion-policy digest: 43 characters. |
| `kid` | Nonblank, valid-Unicode, exact-case local verification-key identifier; not a key-fetch URL. |
| `signature` | Canonical unpadded base64url of a 64-byte P1363 signature: 86 characters. |

Base64url uses only `A-Z`, `a-z`, `0-9`, `-`, `_`; padding, incorrect lengths and noncanonical pad bits fail.
Envelope member order is irrelevant. Only the root envelope is reserved; a nested same-name application field is signed normally.
The document requires a nonempty string `id`, at most 1,023 UTF-8 bytes, without `/`, `\`, `?`, or `#`.
Every configured partition-key path must exist and end in a string, number, boolean or null, not an object/array.
The processor accepts one to three distinct paths with simple unescaped segments; quoted, wildcard and JSON-pointer escapes are unsupported.
Configure the actual container paths, not inferred paths; the factory does not discover or verify them.

## 2. Exact signing input and stages

1. Parse raw JSON, then call the injected `IJsonCanonicalizer.ValidateInput` on the entire document **before filtering**, including fields unknown to an application model and excluded subtrees.
2. Form `document` by removing only the root `_contentValidation` and the effective ignored root properties.
3. Form `header` from the six envelope fields other than `signature`, with their exact v1 values.
4. Use the injected canonicalizer's separate `Canonicalize` operation to canonicalize the object `{document,domain,header}`, where `domain` is exactly `CosmosContentValidation`.
5. Use the injected hasher to compute one SHA-256 digest of its canonical UTF-8 bytes, then the injected signer to sign that 32-byte digest with P-256 ECDSA.
6. Append the seven-field envelope to a separate output document, preserving application and ignored values.

The canonical outer bytes are `{"document":<canonical document>,"domain":"CosmosContentValidation","header":<canonical header>}`.
Angle-bracket terms above denote JSON values, not strings or literal placeholder bytes. There is no BOM or trailing newline.
Canonical header order is `canonicalization`, `exclusionPolicyHash`, `hashAlgorithm`, `kid`, `signatureAlgorithm`, `v`.
Both the document and header are protected, including the domain, policy identity, algorithm identifiers and key identifier.
Neither the signature itself nor ignored values enter this signing input. The stored document need not itself be canonical JSON.
Verification checks the envelope and trusted local policy, resolves a preloaded key, recomputes these bytes/digest, then calls `VerifyHash`.
The implementation composes independently canonical document/header subtrees without charging the outer wrapper against document depth.

`ECDSA-P256-SHA256-P1363` means named NIST P-256, SHA-256 prehash, then unsigned big-endian `r || s`.
Each component is exactly 32 bytes, left-padded with zeroes as needed; the combined signature is 64 bytes, **not ASN.1 DER**.
`SignHash`/`VerifyHash` must not hash the digest again. There is no v1 low-S normalization requirement.
The sample providers use system crypto for signing and nonce generation; regenerated valid signatures need not have identical bytes.
The library enforces fixed v1 identifiers/lengths and JSON protocol structure, not cryptographic implementations.
It does not implement crypto agility or negotiate alternative algorithms.

## 3. RFC 8785 algorithm, restricted acceptance profile

The sample's `UnsafeJcsCanonicalizer` uses Jcs.Net 0.1.1's RFC 8785/JCS algorithm after the stricter `rfc8785-binary64-v1` input checks.
Its `ValidateInput` delegates to the sample helper `UnsafeJsonInputValidation`; `Canonicalize` also validates its own input.
That extra sample check does not replace the processor's required whole-document validation before exclusions.
Jcs.Net and these concrete checks belong to the sample, not the library; replacement providers must implement the same acceptance profile.
This profile does **not** accept every input that standard JCS can canonicalize, nor promise arbitrary-precision JSON semantics.
Decoded property names sort recursively by ordinal UTF-16 code units, not locale or Unicode code-point order.
Arrays retain order; null differs from a missing property. Strings/names are not Unicode-normalized.
JCS emits minimal JSON escaping and no insignificant whitespace; numbers use ECMAScript binary64 formatting (`-0` becomes `0`).
Duplicate decoded names at any depth (including `a` versus `\u0061`), invalid UTF-8 and unpaired surrogates are rejected.
Comments, trailing commas and non-JSON numeric tokens are not accepted.

Numbers are converted to **finite IEEE 754 binary64**. Overflow and nonzero values underflowing to zero are rejected.
If the converted value is integral, its magnitude must not exceed 9,007,199,254,740,991 (2^53−1).
This tests the numeric result, not whether the token contains a decimal point or exponent:
`9007199254740992`, `9.007199254740992e15`, `9007199254740991.5` and **`1e30` are rejected**.
Standard JCS permits some such large finite binary64 values; this v1 application profile deliberately does not.
Fractional precision **rounds to binary64 by design**: `333333333.33333329` canonicalizes as `333333333.3333333`.
Lexically different numbers mapping to the same accepted binary64 value authenticate identically; `4.50` becomes `4.5`.
Store exact money/decimals and large integers as **strings**, with application-defined formatting and validation.
Nonzero representable subnormals are allowed; `5e-324` is accepted, `1e-324` fails, and zero mantissas such as `0e-999` are valid.

The maximum collection depth is 64, counting the root object; ignored subtrees consume the same depth budget.
Defaults are 2 MiB per signed wire document including its envelope, and 8 MiB per buffered input/intermediate representation.
`MaxDocumentBytes` must be positive and no greater than `MaxBufferedBytes`, which must be at least 1,024 bytes.
These are local resource limits, not additional signed header fields. Earlier serializer/SDK loss of lexical information is unrecoverable.
For example, validation cannot identify a surrogate already replaced with a genuine-looking U+FFFD by upstream serialization.

## 4. Trusted root exclusion policy

The defaults are exactly `_rid`, `_self`, `_etag`, `_attachments`, `_ts`; **`ttl` and customer fields are signed by default**.
`AdditionalIgnoredRootProperties` adds exact-case, nonempty valid-Unicode names; options/path collections are copied at construction.
Matching is root-only, without wildcards or recursive name matching. Ignoring a root object excludes its **entire subtree**.
For example, adding `ttl` and `cache` permits their addition/removal/change, but not changes to `nested.cache` or `Cache`.
Excluded values remain in outbound documents, raw responses and the copy supplied to ordinary typed mapping; they are **unauthenticated**.
They must still pass well-formedness, uniqueness, numeric, Unicode, depth and size checks before exclusion.
Excluding `id`, `_contentValidation`, or any root containing a configured partition-key path is forbidden.
Service-default/reserved roots cannot serve as partition-key roots either; protected identity cannot be configured away.

The policy descriptor has exactly `ignoredProperties` (effective union, deduplicated and sorted ordinally), `scope: "root"`, `version: 1`.
Its default canonical bytes are:

`{"ignoredProperties":["_attachments","_etag","_rid","_self","_ts"],"scope":"root","version":1}`

`exclusionPolicyHash = base64url(SHA-256(UTF-8(JCS(descriptor))))`, computed once at processor construction
using the **same injected canonicalizer and hasher** as document processing. There are no hardcoded concrete providers or policy-hashing fallbacks.
The descriptor, canonical bytes and v1 fingerprint format are unchanged; providers must preserve those protocol semantics.
The descriptor contains no key, container location or partition-key paths.
The reader compares the signed fingerprint with **trusted local configuration**; the document cannot supply an ignore list or fetch policy.
Changing the effective policy changes compatibility. Old data needs explicit migration/re-signing, not fallback to a weaker policy.
Automatic multi-policy migration is not implemented. Exclusions are deliberate trust exceptions, not authenticated metadata assertions.

## 5. Injectable providers and key lifecycle

`ContentValidationProcessor(options, verificationKeys, canonicalizer, hasher, signer = null)` requires
options, verification keys, canonicalizer and hasher; only the signer is optional. The reusable library contains abstractions,
Cosmos extension wrappers, JSON processing/serialization and pools, **no built-in/default/fallback content-protection providers**.
This does not remove ordinary option or resource-limit defaults.

The synchronous contracts are `IJsonCanonicalizer.ValidateInput(JsonElement)`,
`IJsonCanonicalizer.Canonicalize(JsonElement, IBufferWriter<byte>)`,
`IContentHasher.ComputeHash(ReadOnlySequence<byte>)`, `IContentSigner.SignHash(ReadOnlySpan<byte>)`,
`IContentVerifier.VerifyHash(ReadOnlySpan<byte>, ReadOnlySpan<byte>)`, and `IVerificationKeyResolver.Resolve(string)`.
See the [canonicalization contract](../dotnet/src/CosmosContentValidation/Abstractions/IJsonCanonicalizer.cs),
[hash contract](../dotnet/src/CosmosContentValidation/Abstractions/IContentHasher.cs),
[signer](../dotnet/src/CosmosContentValidation/Abstractions/IContentSigner.cs), [verifier](../dotnet/src/CosmosContentValidation/Abstractions/IContentVerifier.cs),
and [resolver](../dotnet/src/CosmosContentValidation/Abstractions/IVerificationKeyResolver.cs).
`ValidateInput` is a required interface method, not a default implementation or canonicalization fallback.
It must reject duplicate decoded names, invalid Unicode and unsupported numbers/depth across the entire raw tree,
including ignored subtrees, before the processor filters any properties. Diagnostics must not include input data.
Implementations are injectable, but **v1 only accepts the defined profile and algorithms**, with 32-byte digests and 64-byte signatures.
This is implementation substitution, not arbitrary algorithm agility. Custom implementations must preserve those semantics and stable identifiers.
Providers must be thread-safe, retain no borrowed inputs and perform **no file/network I/O, remote crypto or sync-over-async** in hooks.
Canonical output is written to a borrowed destination; digest/signature arrays are new caller-owned outputs.
The sample's `UnsafeSha256ContentHasher` uses per-call `IncrementalHash` over segments;
`UnsafeEcdsaContentSigner` and `UnsafeEcdsaContentVerifier` lock key operations and disposal together.

The sample's `UnsafeEcdsaKeyImport` accepts exactly one unencrypted PKCS#8 `PRIVATE KEY` PEM block for signing,
or one SPKI `PUBLIC KEY` block for verification.
Only named P-256 is accepted; wrong curves, explicit curve parameters, mixed blocks, SEC1 and encrypted PEM are rejected.
Import clears its decoded DER copy; immutable caller PEM strings cannot be explicitly zeroed. Never log key material.
The caller owns provider lifetimes; the sample signer/verifier each own their imported crypto handle. Processors/resolvers do not dispose providers.
Preload old/new public keys for rotation under distinct `kid` values; switch writers deliberately and retain old verifiers as needed.
`UnsafeInMemoryVerificationKeyResolver` snapshots ordinal key mappings, not provider objects. Unknown `kid` fails without any lookup I/O.
Public-only processors refuse signing. The sample checks private/public key agreement locally before network use; constructors alone do not prove it.

The console and tests compose these `CosmosContentValidation.Sample.Providers` examples through `UnsafeSampleProviders`.
Its illustrative canonicalizer/hasher defaults exist **only in the sample**; callers supply keys and any signer explicitly.
Tests reference the sample project; neither the library nor sample depends on the tests, and the library never references the sample.
The library has no direct crypto/ASN.1/JCS dependency or emitted assembly references to those implementations.
Cosmos SDK/Azure authentication transitives are not covered by that claim: transport and authentication still use cryptography.
Security-team replacement and dependency validation must preserve this separation, including the future Java port.

## 6. Validation, re-signing and failure categories

Typed reads validate raw content **before POCO mapping**, then strip only the root envelope from a copy; service metadata is not removed.
Stream reads retain exact raw bytes and the signature envelope. Ordinary mapper settings determine which verified/ignored fields appear in a POCO.
Ordinary `Sign` and typed writes reject an existing root envelope. Only explicit `replaceExistingSignature: true` permits replacement.
The stream-create wrapper opts in for re-sign compatibility: the old envelope must pass shape/profile/policy/encoding checks,
but its old key is not resolved and its signature is **not verified against intentionally edited content**. New content gets the current signer/header.
No caller document is mutated; ignored or otherwise untrusted fields are neither silently removed nor promoted to trusted claims.
`ContentValidationException.Failure` distinguishes `InvalidDocument`, `MissingSignature`, `InvalidSignature`, `UnknownKey`,
`UnsupportedProfile`, `PolicyMismatch`, `ReservedProperty`, `SigningUnavailable` and `PayloadTooLarge`.
`UnsupportedOperation` also exists in the enum, but current wrapper guards throw `NotSupportedException`.
Provider/configuration failures may throw separately. Malformed-input causes are sanitized rather than retaining payload-bearing parser diagnostics.

## 7. Fixtures and PR1 review evidence

The public fixtures are [shared/test-vectors/default-policy.json](../shared/test-vectors/default-policy.json) and
[shared/test-vectors/custom-policy.json](../shared/test-vectors/custom-policy.json); the latter excludes `ttl` and `cache`.
Each freezes policy/document/header/signing-input canonical strings, policy/signing-input hashes, SPKI key and signed document.
Interpret canonical strings as UTF-8 after JSON string decoding, not as the surrounding fixture serialization.
In the recorded PR1 baseline, their manually specified bytes were independently checked with Node JSON formatting and platform SHA-256/P-256 P1363 verification;
both hashes and signatures passed, and hashing the digest again failed verification. This check is independent of the sample providers.
[ProcessorTests](../dotnet/tests/CosmosContentValidation.Tests/ProcessorTests.cs) also compares canonical bytes and verifies fixtures with platform `ECDsa`;
[CryptoTests](../dotnet/tests/CosmosContentValidation.Tests/CryptoTests.cs) covers independent prehash interoperability and rejection of double hashing/DER.
[CanonicalizationTests](../dotnet/tests/CosmosContentValidation.Tests/CanonicalizationTests.cs) covers numeric/Unicode/depth acceptance, not unrestricted JCS conformance.
These source tests do not establish that the new provider-boundary or guard tests have passed; see the
[latest recorded validation evidence](pr1-validation.md) for executed checks, not an inferred result for subsequent edits.
The future security team is responsible for validating all replacement providers and their dependencies;
user review must approve public interfaces, wire identifiers, exclusion identity, prehash semantics, provider ownership,
restricted numeric acceptance and the [stored-procedure/write-trigger boundary](security-and-supported-operations.md).
For sample configuration and opt-in Azure checks, see [live-tests.md](live-tests.md); Java interoperability remains planned, not demonstrated by PR1.
