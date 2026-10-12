# CosmosContentValidation

Customer-side JSON content integrity samples for Azure Cosmos DB (.NET SDK v3 and Java SDK v4).

See the [approved five-PR implementation plan](docs/implementation-plan.md). PR1 implements the .NET create/read foundation; subsequent operations and Java follow in separate PRs.

## PR1: .NET 10

The reusable library signs JSON document content in `CosmosSerializer` and validates it **before** mapping to application objects. The guarded `CosmosClient`/`Database`/`Container` wrappers allow point create/read/delete and reject unsupported operations. Stream APIs reuse the same processor with pooled, replayable buffers.

- The library supplies abstractions, Cosmos extension wrappers, JSON processing and pools, **not concrete content-protection providers or provider defaults**. Callers must supply canonicalizer, hasher and verification-key resolver implementations; signing is optional.
- The v1 protocol fixes SHA-256, ECDSA P-256/P1363 and the canonicalization profile. These identifiers are compatibility constraints, not built-in implementations or implemented crypto agility.
- Synchronous, I/O-free content protection. Load keys before operations; readers require only public keys.
- The console sample alone supplies the `Unsafe`-prefixed canonicalizer, hasher, signer, verifier and resolver, including a Jcs.Net adapter with a restricted binary64 input profile.
- Default root exclusions: `_rid`, `_self`, `_etag`, `_attachments`, `_ts`. Add `ttl` or customer fields via `AdditionalIgnoredRootProperties`; excluded values are **not authenticated**. A signed policy fingerprint prevents silently changing exclusions.
- Pooled `RecyclableMemoryStream` storage; sequence-based access, no cloning with `ToArray()`, preserved stream ownership, and replay after validation.

### Provider boundary and review responsibility

All concrete content-protection providers live in `CosmosContentValidation.Sample.Providers`, composed by `UnsafeSampleProviders` in the console and tests. **`Unsafe` means illustrative and NOT security reviewed, not deliberately flawed cryptography.** The future owning security team must supply security-validated replacements for all five interfaces; neither the examples nor passing tests constitute security approval. See the [sample provider inventory and replacement contract](dotnet/samples/CosmosContentValidation.Sample/Providers/README.md).

The library constructor is `ContentValidationProcessor(options, verificationKeys, canonicalizer, hasher, signer = null)`: no implicit provider construction or fallback. The injected canonicalizer validates the entire input before exclusions; the same injected canonicalizer and hasher compute both document digests and the unchanged v1 policy fingerprint. Tests reference the sample project; the sample does not reference tests, and the library never references the sample.

The library has no direct crypto/ASN.1/JCS dependency or emitted assembly reference to those implementations or the sample. This is **not** a claim that Cosmos SDK or Azure authentication transitives are crypto-free: transport and authentication still use cryptography. Future security-team validation and user review remain explicit gates.

### Rejected execution paths

`Container.Scripts` throws before accessing the inner delegate, blocking typed stored-procedure execution and both stream overloads. Any write with nonempty `PreTriggers` or `PostTriggers` is rejected before content is read or submitted: create/delete now, replace/upsert when PR2 implements them. Empty lists invoke no trigger and are copied before use. Reads retain ordinary option handling and copied lists without the write-trigger guard. Patch remains blocked even for ignored fields. These boundaries must continue through PR2–PR5, including Java.

### Build and offline demonstration

Run from the repository root with the .NET 10 SDK:

```powershell
dotnet build dotnet/CosmosContentValidation.slnx -c Release
dotnet test dotnet/CosmosContentValidation.slnx -c Release
dotnet run --project dotnet/samples/CosmosContentValidation.Sample -- --offline
dotnet run --project dotnet/samples/CosmosContentValidation.Sample -- --help
```

The offline demo generates ephemeral keys in memory, exercises signing/verification and tampering, and makes no Azure calls. Live tests are skipped unless explicitly enabled. Builds produce a separate library DLL and console app; no package publishing occurs.

### Live Azure sample and tests

Use a **preprovisioned dedicated test container with partition-key path `/pk`**, externally supplied credentials, and matching local PEM keys. No account, database, or container is provisioned automatically. See [live setup, commands, and safe cleanup](docs/live-tests.md).

The normal online sample demonstrates typed and stream create/read with a public-key-only reader. `--tamper` explicitly enables an unprotected test client to change only this run's acknowledged new items, demonstrating that protected reads reject the changes. Never point tamper tests at business data.

### Review and integration references

- [Library project](dotnet/src/CosmosContentValidation/CosmosContentValidation.csproj)
- [Public abstractions and wire protocol](docs/content-validation-protocol.md)
- [Supported operations, security limits, and buffer ownership](docs/security-and-supported-operations.md)
- [Console sample](dotnet/samples/CosmosContentValidation.Sample/Program.cs)
- [Latest recorded validation evidence](docs/pr1-validation.md) (historical runs do not verify subsequently added tests)
- [Offline tests](dotnet/tests/CosmosContentValidation.Tests/CosmosContentValidation.Tests.csproj)
- [Opt-in live tests](dotnet/tests/CosmosContentValidation.LiveTests/CosmosContentValidation.LiveTests.csproj)
- [Shared default-policy fixture](shared/test-vectors/default-policy.json) and [custom-policy fixture](shared/test-vectors/custom-policy.json)

**Limits:** this is a customer sample, not a security certification or an SDK fork. Signatures do not establish freshness, prevent deletion/rollback, or prove query completeness. They cannot protect against a compromised signing key. Transport errors and status-only responses are not validated documents. Unsupported APIs fail closed through the wrappers; directly using another SDK client bypasses those guards.

PR2 adds updates, queries and latest-version change feed; PR3 adds bulk and typed transactional batch. Java follows in PR4–PR5. These operations are intentionally unavailable in PR1.
