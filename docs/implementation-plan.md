# Cosmos content validation — implementation plan

- **Date:** 2026-10-12
- **Status:** Approved plan, updated requirements: configurable ignored root properties, sample-only `Unsafe` providers, and explicit stored-procedure/write-trigger execution boundaries.
- **Delivery:** PR1 foundation implemented; prior offline verification is recorded in the [latest validation report](pr1-validation.md). Provider-refactor and newly added guard-test results must be verified and recorded separately; no new pass claim is made here. Live Azure verification, future security-team provider validation/replacement and user review remain pending. PR2–PR5 not started.
- **Sequence:** PR1 → PR2 → PR3 → PR4 → PR5; finish .NET before Java. Parallel work is permitted only within a PR after its interface prerequisites.
- **Implementation scope:** PR1 only. SDK source and PR2–PR5 remain unchanged. Builds and verification are recorded separately from human interface/wire-format approval.
- **Baseline:** Repository initially contains README, MIT license, ignore rules, and Git metadata on `main`; no application/build/CI scaffolding. Commits, pushes, and starting subsequent PRs remain subject to the normal user workflow.

## 1. Scope and approved decisions

Build reusable content-validation libraries plus one console sample per language: .NET 10 DLL first, then Java 21/Maven JAR. Use existing public Cosmos SDK extension points; no SDK modifications, unsupported internal bridges, reflection-based bypasses, or encryption-package dependency.

Typed protection belongs in custom serializers. Decorators enforce operation/type/options guards. **.NET stream APIs bypass serializers**, so stream overrides explicitly invoke the same shared processor: the narrow exception to guard-only wrappers.

Canonicalization, hashing, signing, verification, and key lookup are **synchronous and I/O-free**. Preload keys before operations. Stream transport/buffering may use **asynchronous I/O** where the API permits; this does not authorize remote signing, file/network key resolution, or blocking asynchronous work inside serializer/crypto hooks.

Use external RFC 8785 canonicalizers in sample providers after bounded evaluation, not a large hand-written JCS implementation. PR1 defines the restricted `rfc8785-binary64-v1` acceptance profile; preserve that wire format and its fixtures across languages, with no silent fallback. Reject unsigned/invalid content; permit delete cleanup. Later PRs include latest-version pull change feed alongside queries.

**Provider placement is a required boundary, not an optional packaging choice.** The reusable DLL/JAR supplies abstractions,
Cosmos extension wrappers, JSON processing/serialization and pools, with no concrete canonicalizer/hasher/signer/verifier/resolver
implementations or provider defaults/fallbacks. All illustrative implementations belong only to the console sample and have `Unsafe` prefixes.
`Unsafe` means **example, NOT security reviewed**, not deliberately flawed cryptography. The future owning security team must supply
security-validated replacements for all five interfaces; user review is an additional gate, not replaced by passing tests.
In .NET, the namespace is `CosmosContentValidation.Sample.Providers`; `UnsafeSampleProviders` composes the console/tests.
Tests reference the sample, never the reverse, and the library never depends on the sample. See the
[provider inventory](../dotnet/samples/CosmosContentValidation.Sample/Providers/README.md).

The .NET library must have no direct crypto/ASN.1/JCS dependency or emitted assembly references to those implementations or the sample.
Java must preserve the equivalent separation when implemented. This is **not** a claim that Cosmos SDK/Azure authentication transitives
are crypto-free: transport/authentication still use cryptography. The fixed v1 wire profile and algorithm identifiers are protocol constraints,
not implementations or implemented crypto agility. External canonicalizer dependencies belong to the sample/provider implementation, not the library.

Run offline tests for each PR and explicitly opted-in live Azure integration tests with external credentials. No emulator requirement, account provisioning, package publishing, or deployment automation.

## 2. Requirements and PR ownership

| ID | Requirement / acceptance scope | Owning PRs |
| --- | --- | --- |
| REQ-001 | .NET 10 DLL + console; Java 21/Maven JAR + console; independent build/test/package and offline CI | 1, 4, 5 |
| REQ-002 | Reviewed SDK-independent canonicalize/hash/sign/verify abstractions, ownership and stage ordering | 1; port 4 |
| REQ-003 | Synchronous no-I/O crypto, preloaded local keys, separated writer/verifier capabilities and concurrency safety | 1, 4, 5 |
| REQ-004 | Shared versioned envelope, protected metadata, explicit crypto encoding and cross-language fixtures | 1, 4, 5 |
| REQ-005 | Tested canonicalization profile, numeric/Unicode semantics and bounded payload/depth | 1, 4 |
| REQ-006 | Immutable custom ignored root names, protected identity, trusted exclusion-policy fingerprint and tests | 1; port 4; interop 5 |
| REQ-007 | Fail-closed raw-content verification before typed mapping; no mutation; explicit envelope collision handling | 1–5 |
| REQ-008 | .NET typed and stream create/read with guarded client/database/container hierarchy | 1 |
| REQ-009 | Pooled, replayable .NET streams with async transport, ownership, cancellation and bounded memory | 1 foundation; 2 pages; 3 bulk/benchmark |
| REQ-010 | .NET typed + stream replace/upsert, ETags and response-content-on/off behavior | 2 |
| REQ-011 | Guard original SQL and preserve unsigned query parameters; pagination/resume; validate every result | 2, 4 |
| REQ-012 | Latest-version pull change feed, bounded polling, continuation and empty/304 handling | 2, 4 |
| REQ-013 | Native .NET bulk and typed-only transactional batch; no emulated atomicity or raw-result guarantee | 3 |
| REQ-014 | Java serializer and async-container integration, lifecycle/query/feed, lazy validation and option guards | 4 |
| REQ-015 | Native Java bulk/batch with pre-submission checks, backpressure and materialization caveats | 5 |
| REQ-016 | Reject stored-procedure execution at the wrapper boundary before delegate access: .NET typed and both stream overloads through `Container.Scripts`, equivalent Java APIs later. Reject every write requesting nonempty `PreTriggers`/`PostTriggers` before content read/signing/enqueue/submission (create/delete now; replace/upsert later). Copy empty lists and allow them because no trigger is requested; reads retain ordinary option handling/copied lists without the write-trigger guard. Keep Patch blocked even for ignored fields. Preserve guards in bulk/batch and all future surfaces. | 1–5 |
| REQ-017 | Offline negative/ownership tests and safe opt-in Azure tests, with bidirectional interoperability | 1–5; interop 4–5 |
| REQ-018 | Document protocol, operation matrix, packaging/running, key rotation and measured allocation behavior | 1–5; benchmark 3; final 5 |
| REQ-019 | All five concrete providers and crypto/JCS/ASN.1 helpers are console-sample-only with `Unsafe` prefixes; no provider defaults/fallbacks or direct implementation dependencies in reusable libraries. Require explicit injection, including policy hashing, and whole-input validation before exclusions. Tests reference the sample, never a reverse library dependency. Future owning security team supplies validated replacements; user review and security approval remain separate gates. | 1 foundation; preserve 2–3; port 4; verify 5 |

## 3. Shared protocol and interfaces

- `ContentValidationProcessor` is SDK-independent: canonicalization → hashing → signing or verification are separate stages. Sign ordinary serialized document content, not POCO ordering; verify JSON/tree **before** mapping to domain objects, including fields unknown to the POJO/POCO.
- Public synchronous contracts: `IJsonCanonicalizer`, `IContentHasher`, `IContentSigner.SignHash`, `IContentVerifier.VerifyHash`, and in-memory `IVerificationKeyResolver`; equivalent Java interfaces follow in PR4.
- The .NET constructor is `ContentValidationProcessor(options, verificationKeys, canonicalizer, hasher, signer = null)`. The first four arguments are required; only the signer is optional. No built-in/default/fallback provider is selected in the library. `UnsafeSampleProviders` supplies illustrative canonicalizer/hasher defaults only in the sample composition root; verification keys and any signer remain explicit.
- `IJsonCanonicalizer.ValidateInput(JsonElement)` is required and separate from `Canonicalize`: validate the complete raw document, including excluded subtrees, for duplicate decoded names, Unicode, numeric and depth acceptance **before filtering**. It is not a default interface implementation or canonicalization fallback. Preserve this split in Java.
- .NET canonicalization writes UTF-8 to a supplied `IBufferWriter<byte>`; an external adapter may require one documented allocation. Hashing accepts `ReadOnlySequence<byte>`/segments without forced `ToArray`. Digests have a fixed small size; signer/verifier accept the digest (and signature for verification), with no double hashing. Provider identity/algorithm properties must match fixed v1 constraints.
- Document ownership and borrowing in contracts. No pooled view escapes its owner’s lifetime. Use per-call primitives or synchronized/key-scoped crypto resources; do not share unsafe mutable crypto state across concurrent requests.
- Separate private signing capability from public verification capability. Startup may load PEM files; hot paths cannot perform I/O. Unknown `kid` fails without URL loading. Public-key-only processors refuse signing writes; cleanup deletes remain allowed. Rotation uses preloaded old/new public keys.
- **Implemented v1 wire constraints, not built-in crypto:** `rfc8785-binary64-v1`, SHA-256 + ECDSA P-256 prehash, P1363 fixed 64-byte `r || s` and unpadded base64url. The .NET sample uses `UnsafeEcdsaContentSigner`/`UnsafeEcdsaContentVerifier` with system crypto and `UnsafeEcdsaKeyImport` for PKCS#8 private/SPKI public PEM. Java's proposed provider can use `NONEwithECDSAinP1363Format`; Java remains unimplemented. Do not write nonce/crypto primitives. Security-team validation and user wire-format review are pending; provider substitution does not implement crypto agility.
- Reserved root `_contentValidation` envelope fields: `v`, `canonicalization`, `hashAlgorithm`, `signatureAlgorithm`, `exclusionPolicyHash`, `kid`, `signature`.
- Bind the protected envelope header and filtered document together in a canonical signing object with fixed domain separator `CosmosContentValidation`. Exclude the signature value and effective ignored root content; handle envelope removal internally while keeping header metadata signed. Freeze the exact bytes with fixtures.
- Allowlist algorithms, profiles and keys. Missing/malformed envelopes, unknown profiles/keys, policy mismatch and invalid signatures fail closed with named reason codes and preserved causes. No payload/key logging or automatic fallback after validation failure.
- Never mutate caller objects or SDK maps. Typed reads remove the validation envelope from a **copy** before ordinary delegate mapping and retain known metadata as serializer settings permit. Reject reserved application-property collisions. Replace/upsert signs current content anew.
- Stream reads retain the exact signed JSON/envelope. Stream writes replace a recognized envelope while rejecting malformed collisions and sign the edited payload; do not require its old signature to validate intentionally edited content.
- The .NET sample's `UnsafeJcsCanonicalizer` adapts Jcs.Net, using `UnsafeJsonInputValidation` for the restricted `rfc8785-binary64-v1` acceptance profile. Keep dependency/license/vector review [S10–S11] scoped to sample/providers; neither a profile-name match nor test success is security approval. Any future alternative profile requires explicit protocol review, not a silent v1 fallback.
- Document binary64 numeric semantics: large/exact integers and decimals should be strings. Reject detectable unsupported input rather than promise arbitrary-precision preservation. Sort keys recursively by UTF-16 order; preserve array order, avoid Unicode normalization, and distinguish null from missing. Enforce depth/payload limits.
- SDK preprocessing may already lose duplicate-property or numeric lexical information. Do not promise raw-wire guarantees that the extension hooks cannot observe.

## 4. Configurable root exclusion policy

- `ContentValidationOptions.AdditionalIgnoredRootProperties` is a copied, immutable set of exact, **case-sensitive JSON property names**. Effective exclusions are the union of custom names with `_rid`, `_self`, `_etag`, `_attachments`, `_ts` [S09].
- Custom names may include `ttl` and customer fields. Matching is root-only: no wildcards, blanket underscore exclusions, recursive name matching, or nested JSON-pointer rules. Ignoring a root object excludes its whole subtree.
- Preserve ignored values in outbound JSON, returned streams, and deserialized content; omit them **only** from signature computation. `ttl` and customer fields remain authenticated by default. Custom exclusions deliberately permit their addition/removal/change; **excluded values are unauthenticated**.
- Validate policy at construction: reject `id`, every root containing a configured partition-key path, and `_contentValidation`. Internal envelope exclusion cannot be reconfigured to remove protected metadata. Canonicalizer and policy are immutable per processor; writers/readers require the same effective policy.
- Compute `exclusionPolicyHash` once at construction **through the injected canonicalizer and hasher**, as SHA-256 plus unpadded base64url over the sorted, deduplicated canonical descriptor containing root-only scope, policy version, and effective names. The v1 descriptor and fixture bytes are unchanged; no hardcoded concrete provider or policy-hashing fallback remains in the library.
- Cryptographically bind that fingerprint in the protected header. Compare it against trusted local configuration; never accept a document-supplied ignore list or fetch policy via I/O. Tampering and mismatched policy fail closed.
- Changing exclusions changes compatibility. Existing documents need an explicit migration/re-signing plan, not silent acceptance under weaker rules; multi-policy migration is out of scope initially. Patch remains prohibited even when targeting an ignored field.
- PR1 documents both defaults and customized-policy examples and reviews options/policy identity as public contracts. Tests cover default `ttl`/customer tampering failure; custom ignored add/remove/change success; nested same-name protection; case sensitivity; ignored subtrees; mismatch/fingerprint tampering; configuration mutation; and forbidden identity/envelope exclusions. Exercise typed and stream create/read; port in PR4 and cross-verify in PR5.

## 5. .NET stream ownership and performance contract

- Use one long-lived configured `RecyclableMemoryStreamManager` per library configuration [S12]. Bound small/large free pools, maximum buffered payload/page sizes, and bulk/page concurrency. Free-pool limits alone do not bound active memory. The manager is thread-safe; streams are not.
- Buffer non-seekable input once into an owned pooled replayable stream, asynchronously when the stream API permits. Reuse safely owned seekable pooled storage when possible. Hash/validate borrowed sequences or segments using **offset and logical length**, never capacity.
- Prefer `GetReadOnlySequence`, sequence readers and `Utf8JsonWriter`/`IBufferWriter`; the sample's `UnsafeSha256ContentHasher` uses `IncrementalHash.AppendData` per segment. Crypto remains outside the library. `GetBuffer`/`TryGetBuffer` may consolidate segmented blocks; `ToArray` always copies, and `GetStream(existing byte[])` copies into the pool rather than leasing zero-copy storage.
- If a consumer requires contiguous memory, choose contiguous pooled storage up front or consolidate once at a documented boundary. Avoid repeated flattening and read-string/re-encode roundtrips. Canonicalization requires its own representation: do not call the transformation zero-copy.
- **Writes:** snapshot from the caller’s current position, sign through the shared processor into separate pooled output, rewind output, and retain it throughout awaited SDK completion/retries. Leave caller input open and restore a seekable input’s original position even on failure.
- A non-seekable original is consumed and cannot be rewound; replayability applies to the owned replacement/snapshot. A separately requested replay helper may expose that snapshot, but do not claim the original became seekable.
- **Reads:** buffer a successful response once, validate without changing raw JSON, rewind replacement to position zero, and attach it to `ResponseMessage.Content`. Transfer ownership to the returned response/caller; do not dispose before return.
- Dispose the superseded SDK body and dispose response/owned buffers on failure; return each buffer exactly once. Preserve status, headers, diagnostics and service-error body handling; do not parse errors or empty bodies as signed documents.
- Query/change-feed streams contain service envelopes. Validate each item in `Documents`, not envelope or continuation metadata; return the full unchanged envelope. Empty/304 feed pages are not unsigned documents.
- Typed serializer input disposal follows `FromStream`’s SDK contract; `ToStream` output belongs to the SDK. Wrapper stream processing must not invoke typed mapping or double-sign. Async copying and cancellation are separate from synchronous, in-memory crypto.
- Never share concurrent `Position` cursors or retain a borrowed sequence across resize/growth/disposal. Do not expose unused capacity. Optionally zero returned content buffers and measure clearing overhead. Tests detect/throw on library-layer `ToArray` and enable pool-leak diagnostics.
- The library's [internal bounded writer](../dotnet/src/CosmosContentValidation/Internal/BoundedBufferWriter.cs) is a buffer utility, not a provider. Pool/scratch clearing uses buffer APIs, not a direct crypto dependency; the sample owns key-import/DER handling.

## 6. Source-backed SDK integration constraints

- .NET `CosmosSerializer.ToStream<T>`/`FromStream<T>` are synchronous; feed arrays reach `FromStream<T[]>`. Query parameters also use the custom serializer, while SDK resource DTOs use a separate serializer [S01].
- .NET `RequestMessage.OperationType`, `ResourceType`, and `RequestOptions` are internal; public method/URI/headers/content/properties do not replace reliable logical guards. Decorate client/database/container using the public encryption example pattern [S02–S03]. Do not parse binary batch bodies; bulk rejects per-item `Properties` markers.
- .NET stored-procedure execution must fail at the `Container.Scripts` getter **before inner scripts delegate access**, covering `ExecuteStoredProcedureAsync<T>` and both `ExecuteStoredProcedureStreamAsync` overloads (object-array parameters or stream payload). This blocks execution, not merely script management.
- `SnapshotOptions(ItemRequestOptions, bool isWrite = true)` copies trigger lists before checking them. Create/delete use the write default and reject nonempty `PreTriggers`/`PostTriggers` before reading content or dispatching; empty lists request no invocation and remain detached. `ReadItemAsync<T>`/`ReadItemStreamAsync` pass `isWrite: false`, retaining normal option validation/copying without the write-trigger guard. Extend the write rule to replace/upsert and applicable bulk/batch options, and port equivalent semantics to Java; never exempt ignored-field Patch.
- Use ordinary parameter serialization with public `QueryDefinition.WithParameterStream` so parameters are not signed a second time [S04]. Preserve originals and parameter/literal semantics.
- SQL guard: accept a case-insensitive `SELECT * FROM` token prefix with leading/inter-token whitespace and proper boundaries; reject null/empty SQL, leading comments, projections, `VALUE`, and `DISTINCT`/`TOP` prefix forms. Never strip whitespace inside literals. This is not a full SQL parser: nested sources/subqueries can still yield invalid content, which must fail signature validation.
- Java `CosmosItemSerializer` synchronously converts objects/maps; public `DEFAULT_SERIALIZER`, client registration and per-request overrides exist [S05]. Deep-copy SDK-owned maps before mutation.
- Java `CosmosAsyncContainer` has a protected wrapping constructor; relevant overloads need explicit review because forwarding is not uniform [S06]. Its operation policy cannot reliably inspect original SQL: diagnostics construction supplies a null query statement. Guard original arguments; `CosmosOperationDetails` exposes context/diagnostics and `setRequestOptions`, not public `getRequestOptions`. No telemetry workaround.
- Java point `getItem()` is lazy; raw `String`/`byte[]` targets bypass custom deserialization. POJO/Map/JsonNode paths through `Utils.parse` invoke it [S07]. Preserve native responses but state validation timing and raw-access limitations.
- Java `CosmosBatch` is final, but operation enumeration, type and item getters are public. Guard before submit; typed batch materialization uses the effective serializer [S08]. Guard bulk before enqueue as well.
- Java `SqlParameter` uses the item serializer: install a library-owned query serializer that delegates parameter serialization unchanged and validates result deserialization. Never permit that read-mode serializer on document writes [S13].
- Java non-idempotent retry tracking can append a field after serialization. Disable payload-mutating tracking through public options and verify the effect; do not permit arbitrary extra unsigned fields. Evidence: `InternalObjectNode.serializeJsonToByteBuffer` and async-container write paths [S06].
- Candidate SDK pins from release notes: .NET **3.63.2**, Java **4.83.0**; confirm packages and tagged APIs during implementation. Java serializer arrived in 4.59, wrapping in 4.69, with relevant replace/upsert/parameter fixes in 4.79/4.80; do not claim all 4.x supported.
- The .NET **sample** pins **Jcs.Net 0.1.1** (.NET 8+, MIT, young/small); **io.github.erdtman:java-json-canonicalization:1.1** (Java 8+, Apache 2, older/established) remains a Java sample-provider candidate. Neither belongs in the reusable library's direct dependencies. Verify vectors/licenses independently of compliance claims [S10–S11]. The .NET pool pins **3.0.1** [S12].

## 7. Five-PR execution checklist

### PR1 — Shared contract, .NET create/read, stream foundation

**Status:** PR1 foundation implemented; prior offline results are recorded, not evidence for subsequent provider/guard edits. **Dependencies:** None. **Review/validation gates still pending:** verification of new changes, live Azure execution, future security-team validated provider replacements, and user public-interface, wire-format, exclusion-policy, boundary and ownership review.

- [ ] **P1.1** Specify protocol, numeric domain, error model, no-I/O key lifecycle, staged interfaces, immutable policy and stream ownership; obtain user review of fixed v1 constraints and provider boundary, and security-team validation/replacement approval separately. **REQ-002–006, REQ-018–019**
- [x] **P1.2** Scaffold .NET solution, reusable DLL, console and xUnit unit/live test projects; pin dependencies and add secrets-free offline CI, README and ignore-rule updates. **REQ-001, REQ-017**
- [x] **P1.3** Implement provider-free processor with required injection, whole-input validation before exclusions and delegated policy hashing; place all five illustrative `Unsafe` providers and crypto/JCS helpers in the console sample, composed by `UnsafeSampleProviders`. Preserve golden protocol/policy vectors and one-way sample/test project references. Implementation is not security approval or a new verification result. **REQ-002–007, REQ-019**
- [x] **P1.4** Implement `ContentValidationSerializer`: sign document writes, verify objects/feed arrays before mapping, preserve ownership and avoid caller mutation. Ordinary delegate mapping is available; query parameter integration remains PR2. **REQ-007–008**
- [x] **P1.5** Implement client/database/container decorators and installing factory; preserve wrapper hierarchy. Allow typed/stream create/read and cleanup delete; block stored-procedure execution (typed/two stream overloads) at `Scripts` before delegate access. Reject nonempty write-trigger lists before content read/submission, copy permitted empty lists, and leave reads outside the write-trigger guard. Reject SDK serializer-bypass DTOs, Patch including ignored targets, unsafe options, resource-returning management and not-yet-supported operations. **REQ-008, REQ-016**
- [x] **P1.6** Implement pooled create/read `StreamAsync` adapters through the shared processor; asynchronous transport, synchronous crypto, replay/rewind and correct ownership through retry/cancellation. **REQ-003, REQ-009**
- [x] **P1.7** Console: explicit `UnsafeSampleProviders` composition, externally loaded keys, writer/public-only reader, typed/stream create/read, default/custom exclusion examples and scoped tampering through a separate intentionally unprotected test client. **REQ-003, REQ-006, REQ-008, REQ-018–019**
- [ ] **P1.8** Test crypto ordering/digest lengths, metadata/custom exclusions, malformed/missing signatures, keys/profiles, reserved collisions, concurrency/no-mutation; stream seekability/chunking/current position/offset/growth/disposal/errors/cancellation; sample-only provider/direct-dependency/emitted-assembly architecture; explicit injection, whole-input validation and policy-provider calls; every stored-procedure overload, write-trigger pre-read/pre-submit rejection, empty-list snapshots and read-only guard exemption; live create/read, service metadata and tampering. **REQ-002–009, REQ-016–017, REQ-019**

P1.1 specifications and public interfaces are implemented, awaiting user review and future security-team provider validation/replacement.
Use the [latest validation report](pr1-validation.md) for executed test counts, packaging and offline-console results rather than treating an older baseline count as current.
The new wrapper tests `EveryStoredProcedureExecutionOverloadIsRejectedAtContainerBoundary`, `WriteTriggerExecutionIsRejectedBeforeContentReadOrSubmission`,
`EmptyWriteTriggerListsAreAllowedAndSnapshottedBeforeInputIsRead` and `TriggerGuardIsWriteOnlyAndReadOptionsAreCopied` are present in
[CosmosWrapperTests](../dotnet/tests/CosmosContentValidation.Tests/CosmosWrapperTests.cs); architecture tests are updated in
[ArchitectureTests](../dotnet/tests/CosmosContentValidation.Tests/ArchitectureTests.cs). Their presence does not establish a passing run.
Six live theory groups (24 enabled Direct/Gateway cases) require external Azure configuration and opt-in. The .NET solution is
[dotnet/CosmosContentValidation.slnx](../dotnet/CosmosContentValidation.slnx).

### PR2 — .NET lifecycle, queries, latest-version change feed

**Status:** Not started. **Depends on:** PR1. Query/feed work may run in parallel after serializer/buffer completion.

Carry REQ-019's sample-only provider boundary and REQ-016's stored-procedure/write-trigger guards forward; adding APIs must not add library provider defaults.

- [ ] **P2.1** Enable typed/stream replace/upsert insert+update, ETag conditional replace, response content on/off; reject nonempty pre/post-trigger lists before input read/signing/submission, snapshot empty lists, verify returned bodies and demonstrate readback for status-only writes. **REQ-007, REQ-009–010, REQ-016, REQ-019**
- [ ] **P2.2** Guard every query overload before delegation. Clone definitions/parameters as needed and use ordinary serialization plus `WithParameterStream`, including object parameters containing `id`; leave caller SQL/literals/options intact. **REQ-011, REQ-016**
- [ ] **P2.3** Add typed/stream full-document WHERE/ORDER BY, single/cross-partition, empty-page and continuation-resume examples. Stream paths inspect service envelopes; typed arrays verify every item. Invalid content fails materialization rather than being skipped. **REQ-007, REQ-009, REQ-011, REQ-018**
- [ ] **P2.4** Add `GetChangeFeedIterator`/`GetChangeFeedStreamIterator` latest-version pull examples with bounded polling, resume and empty/304 handling. Checkpoint only after processing a valid page; no all-versions/delete guarantee. **REQ-009, REQ-012, REQ-018**
- [ ] **P2.5** Test guards before submission, including zero-result projections, all stored-procedure entry points and nonempty triggers on every write. Cover empty-list snapshot mutation and reads retaining ordinary options without the write guard; preserve provider-architecture checks. Test later-page query/feed tampering or missing signatures, retry replay, cancellation and preserved errors. Keep Patch (even ignored targets), LINQ/full-fidelity/processor integration explicitly unsupported. **REQ-007, REQ-009–012, REQ-016–017, REQ-019**

### PR3 — .NET native bulk and transactional batch

**Status:** Not started. **Depends on:** PR2. Completes .NET before Java begins.

Carry REQ-019's sample-only providers and explicit injection into bulk/batch, without exposing stored-procedure execution or weakening REQ-016.

- [ ] **P3.1** Use actual `AllowBulkExecution` with bounded typed and stream operations; serializer/shared-processor protection, Patch rejection before enqueue (including remove-only and ignored-target Patch), and nonempty write-trigger rejection before content read/enqueue. Snapshot allowed empty lists; reads retain ordinary option handling. No bulk property markers or binary parsing. **REQ-009, REQ-013, REQ-016, REQ-019**
- [ ] **P3.2** Add `ContentValidationTransactionalBatch`: native same-partition typed create/read/replace/upsert/delete, safe caller options and atomicity. Reject every Patch overload and raw stream batch addition; enforce REQ-016 for every write option surface before submission, without imposing write-trigger checks on reads. Never emulate a transaction with sequential point calls. **REQ-013, REQ-016, REQ-019**
- [ ] **P3.3** Validate typed `GetOperationResultAtIndex<T>` and document timing. Batch is **typed-only**; point `StreamAsync` and query/feed stream iterators remain supported. Native `ResourceStream` is not advertised as protected; raw batch results are excluded, without another response facade. Status-only success is not content validation. **REQ-007, REQ-013, REQ-018**
- [ ] **P3.4** Retain offline provider-architecture and all stored-procedure/write-trigger guard regressions, including empty-list copying and read exemption. Live mixed batches, atomic rollback/conflict/424, bulk partial failures/retries/cancellation, content on/off and persisted readback; buffers survive retry and return exactly once. A validation error after commit is **not** transaction rollback. **REQ-009, REQ-013, REQ-016–017, REQ-019**
- [ ] **P3.5** Benchmark naive `MemoryStream` + `ToArray` versus pooled replay for small/large documents/pages; report allocations, LOH and throughput without invented targets. Finish .NET API matrix and runnable DLL/sample documentation. **REQ-009, REQ-018**

### PR4 — Java core, lifecycle, queries and change feed

**Status:** Not started. **Depends on:** PR3. Consume reviewed protocol/fixtures; no separate design fork.

- [ ] **P4.1** Scaffold Maven parent, provider-free reusable JAR, console and JUnit 5/Surefire/Failsafe offline/live tests; Java 21 and pinned SDK, with canonicalizer dependency only in the console sample module. Tests may depend on sample providers; never reverse that dependency into the library. No SDK repository edits. **REQ-001, REQ-014, REQ-017, REQ-019**
- [ ] **P4.2** Port synchronous interfaces and provider-free processor with explicit injection, required whole-input validation before filtering, immutable exclusions/fingerprint computed by the injected canonicalizer/hasher, and custom serializer. Put all concrete providers and crypto/JCS helpers in the Java console sample with `Unsafe` prefixes and the same security-team replacement warning; no library defaults. Deep-copy maps, verify before POJO mapping, use a thread-safe JCA strategy in sample providers and ordinary `DEFAULT_SERIALIZER`/custom-mapper delegation. **REQ-002–007, REQ-014, REQ-019**
- [ ] **P4.3** Extend `CosmosAsyncContainer`; audit/guard all relevant overloads and preserve native responses/feeds. Reject stored-procedure execution at the wrapper boundary before underlying delegate access; reject all writes requesting nonempty pre/post triggers before content processing/submission. Snapshot empty lists without permitting later mutation; reads retain ordinary options without the write guard. Reject Patch even for ignored fields, unprotected raw String/byte[] pathways, arbitrary serializer overrides and unsupported APIs; disable retry payload tracking through public settings. **REQ-014, REQ-016**
- [ ] **P4.4** Install query-only parameter-pass-through/result-validating serializer; guard original SQL, not policy diagnostics; safely copy request options and prevent read-mode serializer use for writes. **REQ-011, REQ-014, REQ-016**
- [ ] **P4.5** Console create/read/replace/upsert insert+update, pagination/resume and latest-version `queryChangeFeed` with bounded polling. Force `getItem`/iteration to show lazy validation, not status-only assurance. Top-level console blocking is allowed, never blocking async inside crypto hooks. **REQ-003, REQ-011–012, REQ-014, REQ-018**
- [ ] **P4.6** Port positive/negative tests, custom exclusions, client/per-request serializer selection, fields unknown to POJO, numeric/Unicode/metadata compatibility, parameters and feed resume. Include provider/dependency architecture, no-fallback construction, whole-input validation/policy-provider delegation, every stored-procedure execution overload, nonempty write-trigger pre-processing/pre-submission rejection, empty-list mutation isolation and read-option copying without the write guard. Run live Java↔.NET point/lifecycle interop. Async container is primary; separate Java sync wrapper is not required. **REQ-005–007, REQ-011–012, REQ-014, REQ-016–017, REQ-019**

### PR5 — Java bulk/batch and final cross-language validation

**Status:** Not started. **Depends on:** PR4.

Retain REQ-019's sample-only `Unsafe` implementations, required injection and future security-team/user review gates in Java and .NET. Stored-procedure execution stays blocked; do not weaken the write-only trigger rule for bulk/batch.

- [ ] **P5.1** `executeBulkOperations`: check type/payload/options before each enqueue, reject nonempty write-trigger lists before content processing/enqueue and copy permitted empty lists; preserve ordinary read-option semantics. Retain backpressure/context/native responses; guarded factories prevent hidden unsafe per-item options from bypassing policy, without internal casts/reflection. **REQ-015–017, REQ-019**
- [ ] **P5.2** `executeCosmosBatch`: inspect public operation enumeration/types, reject Patch (including ignored targets)/unknown/raw operations before entire submission; enforce nonempty write-trigger rejection on every exposed write-option path. Guarded builder records otherwise uninspectable safe options. Snapshot/copy using public builders or prohibit mutation during use; an unmodifiable list is not an immutable snapshot. **REQ-015–017, REQ-019**
- [ ] **P5.3** Serializer signs writes and verifies typed batch/bulk `getItem`; demonstrate no-content readback, errors and atomic rollback versus post-commit content errors. State lazy/raw-access limits explicitly. **REQ-007, REQ-015, REQ-018**
- [ ] **P5.4** Mirror .NET bulk/batch tests, including provider/dependency boundaries, every stored-procedure execution entry point, nonempty write-trigger rejection, empty-list snapshots and read-only exemption. Bidirectional live write/read/query/feed/update and bulk/batch output verification, including custom exclusion policies. Compare canonical bytes/digests; randomized signatures are cross-verified, not required to have equal bytes. **REQ-004, REQ-006, REQ-015–017, REQ-019**
- [ ] **P5.5** Final protocol/API matrix, DLL/JAR packaging and run/test documentation, coordinated README update, preloaded old+new key rotation demo, secrets-free offline CI and trusted opt-in live execution. Retain explicit unreviewed-sample warnings and future security-team replacement/user-review responsibilities; no publishing/deployment automation. **REQ-001, REQ-003, REQ-018–019**

## 8. Verification and security boundaries

- Each PR must independently build, test and package its available library/console: .NET build/test, Maven verify, and explicit live profile after scaffolding. Only the [validation report](pr1-validation.md) records executed PR1 results; this updated plan makes no pass claim for new changes or future PRs.
- Offline tests cover stage ordering, wrong digest length/double hashing, default/custom root versus nested exclusions, policy mismatch, missing/invalid signature, unknown profile/key, arrays/null/missing, escaped names/property ordering, safe-number boundaries, invalid input, concurrency, mutation and I/O-free providers.
- Stream tests prove readability after validation, restored seekable positions, non-seekable replacement replay, response/error metadata preservation, cancellation, no use-after-return/double-return/finalizer reliance/shared cursors, and no extra `ToArray`/repeated flattening. Include pool concurrency/memory-growth tests and non-brittle allocation benchmarks.
- Guard tests must prove rejection **before content read/signing/enqueue/submission**, including every stored-procedure execution overload before delegate access, nonempty pre/post triggers on all writes, zero-result projections and remove-only/ignored-target Patch in bulk/batch. Empty trigger lists must be detached before input consumption; reads keep ordinary option checks/copies without write-trigger rejection. Startup metadata network calls are distinct from submitting a content operation.
- Architecture tests must check all five concrete providers are sample-only with `Unsafe` prefixes and that libraries have no provider implementations, defaults/fallbacks, direct crypto/ASN.1/JCS dependencies or reverse sample references (including emitted .NET assembly references). Processor tests cover required injection, full-input validation before exclusions and delegated policy hashing. These checks do not establish that all transitive SDK/auth dependencies are crypto-free or that providers are security reviewed.
- Live tests use external endpoint/auth and a preprovisioned dedicated container, unique run IDs/partition keys, bounded data/cost and cleanup of test-owned records only. The unprotected tamper client touches only scoped test data. Exercise Direct/Gateway where supported; never provision accounts automatically or expose secrets to fork CI.
- Signatures establish integrity/authenticity under a trusted key, **not** freshness/rollback protection, deletion prevention, availability, query completeness/filter correctness/order, storage location or point-request correspondence. Signed `id`/partition keys do not prevent replay of whole valid signed documents.
- Excluded metadata/custom fields are untrusted. TTL is signed by default but can be deliberately excluded; neither signing TTL nor validating content prevents expiry. This is not access control or protection against signing-key compromise.
- Excluded initially: SDK edits/internal bridges, LINQ, scripts/triggers, full-fidelity change-feed envelopes, processor leases/Functions integration, automatic unsigned backfill, arbitrary-precision guarantees, full custom JCS, encryption composition, production key-service integration, nested/wildcard exclusions and automatic multi-policy migration. Raw transactional-batch paths are not a protected surface.

## 9. Planned artifact layout

PR1 artifacts include the [library](../dotnet/src/CosmosContentValidation/CosmosContentValidation.csproj),
[console](../dotnet/samples/CosmosContentValidation.Sample/Program.cs), [protocol](content-validation-protocol.md) and
[shared fixtures](../shared/test-vectors/default-policy.json). Java and benchmarks remain future destinations.
The .NET 10 solution uses [dotnet/CosmosContentValidation.slnx](../dotnet/CosmosContentValidation.slnx).

| Area | Planned artifacts |
| --- | --- |
| Shared documentation | Protocol/stages/envelope/fixtures/no-I/O contract; security and supported/blocked/unguarded operation matrix; stream ownership |
| Shared fixtures | Cross-language canonical bytes, digest/signature and exclusion-policy vectors under shared/test-vectors |
| .NET solution | Provider-free reusable library, abstractions, processor, serializer, pools/internal bounded writer and client/database/container hierarchy; transactional-batch decorator remains PR3 work |
| .NET validation/sample | Console entry point and all concrete `Unsafe` providers/helpers; xUnit unit/live tests reference the sample. Allocation benchmarks remain PR3 work |
| Java Maven modules | Future parent, provider-free library with abstractions/processor/serializer/guards and separate console with `Unsafe` providers/helpers; tests depend on sample providers, not the reverse |
| Automation | Offline workflows under .github/workflows; explicit trusted live-test opt-in, no fork secrets |

## 10. Sources and review gates

These are the approved plan’s research references, not a claim that moving branch tips equal the eventual pinned package APIs. Reconfirm tagged sources and dependencies during implementation.

- **S01:** [.NET CosmosSerializerCore — serializer routing and feed arrays](https://raw.githubusercontent.com/Azure/azure-cosmos-dotnet-v3/master/Microsoft.Azure.Cosmos/src/Serializer/CosmosSerializerCore.cs)
- **S02:** [.NET EncryptionCosmosClient — public client decoration reference](https://raw.githubusercontent.com/Azure/azure-cosmos-dotnet-v3/master/Microsoft.Azure.Cosmos.Encryption/src/EncryptionCosmosClient.cs)
- **S03:** [.NET EncryptionContainer — container/batch decoration reference](https://raw.githubusercontent.com/Azure/azure-cosmos-dotnet-v3/master/Microsoft.Azure.Cosmos.Encryption/src/EncryptionContainer.cs)
- **S04:** [.NET QueryDefinition.WithParameterStream public API](https://learn.microsoft.com/en-us/dotnet/api/microsoft.azure.cosmos.querydefinition.withparameterstream)
- **S05:** [Java CosmosItemSerializer — contracts and default serializer](https://raw.githubusercontent.com/Azure/azure-sdk-for-java/main/sdk/cosmos/azure-cosmos/src/main/java/com/azure/cosmos/CosmosItemSerializer.java)
- **S06:** [Java CosmosAsyncContainer — wrapping, overloads, policy diagnostics and write paths](https://raw.githubusercontent.com/Azure/azure-sdk-for-java/main/sdk/cosmos/azure-cosmos/src/main/java/com/azure/cosmos/CosmosAsyncContainer.java)
- **S07:** [Java CosmosItemResponse — lazy materialization and raw-target behavior](https://raw.githubusercontent.com/Azure/azure-sdk-for-java/main/sdk/cosmos/azure-cosmos/src/main/java/com/azure/cosmos/models/CosmosItemResponse.java)
- **S08:** [Java CosmosBatch — public operation inspection](https://raw.githubusercontent.com/Azure/azure-sdk-for-java/main/sdk/cosmos/azure-cosmos/src/main/java/com/azure/cosmos/models/CosmosBatch.java)
- **S09:** [Cosmos DB document resource — five service-owned root fields](https://learn.microsoft.com/en-us/rest/api/cosmos-db/documents)
- **S10:** [Jcs.Net 0.1.1 candidate package](https://www.nuget.org/packages/Jcs.Net/0.1.1)
- **S11:** [Java JSON canonicalization 1.1 candidate package](https://central.sonatype.com/artifact/io.github.erdtman/java-json-canonicalization/1.1)
- **S12:** [Microsoft.IO.RecyclableMemoryStream — pooling and copying/sequence contracts](https://github.com/microsoft/Microsoft.IO.RecyclableMemoryStream)
- **S13:** [Java SqlParameter — parameter serialization](https://raw.githubusercontent.com/Azure/azure-sdk-for-java/main/sdk/cosmos/azure-cosmos/src/main/java/com/azure/cosmos/models/SqlParameter.java)

**Review responsibilities and gates:** The future owning security team must supply and validate replacements for **all five** sample providers,
including canonicalization/input acceptance, hashing, key import/resolution, signing/verification, concurrency and dependencies.
`Unsafe` examples and test results are not that approval. User review must approve public interfaces, explicit injection/no defaults,
ownership, the synchronous no-I/O contract, fixed v1 wire identifiers/prehash semantics, delegated policy identity, exclusions and signature metadata binding.
Review every stored-procedure execution entry point, write-trigger snapshot/check ordering, the read-only exemption and ignored-field Patch rejection.
Keep direct library dependency/emitted-reference checks distinct from transitive transport/auth crypto. These gates apply to Java as well;
PR2–PR5 remain not started. Guards, security tests and fail-closed behavior are prerequisites in every relevant PR, never deferred to final hardening.
