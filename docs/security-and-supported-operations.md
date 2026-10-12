# Security and supported operations (PR1)

This describes the current .NET 10 library with Cosmos SDK **3.63.2**, not every SDK version or later planned PR.
Read with the [wire protocol](content-validation-protocol.md), [approved plan](implementation-plan.md) and [live-test guide](live-tests.md).

## 1. What is and is not trusted

For a document passing validation, the signature authenticates its included content and protected header under a locally trusted key.
The reader need not trust the server to preserve **included content**: it recomputes the digest and checks the signature locally.
Trust still rests in key provisioning, private-key custody, local policy/providers, application code and its execution environment.
Large/custom exclusion policies are not a prerequisite for this claim; defaults exclude only the five documented service root fields.
Every excluded field is **unauthenticated**, including service metadata and any deliberately excluded `ttl` or customer subtree.
Preserving such values in responses is not an endorsement of their accuracy. Application code must not mistake them for signed claims.

Signatures provide **no** availability, completeness, query-filter correctness, ordering, freshness, rollback/replay or deletion guarantee.
They do not prevent expiry, prove physical storage location or point-request correspondence, or prove a write was durably performed.
Signed `id`/partition-key values do not prevent substitution/replay of an entire previously valid signed document.
ETags, session tokens, HTTP status, diagnostics and response headers are native service data, not content-signature guarantees.
This is neither access control nor encryption, and does not protect against compromised signing keys or malicious trusted local providers.

### Sample providers are not a security approval

All concrete canonicalizer, hasher, signer, verifier and resolver implementations are console-sample-only,
in `CosmosContentValidation.Sample.Providers`, with `Unsafe` prefixes. **`Unsafe` means illustrative and NOT security reviewed,
not deliberately flawed cryptography.** The future owning security team must supply security-validated implementations of all five interfaces.
Passing tests do not replace that team's validation or user review. See the [provider inventory and replacement contract](../dotnet/samples/CosmosContentValidation.Sample/Providers/README.md).

The reusable library contains abstractions, Cosmos extension wrappers, JSON processing/serialization and pools;
it supplies **no built-in, default or fallback content-protection providers**. Its constructor requires
`ContentValidationProcessor(options, verificationKeys, canonicalizer, hasher, signer = null)`; only signing capability is optional.
The library has no direct crypto/ASN.1/JCS dependency or emitted assembly reference to those implementations or the sample.
This is a boundary on the library itself, **not** a claim that Cosmos SDK/Azure authentication transitives are crypto-free:
transport and authentication still use cryptography. The sample references the library, and tests reference the sample, never the reverse.

## 2. Current protected operation matrix

Use `ContentValidationClient.Create` and navigate through its guarded database/container objects.
The [client](../dotnet/src/CosmosContentValidation/Cosmos/ContentValidationClient.cs),
[database](../dotnet/src/CosmosContentValidation/Cosmos/ContentValidationDatabase.cs) and
[container](../dotnet/src/CosmosContentValidation/Cosmos/ContentValidationContainer.cs) are public SDK-derived wrappers.

| Surface | PR1 behavior |
| --- | --- |
| Typed `CreateItemAsync<T>` | Sign via the installed serializer; require signer, explicit partition key, safe type/options. |
| Typed `ReadItemAsync<T>` | Validate raw document before ordinary mapping; invalid/missing signatures fail. |
| `CreateItemStreamAsync` | Snapshot input, sign via the shared processor, validate any nonempty successful returned document. |
| `ReadItemStreamAsync` | Validate the successful body before returning a rewound, unchanged signed JSON stream. |
| Typed/stream point delete | Allowed for cleanup without a signing key or prior valid signature; not proof of deleted-content validation. |
| `GetDatabase`, `GetContainer`, `Database.Client`, `Container.Database` | Navigation remains inside the guarded hierarchy. |
| `ReadAccountAsync`, scalar `ReadThroughputAsync(CancellationToken)` | Allowed native metadata/scalar utilities, **not** authenticated document reads. |
| Database/container management and resource-returning throughput responses | Blocked, including metadata reads, provisioning, replacement and deletion. |
| Replace, upsert, patch (including ignored-field-only patch), read-many, partition-wide delete | Blocked before inner content submission. |
| Queries, LINQ, all change-feed/processor/estimator APIs and feed-range APIs | Blocked in PR1. |
| Stored-procedure execution: typed and both stream overloads | `Container.Scripts` throws before accessing the inner delegate; no execution or argument-stream consumption. All scripts access is blocked. |
| Writes requesting nonempty `PreTriggers` or `PostTriggers` | Rejected before content read/signing/submission for typed/stream create and delete; the same rule is required for future replace/upsert. |
| Empty write-trigger lists | Allowed because no trigger is requested; copied before content is read or the request is submitted. |
| Read options with trigger lists | Copied with ordinary supported options, without applying the write-trigger guard; this does not enable trigger execution on reads. |
| Bulk, transactional batch, conflicts, users/permissions and client-encryption-key management | Not exposed as supported protected operations. |

Resource-returning management responses are blocked because their native resource handles can escape to an unguarded SDK hierarchy.
Raw management response overloads are blocked too; account metadata and scalar throughput exceptions above do not validate document content.
Preprovision resources separately. **Independently check every target container's actual partition-key paths against processor configuration before use.**
The factory does not make this check; sample/live entry points do, and require exactly `/pk`. Startup metadata I/O is not crypto-hook I/O.

Stored procedures can read/write without the client content pipeline; triggers can mutate content outside that pipeline.
The boundary therefore rejects **execution**, not just script creation/management. It covers
`ExecuteStoredProcedureAsync<T>` and both `ExecuteStoredProcedureStreamAsync` forms (object-array parameters and stream payload)
at the `Scripts` getter, before retrieving an underlying scripts delegate. Direct use of an unguarded SDK client remains outside this boundary.
Patch is always blocked, even if every target is excluded from the signature; exclusions do not authorize Patch or trigger execution.

## 3. Type guards and native SDK boundaries

Typed generic targets assignable to `Stream` are unsupported; use guarded `StreamAsync` methods instead. Runtime stream write inputs also fail.
Cosmos 3.63.2 selects its own serializer for certain **exact generic SDK-owned resource DTO types**, bypassing the custom serializer.
Guarded typed create/read/delete therefore reject `AccountProperties`, `DatabaseProperties`, `ContainerProperties`, `PermissionProperties`,
`StoredProcedureProperties`, `TriggerProperties`, `UserDefinedFunctionProperties`, `UserProperties`, `ConflictProperties`,
`ThroughputProperties` and `ClientEncryptionKeyProperties`. Routing depends on generic `T`, not merely an object's runtime type.
This list is pin-specific: review SDK routing on upgrade rather than claiming every publicly usable generic target is protected.
Successful typed responses expected to contain content must materialize a nondefault resource; missing bodies fail with `MissingSignature`.
Default-valued structs are deliberately unsupported as content responses because the SDK can produce `default(T)` without invoking the serializer.

`ResponseFactory` is a **native SDK response-construction utility**, not a protected raw API; SDK DTO routing can bypass validation there.
Native/raw operations outside the wrappers, including an independently retained client/container, are **not protected** by these guards.
Installing the serializer alone does not cover stream APIs or stop unsupported operations that do not invoke it.
The full SDK cannot sandbox a caller holding an underlying client, credentials or reflection access. Wrappers are an operation boundary, not a security sandbox.
Reflection in API-surface tests is a review tripwire, not a production protection mechanism or internal SDK bridge.

## 4. Options and injection

Factories accept ordinary `CosmosClientOptions` only and copy the supported subset; unsupported nondefault settings are rejected, not silently ignored.
Accepted fields are `ApplicationName`, `ApplicationRegion`, `ApplicationPreferredRegions`, `ConnectionMode`, `ConsistencyLevel`,
`RequestTimeout`, `MaxRetryAttemptsOnRateLimitedRequests`, `MaxRetryWaitTimeOnRateLimitedRequests`, `LimitToEndpoint`,
and `EnableContentResponseOnWrite`. Region collections and returned `ClientOptions` snapshots are detached.
Bulk, custom serializers/serializer options, handlers, HTTP factories/proxies, custom certificate callbacks and other unsupported transport/settings fail.
The factory installs its own `ContentValidationSerializer`; it does **not** accept a custom ordinary mapper through client options.
A custom ordinary `CosmosSerializer` is supported separately through the **serializer constructor**, without implying factory integration.
That caller-owned mapper must be thread-safe, perform no I/O/content protection, and not retain borrowed streams; stacked validation serializers fail.

Permitted item options are snapshotted before reading/awaiting input or submitting the request; nested supported cache/threshold settings and region lists are copied.
`SnapshotOptions` has `bool isWrite = true`. It copies `PreTriggers` and `PostTriggers` **before checking** their counts,
then rejects a write if either copied list is nonempty. Typed/stream create and delete use that default.
Null/empty write lists request no invocation and are allowed; later caller mutation cannot attach a trigger to the detached snapshot.
`ReadItemAsync<T>` and `ReadItemStreamAsync` pass `isWrite: false`: even nonempty lists are copied, not rejected by the write-trigger guard.
Ordinary option validation still applies on reads. Derived options, `Properties`, `AddRequestHeaders` and availability hooks remain rejected.
Processor exclusion/path options are also copied. Do not mutate supplied objects concurrently with construction/snapshotting.
Injectable crypto/canonicalizer implementations must retain the fixed v1 profile/algorithm semantics; they do not enable arbitrary algorithm negotiation.
The same injected canonicalizer and hasher compute policy identity and document digests; no hidden built-in provider handles policy hashing.
See [protocol provider contracts](content-validation-protocol.md) for synchronous no-I/O behavior, preloaded keys and caller-owned disposal.

## 5. Content validation and response semantics

Typed writes sign ordinary serialized JSON once. Typed reads validate raw JSON **before POCO mapping**, including model-unknown fields.
They strip the root signature envelope from a copy; the original input is not mutated, and service metadata is not removed or authenticated.
Ignored fields remain in the mapping copy; mapper settings decide which values survive in the model. Unknown signed fields are still checked first.
Stream operations bypass typed mapping and explicitly use the same processor. Stream reads preserve every original response byte and envelope.
An existing envelope normally causes `ReservedProperty`; stream signing explicitly enables `replaceExistingSignature` for re-sign compatibility.
That path checks envelope shape, profile, encoding and local policy, but **does not verify the old signature against edited content**.
The caller is authorizing a new signature, not proving the incoming edited document was authentic. Ignored/untrusted values are preserved as such.

Malformed JSON, unknown keys/profiles, invalid signatures and signed-policy mismatch fail closed on protected document reads.
The processor calls required `IJsonCanonicalizer.ValidateInput` on the complete raw tree **before excluded-property filtering**;
its structural/profile checks are separate from `Canonicalize`. Even excluded metadata/subtrees must satisfy numeric, Unicode,
duplicate-name and depth acceptance, and the processor enforces size limits; exclusion is not a parser bypass.
With `EnableContentResponseOnWrite=false`, an absent/empty successful create body is allowed and is **status-only**, not validated content.
For guarded stream create/read, **every nonempty successful body is validated even when write-content responses are disabled**.
When content is expected, absent/empty successful bodies fail; a 204 is not an exemption for a document read.
Non-success stream responses, including HTTP 304 and service errors, pass through raw with status, headers, body and diagnostics untouched and **unverified**.
Delete stream responses also pass through without document parsing, even if nonempty; cleanup is intentionally not a document-validation operation.
Native typed service-error behavior remains the SDK's. A later readback can validate returned content, but does not establish freshness or proof of write.
Verification/materialization may fail **after a create committed**; the exception does not roll back the write or prove it never happened.

## 6. Stream and provider ownership

Caller write streams remain open. Copying starts at their **current position**, not zero, and restores a seekable source's position even on failure.
A nonseekable original is consumed; only the owned snapshot/replacement can be rewound and replayed. It does not make the original seekable.
Async transport copying honors cancellation; hashing, key lookup and signing/verification remain synchronous and in-memory.
The wrapper holds its input snapshot and separate signed output through awaited SDK completion/retries and response processing.
Each operation owns independent cursors; pooled streams themselves must not be shared concurrently.

For a valid successful stream response, the superseded SDK body is disposed and the rewound pooled body becomes `ResponseMessage.Content`.
The returned response owns that body **until the caller disposes the response**. Do not return it from an already-disposed response scope.
Failed validation/cancellation disposes owned response/buffers; a non-success raw response remains caller-owned and must still be disposed.
`ContentValidationSerializer.FromStream` owns/disposes its input, including failure; `ToStream` output ownership transfers to the SDK/caller.
The ordinary delegate receives a nonowning read view while the serializer retains the pooled owner; neither views nor sequences may be retained.
`ReadOnlySequence<byte>` is borrowed, covers logical length/offsets rather than capacity, and is invalid after owner disposal or resizing/growth.
Do not store a borrowed sequence for later use, read returned storage, or expect clearing to make a stale reference safe.
The client owns only its inner SDK client. Providers, processor, ordinary mapper and supplied token credential remain caller-owned.
Dispose clients after outstanding work, then providers; the sample's `UnsafeEcdsaContentSigner` and `UnsafeEcdsaContentVerifier`
synchronize operations/disposal and own their imported handles. Replacement providers require security-team review of the same lifecycle contract.

## 7. Pooling is bounded storage, not zero allocation

[PooledJsonBufferPool](../dotnet/src/CosmosContentValidation/PooledJsonBufferPool.cs) uses Microsoft.IO.RecyclableMemoryStream **3.0.1**.
One manager per processor pool is shared safely; default small blocks are 16 KiB and small/large free pools are limited to 16 MiB each.
Logical document/intermediate limits are separate from rounded capacity. Free-pool limits **do not cap globally active memory or concurrency**.
Bound application concurrency; multiple simultaneous buffers, parsed trees and provider output can exceed a single-document limit in aggregate.
Copies fill available blocks via `GetMemory(1)`/`GetSpan(1)` to avoid large temporary reservations in the copy loop.
[BoundedBufferWriter](../dotnet/src/CosmosContentValidation/Internal/BoundedBufferWriter.cs) enforces actual written length, not worst-case JSON escaping hints.
It uses cleared pooled scratch where needed and completes outstanding reservations with `Advance(0)` on cleanup:
this works around RMS 3.0.1 not returning a temporary `IBufferWriter` reservation on disposal after a failed write.
Sequence-based hashing avoids flattening/`ToArray`; the configured pool throws on stream `ToArray`. `GetBuffer` may consolidate/copy segments.
This is **not zero-copy or zero-allocation**: the sample's `UnsafeJcsCanonicalizer` uses Jcs.Net, which returns a full canonical byte array per canonicalized subtree that the adapter writes into its destination.
`JsonDocument`, filtered trees, mapping, small digest/signature arrays and reservation scratch also allocate or copy; these are accepted boundaries.
Pooled content has `ZeroOutBuffer=true`, and scratch is returned with `clearArray: true`; these library buffer utilities need no direct crypto reference.
Separately, the sample's `UnsafeEcdsaKeyImport` zeroes decoded key DER. Immutable PEM strings and all managed copies are not erasable.
Do not claim allocation/throughput improvements without measurement; the comparative benchmark belongs to PR3, not completed PR1 evidence.

## 8. Operational checks, tests and later work

The [console source](../dotnet/samples/CosmosContentValidation.Sample/Program.cs) loads external PEM once, probes key agreement before network use,
then uses a preprovisioned dedicated container, separate writer/public-only reader and optional intentionally unprotected tamper client.
The console and tests use `UnsafeSampleProviders` for sample composition; the library never creates these providers implicitly.
Tampering/cleanup is limited to acknowledged run-owned IDs; ambiguous post-commit failures require manual inspection, not automatic deletion.
See [live-tests.md](live-tests.md) for explicit opt-in, external credentials, `/pk` metadata checks, bounded cleanup and Direct/Gateway scenarios.
[CosmosWrapperTests](../dotnet/tests/CosmosContentValidation.Tests/CosmosWrapperTests.cs) audits virtual APIs, pinned DTO routing/options, no-dispatch guards and response semantics.
New source coverage includes `EveryStoredProcedureExecutionOverloadIsRejectedAtContainerBoundary`,
`WriteTriggerExecutionIsRejectedBeforeContentReadOrSubmission`, `EmptyWriteTriggerListsAreAllowedAndSnapshottedBeforeInputIsRead`
and `TriggerGuardIsWriteOnlyAndReadOptionsAreCopied`. These exercise all three stored-procedure overloads, no stream consumption/signing/dispatch
on rejected writes, empty-list mutation isolation and read-option copying.
[ArchitectureTests](../dotnet/tests/CosmosContentValidation.Tests/ArchitectureTests.cs) checks sample-only providers and the library's direct package/emitted assembly boundary;
it does not certify provider security or all transitives. [ProcessorTests](../dotnet/tests/CosmosContentValidation.Tests/ProcessorTests.cs)
covers explicit constructor dependencies, required whole-input validation and delegated policy hashing.
[SerializerTests](../dotnet/tests/CosmosContentValidation.Tests/SerializerTests.cs), [SerializerDisposalTests](../dotnet/tests/CosmosContentValidation.Tests/SerializerDisposalTests.cs)
and [BufferPoolTests](../dotnet/tests/CosmosContentValidation.Tests/BufferPoolTests.cs) cover pre-mapping validation, replay, offsets, cancellation and ownership.
See [latest recorded PR1 validation evidence](pr1-validation.md) for executed build, offline test, demo and packaging checks.
Earlier evidence does not establish that these newly added/updated tests passed; verification of the refactor and guards must be recorded separately. Live Azure execution remains pending.
The future security team owns validation and replacement of all concrete providers and their dependencies. User review must approve public interfaces,
all guarded SDK entry points, policy identity, raw bypass limits and buffer/provider lifetimes; neither gate is satisfied by test counts alone.
PR2 plans replace/upsert, guarded full-document queries and latest-version pull change feed; PR3 plans native bulk and typed-only transactional batch.
PR2/PR3 must retain sample-only providers, block stored-procedure execution and apply the write-trigger rule to every newly supported write,
including relevant bulk/batch entry points before enqueue/submission, without adding it to reads. Java must preserve equivalent boundaries and tests in PR4/PR5.
Java and cross-language live validation remain future work. None of these later operations is supported by PR1;
raw batch results, full-fidelity/processor/Functions integration and LINQ are not promised.
