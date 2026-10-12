# PR1 console sample and opt-in live tests

These examples cover **point create/read, typed and stream**, plus point deletion of
acknowledged sample/test creations. No database or container is provisioned or deleted.
Protected query, replace, upsert, patch, batch, bulk and change feed are not demonstrated.
The deliberately unprotected patch client exists only for scoped tamper tests.

## Sample-only providers and review status

The [console](../dotnet/samples/CosmosContentValidation.Sample/Program.cs) and test fixtures compose providers through
`UnsafeSampleProviders` in `CosmosContentValidation.Sample.Providers`. All five concrete content-protection implementations
live in the console sample; the library supplies no built-in/default/fallback providers. The sample helper supplies
`UnsafeJcsCanonicalizer` and `UnsafeSha256ContentHasher`; callers provide the resolver and optional signer explicitly.
The library constructor requires `ContentValidationProcessor(options, verificationKeys, canonicalizer, hasher, signer = null)`.
Tests reference the sample project, not the reverse, and the library never references the sample.

**`Unsafe` means illustrative and NOT security reviewed, not deliberately flawed cryptography.**
The future owning security team must supply security-validated canonicalizer/hasher/signer/verifier/resolver implementations;
user review remains required. See the [provider inventory and replacement contract](../dotnet/samples/CosmosContentValidation.Sample/Providers/README.md).
The library's lack of direct crypto/ASN.1/JCS and sample assembly references does not make Cosmos SDK/Azure authentication
transitives crypto-free: transport/authentication still use cryptography. Fixed v1 identifiers constrain provider compatibility;
they do not provide built-in crypto or implemented crypto agility.

## Offline first

From the repository root, with the existing .NET 10 projects restored:

```powershell
dotnet run --project ./dotnet/samples/CosmosContentValidation.Sample --no-restore -- --help
dotnet run --project ./dotnet/samples/CosmosContentValidation.Sample --no-restore -- --offline
dotnet test ./dotnet/tests/CosmosContentValidation.LiveTests --no-restore
```

`--help` needs no credentials and does not load keys. `--offline` needs no environment
configuration and does not instantiate an Azure client. It generates ephemeral P-256
keys **only in process**, then exercises the library serializer and sample-only `Unsafe` providers:

- Typed signing, public-only verification and model materialization.
- Signed stream consumption and replay while its owner is alive.
- Default service metadata exclusions, missing signatures, modified content,
  default-policy TTL/customer-field tampering, and signing unavailable to a reader.
- Custom ignored root-field edits/additions/removal, nested same-name protection,
  local policy mismatch, wrong key pairs and unknown key IDs.

Offline success exits 0. The larger offline unit suite remains in its existing project;
the console checks do not replace it. Live tests are discovered but **skipped** unless
the exact environment value `COSMOS_RUN_LIVE_TESTS=1` is set. Any other value skips.
Consult the [latest recorded validation evidence](pr1-validation.md) for executed results.
Earlier runs do not verify the newly added guard tests or updated architecture tests; this guide makes no new pass claim.

## Online prerequisites and configuration

Use a **dedicated, preprovisioned** Cosmos DB for NoSQL test container with exactly
one partition-key path, `/pk`. Both entry points independently read container metadata
through a raw SDK client **before constructing protected clients** and reject any
other path configuration. They never change container settings or throughput.

Set these variables outside source control, using the host's normal secret delivery
mechanism. Do not paste credentials into chat, console logs, or source files.

| Variable | Console online | Live tests |
| --- | --- | --- |
| `COSMOS_RUN_LIVE_TESTS` | Exactly `1` authorizes online operations | Exactly `1` enables discovery/execution |
| `COSMOS_ENDPOINT` | Required absolute HTTPS account endpoint | Required |
| `COSMOS_DATABASE` | Required existing dedicated database | Required |
| `COSMOS_CONTAINER` | Required existing dedicated `/pk` container | Required |
| `COSMOS_KEY` | Optional account key | Optional account key |
| `CONTENT_SIGNING_KEY_FILE` | Required local private PEM file | Not used |
| `CONTENT_VERIFICATION_KEY_FILE` | Required matching local public PEM file | Not used |
| `CONTENT_KEY_ID` | Required trusted key identifier | Not used; fixture chooses an ephemeral ID |
| `CONTENT_IGNORED_PROPERTIES` | Optional comma-delimited exact root names | Not used; scenarios specify their own policy |

If `COSMOS_KEY` is absent/blank, authentication uses `DefaultAzureCredential` with
interactive browser acquisition disabled. Configure an appropriate external identity
(for example an authenticated development identity or managed identity) with metadata
read and item create/read/patch/delete data-plane permissions on this dedicated scope.
The public-only reader has no **content signing key**; this is not a replacement for
service authorization or a claim that its Azure identity lacks write permissions.

**Opted-in but incomplete configuration fails rather than skips**, before any network
request. Authentication, networking, incompatible metadata and service errors also fail;
there is no emulator fallback. Do not enable the flag in untrusted/fork CI.

## Console key lifecycle and exclusion policy

Supply a matching pair from your approved external key-provisioning process:

- Private file: exactly one unencrypted PKCS#8 `PRIVATE KEY` PEM block, named NIST P-256.
- Public file: exactly one SPKI `PUBLIC KEY` PEM block for that same key, named NIST P-256.
- `CONTENT_KEY_ID`: the same trusted identifier assigned to signer and verifier.

The sample does not have a key-file generation option. Restrict private-file access and
keep it outside the repository. Each file is loaded **once at startup**; providers then
operate synchronously in memory. A full local sign/verify/materialization probe rejects
wrong key pairs **before any network call or item write**. `UnsafeEcdsaContentSigner` holds the private key;
`UnsafeEcdsaContentVerifier` holds the SPKI public key, and `UnsafeInMemoryVerificationKeyResolver` maps the trusted ID to it.
The public-only processor has no signer. Clients are disposed before the caller-owned providers.
The sample's `UnsafeEcdsaKeyImport` handles import. Current sample provider constructors require temporary immutable PEM strings; their managed
string storage cannot be explicitly zeroed. Key material is never printed or written.

With `CONTENT_IGNORED_PROPERTIES` unset, only these service-owned **root** fields are
ignored: `_rid`, `_self`, `_etag`, `_attachments`, `_ts`. TTL and customer fields are signed.
For a custom policy, set `CONTENT_IGNORED_PROPERTIES` to `ttl,customerTag`. Whitespace
around comma-separated names is trimmed and duplicate names are deduplicated ordinally.

Ignored values remain in the returned JSON but are **unauthenticated**. Matching is
case-sensitive and root-only: excluding `customerTag` does not exclude
`nested.customerTag` or `CustomerTag`. Ignoring a root object excludes its entire subtree.
`id`, the root containing `/pk`, and `_contentValidation` cannot be ignored. Both clients
use the same trusted local policy; its fingerprint is bound into the signature. Changing
policy does not make older signatures compatible. The online tamper example requires
`value` to remain signed and rejects configurations that ignore it.
The injected canonicalizer/hasher compute that fingerprint using the unchanged v1 descriptor;
there is no library policy-hashing fallback. Required `IJsonCanonicalizer.ValidateInput` checks the whole raw tree,
including excluded subtrees, before filtering; `Canonicalize` is a separate operation.

## Running against Azure

After externally configuring the environment and explicitly setting the opt-in flag:

```powershell
dotnet run --project ./dotnet/samples/CosmosContentValidation.Sample --no-restore
dotnet run --project ./dotnet/samples/CosmosContentValidation.Sample --no-restore -- --tamper
dotnet run --project ./dotnet/samples/CosmosContentValidation.Sample --no-restore -- --direct
dotnet test ./dotnet/tests/CosmosContentValidation.LiveTests --no-restore --logger 'console;verbosity=normal'
```

The sample defaults to Gateway; `--direct` selects Direct and may be combined with
`--tamper`. It creates two new items, one typed and one stream, and reads each through
the public-only reader using both APIs. Output reports action outcomes, not documents,
keys, endpoints or full credential/SDK exception text. Typed examples access the native
`ItemResponse<T>.Resource`; a status code alone is not a content-validation claim.
Stream examples consume then rewind the actual response body before disposing the
`ResponseMessage` that owns it. Caller payloads stay alive through awaited writes.
Separate clients forward session tokens to avoid stale reads after creates/patches.

`--tamper` additionally changes `/value` on **only these two acknowledged new items**
through the raw client. Both typed and stream signed reads must reject `InvalidSignature`.
Without `--tamper`, no online patch is issued by the console. Offline mode already tests
local tampering and must be used alone. Nothing is re-signed to hide deliberate tampering.

Console exit codes: 0 success; 1 configuration/unexpected failure; 2 content-validation
failure (category printed); 3 Cosmos service failure (HTTP status/substatus printed);
4 authentication failure; 5 cleanup-only failure. Expected negative demonstrations are
successes. A failed startup key-match probe is a configuration failure, not an Azure error.

## Live coverage

The live project has six custom theories and **24 rows**, covering Direct and Gateway:

| Scenario | Rows |
| --- | ---: |
| Typed create, public-only typed and stream reads | 2 |
| Stream create, public-only typed and stream reads | 2 |
| Default policy rejects raw application/TTL/customer-field patches | 6 |
| Custom policy permits root-field add/remove/change after typed or stream create | 4 |
| Custom policy still protects nested and case-variant names | 8 |
| Public-only typed and stream writes reject `SigningUnavailable` | 2 |

Checks include 201/200 statuses, activity ID, request charge, ETag/session headers,
materialized service metadata, envelope retention/stripping, explicit public-only
revalidation of returned signed bytes, byte-identical stream replay, and nonzero-position
caller input ownership. Negative no-dispatch guards belong to the existing unit suite.
Every class fixture lazily creates ephemeral in-process signing/verification providers;
skipped tests perform no credential acquisition or Azure operations.

### Execution guards are checked offline, not by invoking scripts in Azure

The protected `Container.Scripts` getter rejects access before touching the underlying delegate, covering
typed `ExecuteStoredProcedureAsync<T>` and both `ExecuteStoredProcedureStreamAsync` overloads.
All writes with nonempty `PreTriggers` or `PostTriggers` are rejected before reading content or submitting a request:
typed/stream create and delete now, replace/upsert when PR2 implements them. Empty lists request no invocation and are copied
before input is read. `SnapshotOptions` defaults `isWrite` to `true`; typed/stream reads pass `false` and retain ordinary option
handling and detached list copies, without a write-trigger guard. Patch stays blocked even for ignored fields.

The unit source includes `EveryStoredProcedureExecutionOverloadIsRejectedAtContainerBoundary`,
`WriteTriggerExecutionIsRejectedBeforeContentReadOrSubmission`, `EmptyWriteTriggerListsAreAllowedAndSnapshottedBeforeInputIsRead`
and `TriggerGuardIsWriteOnlyAndReadOptionsAreCopied` in [CosmosWrapperTests](../dotnet/tests/CosmosContentValidation.Tests/CosmosWrapperTests.cs).
[ArchitectureTests](../dotnet/tests/CosmosContentValidation.Tests/ArchitectureTests.cs) checks provider placement and direct dependency/emitted assembly boundaries;
[ProcessorTests](../dotnet/tests/CosmosContentValidation.Tests/ProcessorTests.cs) covers constructor contracts, whole-input validation and policy-provider delegation.
These are coverage descriptions, not newly verified results or security approval.
PR2–PR5 must carry the provider boundary and execution guards forward, including equivalent Java tests; those PRs are not implemented here.

Direct mode requires the account's data-plane network connectivity, not just HTTPS
gateway access. Accounts must support the explicitly requested Session consistency;
there is no retry with weaker consistency. Tests use their own default/custom policy,
not console key files or `CONTENT_IGNORED_PROPERTIES`.

## Ownership, cleanup and limitations

- IDs and partition keys include a fresh GUID prefix. A ledger records successful
  creates **before** response-content assertions. A GUID alone never authorizes deletion.
- A create conflict is never treated as ownership. A create may commit and then fail
  signature validation, transport or materialization before acknowledgement. Such an ID
  is **not automatically patched or deleted**; warnings identify the generated ID and
  partition key for manual inspection, without logging its payload.
- `finally` attempts cleanup of **every confirmed ID**, using an independent timeout
  per item even if main work was canceled. Deletes use the last observed ETag. Patch
  `IfMatchEtag` is unsupported by the pinned SDK, so raw tampering relies on the isolated
  dedicated container and confirmed GUID-scoped identities; do not concurrently modify
  or recreate those items. A delete precondition failure is reported for manual handling,
  not retried unconditionally.
  Cleanup failures do not replace the original operation failure; cleanup-only failures
  produce a failing result. Already absent items count as cleaned.
- No queries, partition-wide deletion, database/container provisioning or resource
  deletion occur. Each live row budgets at most two identities. Main work is bounded to
  two minutes; cleanup has a fresh 20-second budget per confirmed item. Rate-limit retries
  are disabled. Tests still consume request units, including metadata reads and failures.
- Items begin with `ttl=-1`; TTL mutations use 86400, avoiding short accidental expiry.
  TTL container settings are not modified. Process termination can prevent `finally`;
  use a dedicated container and your own operational reconciliation procedures.
- Ephemeral test keys disappear at process exit. Leftover live items cannot subsequently
  be signature-verified with a new fixture's key. Use their logged identities and dedicated
  scope for manual investigation, rather than weakening verification.
- Signatures do not prevent deletion, expiry, rollback/replay of whole signed documents,
  signing-key compromise, or establish query completeness or storage-location identity.
  Excluded metadata/fields are not trustworthy application claims.
