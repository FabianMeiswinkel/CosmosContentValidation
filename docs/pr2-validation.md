# PR2 validation evidence

- **Date:** 2026-10-12
- **Scope:** .NET lifecycle updates, guarded full-document queries and latest-version pull change feed.
- **Baseline:** PR1 commit `ebc2c4f`.
- **SDK/runtime:** .NET 10, Azure Cosmos DB SDK 3.63.2.
- **Live Azure status:** Passed against the externally configured dedicated `/pk` container: all 30 Direct/Gateway rows passed and confirmed test items were cleaned up. No endpoint, credential or key value is recorded here.
- **Review status:** Automated evidence is not user approval or security-team approval. All five sample-only `Unsafe` providers still require security-team validation/replacement.

## Executed checks

From the repository root:

| Check | Result |
| --- | --- |
| `dotnet test dotnet/CosmosContentValidation.slnx -c Release --no-restore` | Passed after the live-discovered fix: solution build plus 631 offline tests; 9 live theory methods skipped without opt-in; 0 failed (640 total). |
| Opted-in `dotnet test` of the live-test project with externally supplied system environment | Passed: 30/30 enabled Direct/Gateway rows, 0 failed, 0 skipped. Cleanup reported success. |
| `dotnet run --project dotnet/samples/CosmosContentValidation.Sample/CosmosContentValidation.Sample.csproj -c Release --no-build -- --offline` | Passed all serializer, replay, tamper, exclusion-policy and key-isolation checks without Azure clients or credentials. |
| `dotnet run --project dotnet/samples/CosmosContentValidation.Sample/CosmosContentValidation.Sample.csproj -c Release --no-build -- --help` | Passed; documented PR2 lifecycle/query/feed configuration and limitations without key or credential access. |
| `dotnet pack dotnet/src/CosmosContentValidation/CosmosContentValidation.csproj -c Release --no-restore -o artifacts/pr2-pack` | Passed; produced `CosmosContentValidation.0.1.0.nupkg`. |
| `git diff --check` | Passed after final changes. |
| Editor diagnostics | No reported errors in the workspace files checked before final validation. |

## Covered PR2 behavior

- Typed and stream replace/upsert insert/update, conditional ETags, response-content on/off, replay through retries, caller ownership and readback after status-only success.
- Trigger and stored-procedure guards remain fail-closed before content read/signing/submission; Patch, LINQ, read-many, full-fidelity feed and processor integrations remain blocked.
- All six item-query overloads guard the original SQL before native iterator construction. Projections, nested sources, joins, collection iteration and comma sources fail even if they would return no rows.
- `ContentValidationQueryDefinition` snapshots ordinary and strict raw JSON parameters without document signing; opaque native parameterized definitions and base-API bypasses fail closed.
- Stream feed pages preserve their exact validated envelope through a response facade required by the pinned SDK query response implementation. Typed pages validate every document before target construction and perform one cryptographic verification pass per document.
- Exact case-sensitive `Documents` envelope handling, duplicate/missing/wrong-type fields, malformed/trailing JSON, per-document/page limits, documented feed-only `_lsn` handling with unchanged point semantics, later-page invalid/missing signatures, cancellation, service errors, 304 pages, transient pre-response retry and iterator poisoning after local page failure.
- Latest-version/incremental pull mode only, with bounded sample/live polling and continuation advancement after successful validation and processing.
- Provider placement and dependency architecture remain sample-only; the reusable library contains no concrete provider implementation or fallback.

## Pending gates

- User review of the PR2 public API, guarded SQL subset, query parameter ownership, response facade and checkpoint semantics.
- Future owning security-team validation or replacement of every sample-only `Unsafe` provider.
- PR3 bulk/batch work and all Java/cross-language work remain out of scope.
