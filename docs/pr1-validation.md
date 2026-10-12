# PR1 validation evidence

Date: **2026-10-12**, updated after the sample-provider isolation refinement. Scope: .NET create/read foundation only; no SDK modifications, Java implementation, commits, pushes or remote pull request creation.

## Executed locally

| Check | Result |
| --- | --- |
| Release solution build (.NET SDK 10.0.401) | Passed; library, console, offline tests and live-test projects compiled with warnings as errors |
| Offline xUnit suite | **527 passed, zero failed, zero skipped** (original pre-refactor baseline: 495) |
| Provider architecture checks | All five concrete providers and crypto/key-import helpers reside in the console sample with `Unsafe` names; original library has no concrete providers or direct crypto/ASN.1/JCS/sample assembly references |
| Explicit server-code guards | All three stored-procedure execution overloads rejected at `Container.Scripts`; nonempty write pre/post-trigger lists rejected before signing, stream consumption or dispatch; empty lists copied and allowed; reads do not use the write-trigger guard |
| Live Azure suite discovery | **Six theory groups skipped**; explicit opt-in and endpoint/database/container/auth configuration are absent |
| Console `--offline` | Passed signing, public-only verification, tamper/missing-signature rejection, default/custom exclusions, stream replay and wrong/unknown key checks; no Azure clients created |
| Console `--help` | Passed without configuration or credentials |
| Library packaging | Produced `CosmosContentValidation.0.1.0.nupkg`, containing the separate .NET library |
| NuGet known-vulnerability check, including transitives | No vulnerable packages reported by the machine's configured package proxy at execution time; not a guarantee against unknown advisories |
| `git diff --check` | Passed |

Commands from the repository root:

```powershell
dotnet build dotnet/CosmosContentValidation.slnx -c Release --no-restore
dotnet test dotnet/CosmosContentValidation.slnx -c Release --no-build --logger "trx;LogFilePrefix=pr1"
dotnet run --project dotnet/samples/CosmosContentValidation.Sample -c Release --no-build -- --offline
dotnet pack dotnet/src/CosmosContentValidation -c Release --no-build --output artifacts/packages
```

Local restore used the already-configured package proxy because direct NuGet TLS access failed on this machine. No certificate-validation bypass or machine-wide source change was introduced. CI uses NuGet.org explicitly. Dependencies are pinned in the project files; both canonical/hash/signature fixtures were independently checked using Node crypto as well as .NET tests.

The relocation preserved the signed fixtures and fixed v1 wire format. Release build, the full test suite, offline console and packaging were rerun normally without temporary source exclusions. Sample `Unsafe*` implementations are **illustrative and not security reviewed**; passing tests is not security approval. The future owning security team must supply validated replacements. No direct crypto reference in the integration library does not imply its transitive Cosmos transport/authentication stack uses no cryptography.

## Review findings resolved before the final run

- Reject generic SDK resource DTOs whose Cosmos serializer routing bypasses the custom serializer; tests include an actual native SDK response-factory routing probe.
- Validate every nonempty successful stream create response, even when write-response content is disabled.
- Dispose signed output if an ordinary serializer's input-stream disposal throws after signing.
- Fill pooled stream blocks without oversized reservations and complete outstanding buffer-writer reservations on error; tests verify pool leases return without finalization.
- Preserve caller stream positions and buffer lifetimes through failures, cancellation and simulated SDK retries.

## Remaining merge gates

1. **Live Azure execution:** configure a dedicated preprovisioned `/pk` container, credentials outside source control, and explicit opt-in as described in [the live guide](live-tests.md). The six theory groups expand to 24 Direct/Gateway cases. Actual service roundtrips have not been verified in this session.
2. **Human review and security-team replacement:** approve [required provider injection, interfaces and wire format](content-validation-protocol.md), exclusion policy, [API restrictions and ownership](security-and-supported-operations.md). A separate team must supply and security-validate replacements for the sample `Unsafe*` providers; no provider security sign-off is claimed here.
3. **CI execution:** the Windows/Linux workflow is authored; remote workflow execution and Linux behavior have not been observed here.

Benchmarks, queries, change feed, updates and bulk/batch remain in later PRs per [the implementation plan](implementation-plan.md). No performance measurements or universal SDK-surface protection claims are made by PR1.
