# Techyonx kode Architecture

**Product:** Techyonx kode  
**Company:** Techyonx Global Private Limited  
**Document role:** Normative system blueprint for the 60 modules listed below.

Techyonx kode is an autonomous coding workspace whose agents propose and validate changes inside an isolated project workspace. The architecture is designed for provider portability, explicit user control over writes and deployment, auditable security and compliance decisions, and recoverable execution. A module is not considered production-ready merely because it appears in this blueprint: each implementation must satisfy its contracts, tests, and operational gates before release.

## 1. Product and platform contract

### Core stack

- **Web application:** Next.js App Router, React, and TypeScript with `strict: true`.
- **Styling and icons:** Tailwind CSS and Lucide React icons.
- **Model access:** A server-side Universal Multi-API Router for Google Gemini Free Tier, Pro, and Flash; a future Techyonx kode custom open-source LLM API; and OpenAI-compatible endpoints. Offline deterministic operations are available when model access is unavailable.
- **Project changes:** A virtual file system (VFS) stages edits. The application never silently writes generated code to the user's working tree or pushes a Git commit.
- **Trust boundary:** Provider credentials and provider calls remain on the server. Client requests carry credential references, never raw provider secrets.

### Operating invariants

1. Every generated or modified file is associated with a request, a validated path, and an auditable patch.
2. Security and compliance gates can reject a change. A model response cannot override a gate.
3. Agent output is untrusted input until parsed, validated, and reviewed by the applicable deterministic checks.
4. A failed or interrupted operation leaves the last committed VFS snapshot recoverable.
5. External side effects, including Git pushes, require explicit authorization and a scoped deployment payload.
6. Provider selection, fallback, token use, and tool execution are observable without logging secrets or unnecessary source content.

## 2. Canonical file tree

The following is the complete owned application tree for the 60 modules in this blueprint. The root architecture document is module 1; the remaining entries are source modules. Framework and package-manager files such as `package.json`, `tsconfig.json`, `next.config.ts`, and lockfiles are repository-level build inputs, not additional numbered modules.

```text
ARCHITECTURE.md
src/
  app/
    api/
      code-engine/route.ts
      git-deploy/route.ts
      self-heal-status/route.ts
    page.tsx
  components/
    AgentSwarmExecutionVisualizer.tsx
    BottomSelfHealingTerminal.tsx
    CenterMultiTabCodeEditor.tsx
    IDEErrorBoundary.tsx
    LeftFileExplorerAndGitPane.tsx
    RightLivePreviewAndAuditDrawer.tsx
    TopIDETelemetryBar.tsx
    UniversalProjectExportModal.tsx
  core/
    agents/
      astStaticAnalyzerAgent.ts
      autonomousBugHunterAgent.ts
      automatedUnitTestAgent.ts
      codeDocumentationAgent.ts
      databaseAndApiSchemaAgent.ts
      masterOrchestratorPipeline.ts
      multiFileDependencyLinker.ts
      polyglotCodeGeneratorAgent.ts
      refactoringAndPerfAgent.ts
      requirementArchitectAgent.ts
      surgicalAutoPatcherAgent.ts
      terminalErrorHealerAgent.ts
    ai-router/
      apiKeyVaultManager.ts
      smartModelSelector.ts
      streamingCodeParser.ts
      universalModelAdapter.ts
    compliance/
      cleanRoomCodeVerifier.ts
      complianceGatekeeperHub.ts
      dependencySupplyChainAuditor.ts
      dpdpGdprCodeCompliance.ts
      ipOwnershipCertificateGenerator.ts
      openSourceLicenseGuard.ts
    immune-system/
      astJsonStreamHealer.ts
      circuitBreakerFailover.ts
      immuneTelemetryHub.ts
      memoryWatchdogAndGC.ts
      offlineDeterministicEngine.ts
      quotaAndRpmScheduler.ts
      runtimeCrashInterceptor.ts
      workspaceStateSnapshotter.ts
    performance/
      codebaseContextPruner.ts
      finOpsTokenAccountant.ts
      l1ExactAstCache.ts
      l2SemanticCodePatternCache.ts
      singleflightRequestCoalescer.ts
      surgicalDiffTokenSaver.ts
    security/
      codeInjectionFirewall.ts
      cryptographicCodeSigner.ts
      ddosAndRateGovernor.ts
      maliciousCodeDetector.ts
      owaspVulnerabilityScanner.ts
      sandboxIsolationGuard.ts
      secretLeakPrevention.ts
      securityTelemetryAuditor.ts
    vcs/
      universalGitPushConnector.ts
      virtualFileSystemEngine.ts
  types/
    codingEngine.ts
```

## 3. Cluster map and module responsibilities

The numbering is stable for planning and telemetry. Cluster A's first module is this document, followed by five TypeScript modules; together, the eight clusters contain exactly 60 modules.

### Cluster A — Universal AI Router (Modules 1–6)

| # | Module | Responsibility |
|---:|---|---|
| 1 | `ARCHITECTURE.md` | Defines module ownership, trust boundaries, data flow, operating invariants, and mandatory engineering rules. |
| 2 | `src/types/codingEngine.ts` | Shared strict contracts for providers, files, patches, agents, reports, deployments, and telemetry. |
| 3 | `src/core/ai-router/universalModelAdapter.ts` | Normalizes provider requests, streaming responses, errors, and usage into the shared contract. |
| 4 | `src/core/ai-router/smartModelSelector.ts` | Selects an allowed provider/model from task needs, policy, availability, and configured budget. |
| 5 | `src/core/ai-router/apiKeyVaultManager.ts` | Resolves, rotates, and scopes server-side credential references without exposing secret values. |
| 6 | `src/core/ai-router/streamingCodeParser.ts` | Parses and validates streamed text, structured tool output, and code chunks incrementally. |

### Cluster B — Zero-Trust Cyber Security and Hack-Proof Shield (Modules 7–14)

| # | Module | Responsibility |
|---:|---|---|
| 7 | `src/core/security/codeInjectionFirewall.ts` | Rejects unsafe instruction, tool, path, and generated-content transitions at trust boundaries. |
| 8 | `src/core/security/maliciousCodeDetector.ts` | Flags suspicious generated behavior using deterministic rules and explainable findings. |
| 9 | `src/core/security/secretLeakPrevention.ts` | Detects and redacts credentials in prompts, patches, logs, exports, and telemetry. |
| 10 | `src/core/security/owaspVulnerabilityScanner.ts` | Reports applicable OWASP-category findings with evidence, severity, and source locations. |
| 11 | `src/core/security/sandboxIsolationGuard.ts` | Enforces isolated execution, resource bounds, and least-privilege workspace access. |
| 12 | `src/core/security/ddosAndRateGovernor.ts` | Applies request, concurrency, and resource limits by identity and operation. |
| 13 | `src/core/security/cryptographicCodeSigner.ts` | Signs and verifies canonical patch or artifact digests using managed signing keys. |
| 14 | `src/core/security/securityTelemetryAuditor.ts` | Produces privacy-conscious, tamper-evident records of security decisions and events. |

### Cluster C — Global Legal Compliance and Clean-Room Originality (Modules 15–20)

| # | Module | Responsibility |
|---:|---|---|
| 15 | `src/core/compliance/cleanRoomCodeVerifier.ts` | Checks generated work against configured provenance and originality policies; records evidence and limitations. |
| 16 | `src/core/compliance/openSourceLicenseGuard.ts` | Evaluates detected license metadata against project policy and reports conflicts or unknowns. |
| 17 | `src/core/compliance/dependencySupplyChainAuditor.ts` | Audits dependency identity, version, integrity metadata, advisories, and configured provenance requirements. |
| 18 | `src/core/compliance/dpdpGdprCodeCompliance.ts` | Evaluates configured DPDP/GDPR privacy controls and data-handling obligations; does not provide legal advice. |
| 19 | `src/core/compliance/ipOwnershipCertificateGenerator.ts` | Creates a verifiable record of project, contributor, and artifact provenance from supplied evidence. |
| 20 | `src/core/compliance/complianceGatekeeperHub.ts` | Aggregates compliance results into explicit pass, fail, or review-required decisions for the orchestrator. |

### Cluster D — Multi-Agent Autonomous Coding and Bug-Fixing Brain (Modules 21–32)

| # | Module | Responsibility |
|---:|---|---|
| 21 | `src/core/agents/requirementArchitectAgent.ts` | Converts a user request into bounded acceptance criteria, affected areas, and a reviewable execution plan. |
| 22 | `src/core/agents/polyglotCodeGeneratorAgent.ts` | Generates language-aware candidate code through the model router under the active project constraints. |
| 23 | `src/core/agents/astStaticAnalyzerAgent.ts` | Parses changed files and returns syntax, symbol, import, and static-analysis results. |
| 24 | `src/core/agents/autonomousBugHunterAgent.ts` | Finds reproducible defects in the scoped change and reports evidence-backed bug candidates. |
| 25 | `src/core/agents/surgicalAutoPatcherAgent.ts` | Produces minimal, path-scoped patches from accepted findings; it does not apply them outside the VFS. |
| 26 | `src/core/agents/automatedUnitTestAgent.ts` | Selects and runs approved tests in isolation and returns structured execution reports. |
| 27 | `src/core/agents/refactoringAndPerfAgent.ts` | Identifies scoped maintainability or performance improvements and measures claims where possible. |
| 28 | `src/core/agents/multiFileDependencyLinker.ts` | Resolves references among changed files and checks import, export, and dependency consistency. |
| 29 | `src/core/agents/terminalErrorHealerAgent.ts` | Converts sanitized command failures into bounded diagnostic steps and candidate repairs. |
| 30 | `src/core/agents/databaseAndApiSchemaAgent.ts` | Produces and validates database or API schema changes against supplied project contracts. |
| 31 | `src/core/agents/codeDocumentationAgent.ts` | Generates or updates documentation from verified project behavior and accepted changes. |
| 32 | `src/core/agents/masterOrchestratorPipeline.ts` | Schedules agent stages, enforces approval and gate transitions, and records the end-to-end trace. |

### Cluster E — Autonomous Immune System and Zero-Crash Infrastructure (Modules 33–40)

| # | Module | Responsibility |
|---:|---|---|
| 33 | `src/core/immune-system/quotaAndRpmScheduler.ts` | Queues provider work within configured concurrency, request-per-minute, and quota limits. |
| 34 | `src/core/immune-system/circuitBreakerFailover.ts` | Stops calls to unhealthy providers and selects policy-approved fallback behavior. |
| 35 | `src/core/immune-system/astJsonStreamHealer.ts` | Recovers from incomplete or malformed structured streams without treating repaired data as trusted. |
| 36 | `src/core/immune-system/memoryWatchdogAndGC.ts` | Monitors bounded process memory and invokes supported cleanup or workload shedding. |
| 37 | `src/core/immune-system/workspaceStateSnapshotter.ts` | Captures and restores versioned VFS and operation state for rollback and crash recovery. |
| 38 | `src/core/immune-system/runtimeCrashInterceptor.ts` | Converts uncaught operation failures into sanitized, correlated error records and recovery signals. |
| 39 | `src/core/immune-system/offlineDeterministicEngine.ts` | Runs deterministic local operations that do not require a model provider. |
| 40 | `src/core/immune-system/immuneTelemetryHub.ts` | Aggregates health, recovery, fallback, and scheduler signals without collecting secret values. |

### Cluster F — Extreme Token Economy and Sub-Millisecond Caching (Modules 41–46)

| # | Module | Responsibility |
|---:|---|---|
| 41 | `src/core/performance/l1ExactAstCache.ts` | Caches exact, content-addressed parse or analysis results with explicit invalidation. |
| 42 | `src/core/performance/l2SemanticCodePatternCache.ts` | Reuses eligible semantic results only when scope, model, policy, and freshness keys match. |
| 43 | `src/core/performance/surgicalDiffTokenSaver.ts` | Limits model context and patch output to relevant changed regions while preserving required context. |
| 44 | `src/core/performance/codebaseContextPruner.ts` | Selects and budgets relevant project context according to task and privacy policy. |
| 45 | `src/core/performance/singleflightRequestCoalescer.ts` | Coalesces equivalent in-flight work and separates callers' authorization and cancellation scopes. |
| 46 | `src/core/performance/finOpsTokenAccountant.ts` | Accounts for provider usage and estimated cost by request, project, model, and operation. |

### Cluster G — Virtual File System, Universal Git Push, and API Gateways (Modules 47–52)

| # | Module | Responsibility |
|---:|---|---|
| 47 | `src/core/vcs/virtualFileSystemEngine.ts` | Validates and stages file operations, computes digests, and provides snapshot-based atomic commit or rollback. |
| 48 | `src/core/vcs/universalGitPushConnector.ts` | Implements authorized Git-provider operations with scoped credentials and explicit branch/commit inputs. |
| 49 | `src/app/api/code-engine/route.ts` | Authenticates and validates coding requests, invokes the orchestrator, and streams typed results. |
| 50 | `src/app/api/git-deploy/route.ts` | Validates deployment authorization and payload, runs final gates, then invokes the Git connector. |
| 51 | `src/app/api/self-heal-status/route.ts` | Returns authorized, sanitized health and recovery telemetry for the active workspace. |
| 52 | `src/components/IDEErrorBoundary.tsx` | Contains rendering failures and offers a recoverable UI state without exposing internal secrets. |

### Cluster H — Next-Generation Four-Pane Autonomous IDE Studio UI (Modules 53–60)

| # | Module | Responsibility |
|---:|---|---|
| 53 | `src/components/TopIDETelemetryBar.tsx` | Presents project status, provider state, usage, and security/compliance gate summaries. |
| 54 | `src/components/LeftFileExplorerAndGitPane.tsx` | Displays the VFS tree, staged changes, and Git state with explicit file actions. |
| 55 | `src/components/CenterMultiTabCodeEditor.tsx` | Hosts the multi-tab editor and renders versioned VFS content and patch review state. |
| 56 | `src/components/AgentSwarmExecutionVisualizer.tsx` | Shows agent stage, dependencies, progress, and sanitized trace details. |
| 57 | `src/components/BottomSelfHealingTerminal.tsx` | Presents approved task output, diagnostics, recovery actions, and test results. |
| 58 | `src/components/RightLivePreviewAndAuditDrawer.tsx` | Hosts an isolated preview and inspectable security, compliance, and change audits. |
| 59 | `src/components/UniversalProjectExportModal.tsx` | Reviews and exports an explicitly selected project snapshot or deployment payload. |
| 60 | `src/app/page.tsx` | Composes the authenticated four-pane IDE workspace and its loading, empty, and error states. |

## 4. Runtime boundaries and data flow

### Coding request and patch flow

1. The IDE submits a scoped request and workspace version to `POST /api/code-engine`. The route authenticates the caller, validates the request shape, applies rate limits, and rejects paths or payloads outside the authorized workspace.
2. The orchestrator snapshots the workspace, creates a trace, obtains bounded context, and asks the requirement architect to produce acceptance criteria. The user-visible plan and any approval requirement are preserved in the trace.
3. The security firewall and policy gate validate task instructions and allowed tools. The model selector chooses a configured provider/model; the quota scheduler and circuit breaker may delay, reject, or route the request to an allowed fallback. The vault resolves a secret only inside the server-side adapter boundary.
4. The provider adapter emits normalized chunks. The streaming parser validates structure and associates content with the request. Malformed or incomplete output is either rejected or passed through the stream healer as untrusted candidate data.
5. Candidate changes are parsed and analyzed. The bug hunter, dependency linker, and relevant specialist agents produce evidence-bearing results. The patcher creates path-scoped surgical diffs; secret scanning and malicious-code checks run before staging.
6. The VFS validates paths and preconditions, stages a candidate transaction, and records content digests. AST/static analysis, tests, vulnerability checks, license/supply-chain checks, and applicable privacy/compliance gates run against the staged snapshot.
7. The gatekeeper returns pass, fail, or review-required. Failed gates prevent promotion. Passing changes are presented for user review; only an explicit apply action promotes the staged transaction to the active VFS version. The original snapshot remains available for rollback.
8. The route streams sanitized progress, final patch references, test/audit results, and usage metrics to the IDE. Telemetry excludes raw credentials and redacts sensitive content.

### Git deployment flow

1. The user selects a VFS version, repository, branch, and commit message and explicitly authorizes deployment.
2. `/api/git-deploy` authenticates and validates the payload, confirms the selected snapshot has not changed, and reruns required security and compliance gates against that exact content.
3. The connector obtains a narrowly scoped credential reference, verifies the destination and branch policy, and performs the requested operation. It never interprets model-generated instructions as deployment authorization.
4. The result records the target, resulting commit/revision, gate outcomes, and trace correlation identifier. Failures do not discard the local VFS snapshot.

### Self-healing and offline flow

Provider and runtime failures are correlated with an operation trace. The circuit breaker prevents repeated calls to unhealthy providers; the scheduler applies bounded retries only to retryable failures. The offline engine handles deterministic capabilities where available. Recovery may restore a prior workspace snapshot, but it cannot silently apply a generated repair or bypass security, test, or user-approval gates.

## 5. Contract and state ownership

- `src/types/codingEngine.ts` is the canonical shared data contract. Provider-specific SDK objects are translated at the adapter boundary and do not cross into agents, routes, or components.
- API routes own authentication, request validation, authorization, response shaping, and transport-level streaming. Core modules receive validated inputs and explicit capabilities; they do not read ambient credentials or request globals.
- The VFS owns active, staged, and snapshot versions. Components render those versions but do not mutate disk or Git directly.
- The orchestrator owns stage ordering and operation cancellation. Agents return typed results and cannot grant themselves permissions or skip a gate.
- Audit and telemetry records use stable correlation IDs. Raw API keys, access tokens, private signing keys, and unredacted secrets are never valid telemetry fields.
- Cache keys include every input that can change the result, including content digest, relevant configuration, provider/model where applicable, and policy version. Security-sensitive results are not reused across authorization scopes.

## 6. Strict coding and release rules

1. **TypeScript:** Enable `strict`, `noUncheckedIndexedAccess`, and `exactOptionalPropertyTypes`. Avoid `any`, unsafe casts, non-null assertions, and unvalidated `unknown`; narrow external values at the boundary.
2. **Contracts:** Use the shared types, discriminated unions, explicit result/error shapes, and UTC ISO-8601 timestamps. Do not duplicate provider SDK types in public module contracts.
3. **Validation:** Validate all API input, provider output, file paths, patch preconditions, serialized state, and deployment payloads at runtime. TypeScript types do not replace runtime validation.
4. **Security:** Apply least privilege, server-only secret handling, output encoding, path traversal protection, bounded resource use, and sandboxing. Never execute model output as shell commands or trusted code without an explicit allowlisted tool and isolated execution policy.
5. **Changes:** Stage generated work in the VFS, use content hashes and version checks, and make multi-file changes transactional. Do not overwrite conflicting user edits. Require explicit user intent for apply, export, and deploy operations.
6. **Agents:** Give every stage bounded inputs, outputs, time/resource limits, cancellation support, and a trace entry. Treat model-produced plans, patches, tests, and explanations as untrusted until independently checked.
7. **Reliability:** Bound retries and queues; use idempotency keys for retryable side effects; make fallback policy explicit; and preserve recoverable state before mutation.
8. **Privacy and compliance:** Minimize retained source and personal data, redact secrets before logs, enforce configured retention, and report unknown or unverifiable compliance evidence rather than claiming a pass.
9. **Performance and cost:** Set explicit context, token, concurrency, and execution budgets. Cache only deterministic or policy-approved results with complete invalidation keys. Report measured performance; do not promise latency targets without measurements.
10. **UI:** Keep provider keys and privileged operations out of client code. Show pending, rejected, review-required, failed, and successful states distinctly. Make destructive or external side effects confirmable and accessible.
11. **Testing:** Cover contracts, malformed input, authorization boundaries, failure/fallback paths, patch conflicts, rollback, and gate enforcement. Use deterministic fixtures for unit tests and isolated environments for code execution.
12. **Release gate:** A module is releasable only after lint, strict type-check, focused tests, dependency/security review, and applicable integration tests pass. Document known limitations and operational configuration; never represent a planned module as implemented functionality.

## 7. Required operational signals

Each operation should expose a trace identifier, current stage, elapsed time, cancellation state, provider/model selection when applicable, sanitized failure category, cache activity, token/accounting data when provided, and security/compliance gate status. Health endpoints expose only authorized aggregate state. Logs and dashboards must not include raw secrets or treat model-generated claims as verified facts.
