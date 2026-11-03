import { randomUUID } from 'node:crypto';
import type { AgentStepTrace } from '../../types/codingEngine';
import { enforcePrivacyComplianceInCode } from '../compliance/dpdpGdprCodeCompliance';
import { scrubHardcodedSecrets } from '../security/secretLeakPrevention';

export interface ArchitectPlannedFile {
  readonly path: string;
  readonly responsibility: string;
}

export type ArchitectStackProfile = 'NEXTJS' | 'FASTAPI' | 'RUST' | 'GO';

export interface RequirementArchitectureBlueprint {
  readonly projectTitle: string;
  readonly stackProfile: ArchitectStackProfile;
  readonly targetTechStack: readonly string[];
  readonly plannedFiles: readonly ArchitectPlannedFile[];
  readonly componentHierarchy: readonly string[];
  readonly apiContract: readonly string[];
  readonly edgeCases: readonly string[];
  readonly securityRequirements: readonly string[];
  readonly featureSignals: {
    readonly dashboard: boolean;
    readonly finance: boolean;
    readonly authentication: boolean;
    readonly realTime: boolean;
    readonly persistence: boolean;
  };
  readonly requestSummary: string;
}

export interface RequirementArchitectResult {
  readonly blueprintSummary: string;
  readonly plannedFiles: Array<{ path: string; responsibility: string }>;
  readonly architectureDiagramMermaid: string;
  readonly stepTrace: AgentStepTrace;
}

const MAX_PROMPT_CHARS = 100_000;
const MAX_STACK_PREFERENCE_CHARS = 256;

function selectStackProfile(stackPreference: string): ArchitectStackProfile {
  const preference = stackPreference.toLowerCase();
  if (/fastapi|python|django|flask/.test(preference)) return 'FASTAPI';
  if (/rust|axum|actix/.test(preference)) return 'RUST';
  if (/\bgo\b|golang|gin-gonic|fiber/.test(preference)) return 'GO';
  return 'NEXTJS';
}

function inferFeatures(prompt: string): RequirementArchitectureBlueprint['featureSignals'] {
  const normalized = prompt.toLowerCase();
  return {
    dashboard: /dashboard|analytics|chart|metrics|report|admin panel/.test(normalized),
    finance: /fintech|finance|financial|payment|bank|transaction|ledger|invoice/.test(normalized),
    authentication: /auth|login|sign.?in|account|session|permission|role.?based/.test(normalized),
    realTime: /real.?time|live update|streaming|websocket|socket|event.?driven/.test(normalized),
    persistence: /database|persist|save|postgres|mysql|sqlite|data store|api|backend/.test(normalized),
  };
}

function projectTitle(prompt: string, features: RequirementArchitectureBlueprint['featureSignals']): string {
  if (features.finance && features.dashboard) return 'Financial Operations Dashboard';
  if (features.finance) return 'Financial Services Application';
  if (features.dashboard) return 'Analytics Dashboard';
  if (/store|shop|ecommerce|e-commerce|cart|catalog/.test(prompt.toLowerCase())) return 'Commerce Application';
  if (/blog|article|publishing|content management/.test(prompt.toLowerCase())) return 'Publishing Workspace';
  if (/task|project management|kanban|workflow/.test(prompt.toLowerCase())) return 'Project Workflow Application';
  return 'Application Workspace';
}

function addFile(files: ArchitectPlannedFile[], path: string, responsibility: string): void {
  if (!files.some(file => file.path === path)) {
    files.push({ path, responsibility });
  }
}

function nextFilePlan(features: RequirementArchitectureBlueprint['featureSignals']): ArchitectPlannedFile[] {
  const files: ArchitectPlannedFile[] = [];
  addFile(files, 'README.md', 'Document product scope, local setup, environment configuration, and operational constraints.');
  addFile(files, 'package.json', 'Declare the application scripts and pinned runtime dependencies.');
  addFile(files, 'tsconfig.json', 'Enable strict TypeScript checking and Next.js-compatible module settings.');
  addFile(files, 'next.config.ts', 'Configure the Next.js application and security-conscious build options.');
  addFile(files, 'postcss.config.mjs', 'Configure the Tailwind CSS v4 PostCSS plugin required by the Next.js build.');
  addFile(files, 'src/app/layout.tsx', 'Define the document shell, metadata, global styles, and accessible page structure.');
  addFile(files, 'src/app/page.tsx', 'Compose the primary responsive workspace from focused feature components.');
  addFile(files, 'src/app/globals.css', 'Implement responsive layout, color tokens, typography, and accessible interaction states.');
  addFile(files, 'src/lib/formatters.ts', 'Provide deterministic formatting helpers for dates, currency, and compact metric labels.');
  addFile(files, 'src/app/api/health/route.ts', 'Expose a minimal health endpoint without leaking environment or infrastructure details.');

  if (features.dashboard) {
    addFile(files, 'src/components/MetricCard.tsx', 'Render a labeled metric, value, trend, and accessible status.');
    addFile(files, 'src/components/AnalyticsChart.tsx', 'Render an accessible, responsive data visualization from typed input.');
    addFile(files, 'src/lib/dashboard-data.ts', 'Define typed dashboard metrics and deterministic sample data without personal information.');
  }
  if (features.authentication || features.realTime) {
    addFile(files, 'src/lib/auth/session.ts', 'Validate server-side sessions and centralize authorization decisions.');
    addFile(files, 'src/app/api/auth/session/route.ts', 'Expose a minimal session endpoint with secure cookie and CSRF policy requirements.');
  }
  if (features.persistence || features.finance) {
    addFile(files, 'src/app/api/metrics/route.ts', 'Validate and return bounded, typed metrics without exposing sensitive records.');
    if (features.finance) {
      addFile(files, 'src/lib/finance/money.ts', 'Represent and format monetary values without floating-point arithmetic.');
      addFile(files, 'src/db/schema.sql', 'Define constrained, auditable database tables for the requested domain.');
    }
  }
  if (features.realTime) {
    addFile(files, 'src/lib/realtime/events.ts', 'Define typed real-time events, validation boundaries, and reconnection behavior.');
    addFile(files, 'src/app/api/events/route.ts', 'Stream bounded, authenticated server events with backpressure and disconnect cleanup.');
  }
  addFile(files, 'tests/unit/formatters.test.ts', 'Verify formatting behavior, boundary cases, and invalid input handling.');
  addFile(files, '.env.example', 'List required environment variable names without secret values.');
  return files;
}

function backendFilePlan(profile: Exclude<ArchitectStackProfile, 'NEXTJS'>): ArchitectPlannedFile[] {
  if (profile === 'FASTAPI') {
    return [
      { path: 'README.md', responsibility: 'Document service setup, environment configuration, API routes, and deployment assumptions.' },
      { path: 'pyproject.toml', responsibility: 'Declare pinned Python dependencies, package metadata, and test configuration.' },
      { path: 'app/__init__.py', responsibility: 'Define the Python application package.' },
      { path: 'app/main.py', responsibility: 'Create the FastAPI application with lifecycle handling and router registration.' },
      { path: 'app/schemas.py', responsibility: 'Define validated request and response models.' },
      { path: 'app/routes/health.py', responsibility: 'Expose a minimal health route without sensitive diagnostics.' },
      { path: 'tests/test_health.py', responsibility: 'Test health responses and API error handling.' },
      { path: '.env.example', responsibility: 'List required environment variable names without secret values.' },
    ];
  }
  if (profile === 'RUST') {
    return [
      { path: 'README.md', responsibility: 'Document build, run, configuration, and operational constraints.' },
      { path: 'Cargo.toml', responsibility: 'Declare the Rust package and approved dependencies.' },
      { path: 'src/main.rs', responsibility: 'Initialize the service runtime and handle graceful shutdown.' },
      { path: 'src/lib.rs', responsibility: 'Expose validated domain types and reusable service logic.' },
      { path: 'src/routes/health.rs', responsibility: 'Implement a minimal health route.' },
      { path: 'tests/health_test.rs', responsibility: 'Exercise service and health-route behavior.' },
      { path: '.env.example', responsibility: 'List required environment variable names without secret values.' },
    ];
  }
  return [
    { path: 'README.md', responsibility: 'Document build, run, configuration, and operational constraints.' },
    { path: 'go.mod', responsibility: 'Declare the Go module and pinned dependencies.' },
    { path: 'cmd/server/main.go', responsibility: 'Initialize the HTTP service, configure timeouts, and handle graceful shutdown.' },
    { path: 'internal/health/handler.go', responsibility: 'Implement a minimal health handler without infrastructure disclosure.' },
    { path: 'internal/health/handler_test.go', responsibility: 'Test health status, response shape, and method handling.' },
    { path: '.env.example', responsibility: 'List required environment variable names without secret values.' },
  ];
}

function techStack(profile: ArchitectStackProfile, stackPreference: string, features: RequirementArchitectureBlueprint['featureSignals']): string[] {
  const preference = stackPreference.trim();
  if (profile === 'FASTAPI') {
    return ['Python 3.12+', 'FastAPI', 'Pydantic request validation', 'Pytest', ...(features.persistence ? ['SQLAlchemy-compatible persistence boundary'] : []), ...(preference ? [`Requested preference: ${preference}`] : [])];
  }
  if (profile === 'RUST') {
    return ['Stable Rust', 'Axum HTTP service', 'Serde validation', 'Cargo test', ...(preference ? [`Requested preference: ${preference}`] : [])];
  }
  if (profile === 'GO') {
    return ['Go 1.23+', 'net/http service', 'Go testing package', ...(preference ? [`Requested preference: ${preference}`] : [])];
  }
  return ['Next.js App Router', 'React', 'TypeScript strict mode', 'Tailwind CSS', 'Lucide React icons', ...(features.persistence ? ['PostgreSQL through a server-only data-access layer'] : []), ...(preference ? [`Requested preference: ${preference}`] : [])];
}

function componentHierarchy(profile: ArchitectStackProfile, features: RequirementArchitectureBlueprint['featureSignals']): string[] {
  if (profile !== 'NEXTJS') {
    return ['HTTP service', 'Route handlers', 'Validated request/response schemas', 'Domain and persistence services'];
  }
  return [
    'AppShell',
    features.authentication ? '  Authentication boundary and protected workspace' : '  Public workspace boundary',
    features.dashboard ? '  DashboardPage' : '  PrimaryFeaturePage',
    ...(features.dashboard ? ['    MetricCard[]', '    AnalyticsChart'] : []),
    ...(features.realTime ? ['    LiveEventStatus'] : []),
    '  Shared accessible navigation and status regions',
  ];
}

function apiContracts(features: RequirementArchitectureBlueprint['featureSignals']): string[] {
  const contracts = [
    'GET /api/health -> 200 { status: "ok" }; return no secrets, hostnames, or dependency internals.',
  ];
  if (features.persistence || features.dashboard) {
    contracts.push('GET /api/metrics -> 200 { data: Metric[] }; validate query bounds and return a stable error envelope on failure.');
  }
  if (features.authentication || features.realTime) {
    contracts.push('GET /api/auth/session -> 200 { authenticated: boolean }; use HttpOnly, Secure, SameSite cookies and verify origin/CSRF policy for mutations.');
  }
  if (features.realTime) {
    contracts.push('GET /api/events -> authenticated event stream; enforce origin checks, bounded connections, backpressure, and reconnect limits.');
  }
  return contracts;
}

function edgeCases(features: RequirementArchitectureBlueprint['featureSignals']): string[] {
  return [
    'Empty, malformed, oversized, and stale inputs must return typed errors without partial writes.',
    'Loading, empty, unauthorized, rate-limited, upstream-failure, and recovery states must be distinct.',
    'Currency precision, negative/zero values, missing timestamps, and timezone boundaries must be explicit.',
    ...(features.authentication ? ['Expired sessions, invalid CSRF tokens, revoked access, and concurrent logout must fail closed.'] : []),
    ...(features.realTime ? ['Disconnected clients, duplicate/out-of-order events, and slow consumers must not corrupt state.'] : []),
    ...(features.persistence ? ['Duplicate requests, transaction rollback, migration drift, and concurrent updates must be handled idempotently.'] : []),
  ];
}

function securityRequirements(features: RequirementArchitectureBlueprint['featureSignals']): string[] {
  return [
    'Validate all user input and model-produced content at runtime; use parameterized database operations.',
    'Keep credentials server-side, redact PII/secrets from logs, and use least-privilege service identities.',
    'Apply CSP, output encoding, secure cookies, rate limits, bounded request sizes, and dependency review.',
    'Never execute model output as shell commands; stage generated code in the VFS and require explicit review before apply/deploy.',
    ...(features.finance ? ['Use integer minor units or a decimal library for money; enforce ledger invariants and immutable audit events.'] : []),
    ...(features.authentication || features.realTime ? ['Enforce server-side authorization on every protected operation; UI visibility is not an access control.'] : []),
  ];
}

function buildMermaid(profile: ArchitectStackProfile, features: RequirementArchitectureBlueprint['featureSignals']): string {
  if (profile !== 'NEXTJS') {
    return [
      'flowchart TD',
      '  Client[Client] --> API[Validated HTTP API]',
      '  API --> Domain[Domain Services]',
      features.persistence ? '  Domain --> Store[(Persistent Store)]' : '  Domain --> Logic[Deterministic Service Logic]',
      '  API --> Tests[Contract and Unit Tests]',
    ].join('\n');
  }
  return [
    'flowchart TD',
    '  User[User] --> UI[Next.js App Router UI]',
    features.authentication ? '  UI --> Auth[Server Session and Authorization]' : '  UI --> API[Typed Route Handlers]',
    features.authentication ? '  Auth --> API[Typed Route Handlers]' : '  API --> Domain[Validated Domain Services]',
    features.authentication ? '  API --> Domain[Validated Domain Services]' : '  Domain --> Data[Typed Data Contract]',
    features.persistence ? '  Domain --> DB[(PostgreSQL)]' : '  Domain --> Data[Typed Data Contract]',
    features.realTime ? '  Domain --> Events[Bounded Real-Time Event Stream]' : '  Domain --> Tests[Unit and Contract Tests]',
    features.realTime ? '  Events --> Tests[Unit and Contract Tests]' : '  UI --> Tests',
  ].join('\n');
}

function makeBlueprint(prompt: string, stackPreference: string): RequirementArchitectureBlueprint {
  const features = inferFeatures(prompt);
  const stackProfile = selectStackProfile(stackPreference);
  const privacySafePrompt = enforcePrivacyComplianceInCode(prompt).compliantText;
  const privacySafePreference = enforcePrivacyComplianceInCode(stackPreference).compliantText;
  const safeInputs = scrubHardcodedSecrets([
    { path: 'request.txt', content: privacySafePrompt },
    { path: 'stack-preference.txt', content: privacySafePreference },
  ]).scrubbedFiles;
  const plannedFiles = stackProfile === 'NEXTJS'
    ? nextFilePlan(features)
    : backendFilePlan(stackProfile);
  const boundedPrompt = (safeInputs[0]?.content ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return {
    projectTitle: projectTitle(prompt, features),
    stackProfile,
    targetTechStack: techStack(stackProfile, safeInputs[1]?.content ?? '', features),
    plannedFiles,
    componentHierarchy: componentHierarchy(stackProfile, features),
    apiContract: apiContracts(features),
    edgeCases: edgeCases(features),
    securityRequirements: securityRequirements(features),
    featureSignals: features,
    requestSummary: boundedPrompt.slice(0, 1_000),
  };
}

/** Decomposes a natural-language request into a bounded, deterministic implementation blueprint. */
export async function runRequirementArchitectAgent(
  userPrompt: string,
  stackPreference = '',
): Promise<{
  blueprintSummary: string;
  plannedFiles: Array<{ path: string; responsibility: string }>;
  architectureDiagramMermaid: string;
  stepTrace: AgentStepTrace;
}> {
  if (typeof userPrompt !== 'string' || userPrompt.trim().length === 0 || userPrompt.length > MAX_PROMPT_CHARS) {
    throw new TypeError('Architect prompt must be non-empty and within the configured size limit.');
  }
  if (typeof stackPreference !== 'string' || stackPreference.length > MAX_STACK_PREFERENCE_CHARS) {
    throw new TypeError('Stack preference must be a string within the configured size limit.');
  }

  const started = Date.now();
  const blueprint = makeBlueprint(userPrompt, stackPreference);
  const blueprintSummary = [
    `Project: ${blueprint.projectTitle}`,
    `Request summary: ${blueprint.requestSummary}`,
    `Target tech stack: ${blueprint.targetTechStack.join(', ')}.`,
    `Component hierarchy:\n${blueprint.componentHierarchy.map(item => `- ${item}`).join('\n')}`,
    `API contract:\n${blueprint.apiContract.map(item => `- ${item}`).join('\n')}`,
    `Edge cases:\n${blueprint.edgeCases.map(item => `- ${item}`).join('\n')}`,
    `Security requirements:\n${blueprint.securityRequirements.map(item => `- ${item}`).join('\n')}`,
    `Planned implementation files: ${blueprint.plannedFiles.length}.`,
  ].join('\n\n');
  const completedAt = new Date().toISOString();
  const stepTrace: AgentStepTrace = {
    traceId: randomUUID(),
    operationId: randomUUID(),
    agentId: 'requirement-architect-1',
    role: 'ARCHITECT',
    status: 'SUCCEEDED',
    startedAt: new Date(started).toISOString(),
    completedAt,
    inputSummary: `Architected ${blueprint.stackProfile} plan from ${userPrompt.length} prompt characters.`,
    outputSummary: `Produced ${blueprint.plannedFiles.length} planned files and ${blueprint.apiContract.length} API contracts.`,
    affectedPaths: blueprint.plannedFiles.map(file => file.path),
  };

  return {
    blueprintSummary,
    plannedFiles: blueprint.plannedFiles.map(file => ({ ...file })),
    architectureDiagramMermaid: buildMermaid(blueprint.stackProfile, blueprint.featureSignals),
    stepTrace,
  };
}

export function parseRequirementBlueprint(value: unknown): RequirementArchitectureBlueprint | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return undefined;
  }
  const candidate = value as Partial<RequirementArchitectureBlueprint>;
  const signals = candidate.featureSignals;
  if (
    typeof candidate.projectTitle !== 'string' ||
    candidate.projectTitle.length > 200 ||
    !['NEXTJS', 'FASTAPI', 'RUST', 'GO'].includes(candidate.stackProfile ?? '') ||
    !Array.isArray(candidate.plannedFiles) ||
    candidate.plannedFiles.length === 0 ||
    candidate.plannedFiles.length > 100 ||
    !Array.isArray(candidate.targetTechStack) ||
    candidate.targetTechStack.length === 0 ||
    candidate.targetTechStack.length > 30 ||
    candidate.targetTechStack.some(item => typeof item !== 'string' || item.length > 256) ||
    !signals ||
    typeof signals.dashboard !== 'boolean' ||
    typeof signals.finance !== 'boolean' ||
    typeof signals.authentication !== 'boolean' ||
    typeof signals.realTime !== 'boolean' ||
    typeof signals.persistence !== 'boolean' ||
    !Array.isArray(candidate.componentHierarchy) ||
    candidate.componentHierarchy.some(item => typeof item !== 'string' || item.length > 1_000) ||
    !Array.isArray(candidate.apiContract) ||
    candidate.apiContract.some(item => typeof item !== 'string' || item.length > 2_000) ||
    !Array.isArray(candidate.edgeCases) ||
    candidate.edgeCases.some(item => typeof item !== 'string' || item.length > 2_000) ||
    !Array.isArray(candidate.securityRequirements) ||
    candidate.securityRequirements.some(item => typeof item !== 'string' || item.length > 2_000) ||
    typeof candidate.requestSummary !== 'string' ||
    candidate.requestSummary.length > 2_000
  ) {
    return undefined;
  }
  const plannedFiles = candidate.plannedFiles.filter((file): file is ArchitectPlannedFile =>
    typeof file?.path === 'string' &&
    typeof file.responsibility === 'string' &&
    file.path.length <= 1_024 &&
    !file.path.startsWith('/') &&
    !file.path.includes('\\') &&
    !file.path.split('/').some(segment => segment === '..' || segment === '.')
  );
  if (plannedFiles.length !== candidate.plannedFiles.length || plannedFiles.length === 0 || plannedFiles.length > 100) {
    return undefined;
  }
  if (new Set(plannedFiles.map(file => file.path)).size !== plannedFiles.length) {
    return undefined;
  }
  return {
    projectTitle: candidate.projectTitle.replace(/[\u0000-\u001f\u007f]/g, ' ').trim(),
    stackProfile: candidate.stackProfile as ArchitectStackProfile,
    targetTechStack: candidate.targetTechStack as string[],
    plannedFiles,
    componentHierarchy: candidate.componentHierarchy as string[],
    apiContract: candidate.apiContract as string[],
    edgeCases: candidate.edgeCases as string[],
    securityRequirements: candidate.securityRequirements as string[],
    featureSignals: {
      dashboard: signals.dashboard,
      finance: signals.finance,
      authentication: signals.authentication,
      realTime: signals.realTime,
      persistence: signals.persistence,
    },
    requestSummary: candidate.requestSummary.replace(/[\u0000-\u001f\u007f]/g, ' ').trim(),
  };
}

export function createRequirementBlueprint(userPrompt: string, stackPreference = ''): RequirementArchitectureBlueprint {
  return makeBlueprint(userPrompt, stackPreference);
}