import { createHash } from 'node:crypto';
import { inspectCodingPromptSecurity } from './codeInjectionFirewall';
import { checkCodingRateLimit, type CodingRateLimitDecision } from './ddosAndRateGovernor';
import { signGeneratedCodeBundle, type SignedCodeBundle } from './cryptographicCodeSigner';
import { scanForMaliciousCode, type MaliciousCodeFinding } from './maliciousCodeDetector';
import { runOwaspSecurityAudit, type OwaspVulnerability } from './owaspVulnerabilityScanner';
import { scrubHardcodedSecrets } from './secretLeakPrevention';
import {
  createIsolatedPreviewHtml,
  PREVIEW_IFRAME_SANDBOX,
} from './sandboxIsolationGuard';

export type SecurityPipelineStatus =
  | 'ALLOWED'
  | 'BLOCKED'
  | 'RATE_LIMITED'
  | 'SIGNING_UNAVAILABLE'
  | 'INPUT_REJECTED';

export type SecurityTelemetryEventType =
  | 'RATE_LIMIT_BLOCKED'
  | 'PROMPT_BLOCKED'
  | 'SECRET_SCRUBBED'
  | 'MALICIOUS_CODE_BLOCKED'
  | 'OWASP_AUTO_FIXED'
  | 'OWASP_REVIEW_REQUIRED'
  | 'PREVIEW_CREATED'
  | 'BUNDLE_SIGNED'
  | 'SIGNING_FAILED'
  | 'INPUT_REJECTED';

export interface SecurityTelemetryEvent {
  readonly timestamp: string;
  readonly type: SecurityTelemetryEventType;
  readonly clientIdHash: string;
  readonly affectedFileCount: number;
  readonly findingCount: number;
  readonly securityScore?: number;
}

export interface SecurityTelemetrySummary {
  readonly eventsRecorded: number;
  readonly retainedEvents: number;
  readonly countsByType: Readonly<Record<SecurityTelemetryEventType, number>>;
  readonly recentEvents: readonly SecurityTelemetryEvent[];
}

export interface SecurityPipelineResult {
  readonly status: SecurityPipelineStatus;
  readonly allowed: boolean;
  readonly blockedReason?: string;
  readonly sanitizedPrompt: string;
  readonly rateLimit: CodingRateLimitDecision;
  readonly files: Array<{ path: string; content: string }>;
  readonly secretsPreventedCount: number;
  readonly maliciousFindings: MaliciousCodeFinding[];
  readonly securityScore: number;
  readonly vulnerabilities: OwaspVulnerability[];
  readonly signature: SignedCodeBundle | null;
  readonly preview: {
    readonly safeSrcDoc: string;
    readonly cspHeader: string;
    readonly iframeSandbox: typeof PREVIEW_IFRAME_SANDBOX;
  } | null;
}

interface TelemetryEventInput {
  readonly type: SecurityTelemetryEventType;
  readonly clientId: string;
  readonly affectedFileCount?: number;
  readonly findingCount?: number;
  readonly securityScore?: number;
}

const TELEMETRY_CAPACITY = 1_000;
const RECENT_EVENT_LIMIT = 25;
const MAX_CLIENT_ID_CHARS = 1_024;
const MAX_INPUT_FILE_COUNT = 20_000;
const MAX_INPUT_SOURCE_CHARS = 16_000_000;
const telemetryRing: Array<SecurityTelemetryEvent | undefined> = new Array(TELEMETRY_CAPACITY);
const telemetryCounts: Record<SecurityTelemetryEventType, number> = {
  RATE_LIMIT_BLOCKED: 0,
  PROMPT_BLOCKED: 0,
  SECRET_SCRUBBED: 0,
  MALICIOUS_CODE_BLOCKED: 0,
  OWASP_AUTO_FIXED: 0,
  OWASP_REVIEW_REQUIRED: 0,
  PREVIEW_CREATED: 0,
  BUNDLE_SIGNED: 0,
  SIGNING_FAILED: 0,
  INPUT_REJECTED: 0,
};

let ringStart = 0;
let ringSize = 0;
let lifetimeEventsRecorded = 0;

function clientIdDigest(clientId: string): string {
  return createHash('sha256').update(clientId, 'utf8').digest('hex').slice(0, 20);
}

function recordTelemetry(input: TelemetryEventInput): void {
  const event: SecurityTelemetryEvent = {
    timestamp: new Date().toISOString(),
    type: input.type,
    clientIdHash: clientIdDigest(input.clientId),
    affectedFileCount: input.affectedFileCount ?? 0,
    findingCount: input.findingCount ?? 0,
    ...(input.securityScore !== undefined ? { securityScore: input.securityScore } : {}),
  };

  const writeIndex = (ringStart + ringSize) % TELEMETRY_CAPACITY;
  if (ringSize < TELEMETRY_CAPACITY) {
    telemetryRing[writeIndex] = event;
    ringSize += 1;
  } else {
    telemetryRing[ringStart] = event;
    ringStart = (ringStart + 1) % TELEMETRY_CAPACITY;
  }
  telemetryCounts[input.type] += 1;
  lifetimeEventsRecorded += 1;
}

function recentEvents(limit: number): SecurityTelemetryEvent[] {
  const count = Math.min(limit, ringSize);
  const result: SecurityTelemetryEvent[] = [];
  const firstIndex = (ringStart + ringSize - count + TELEMETRY_CAPACITY) % TELEMETRY_CAPACITY;
  for (let offset = 0; offset < count; offset += 1) {
    const index = (firstIndex + offset) % TELEMETRY_CAPACITY;
    const event = telemetryRing[index];
    if (event) {
      result.push(event);
    }
  }
  return result;
}

function emptyRateDecision(resetInMs = 0): CodingRateLimitDecision {
  return { allowed: false, remainingRequests: 0, resetInMs };
}

function pipelineResult(
  input: {
    readonly status: SecurityPipelineStatus;
    readonly blockedReason?: string;
    readonly sanitizedPrompt?: string;
    readonly rateLimit: CodingRateLimitDecision;
    readonly files?: Array<{ path: string; content: string }>;
    readonly secretsPreventedCount?: number;
    readonly maliciousFindings?: MaliciousCodeFinding[];
    readonly securityScore?: number;
    readonly vulnerabilities?: OwaspVulnerability[];
    readonly signature?: SignedCodeBundle | null;
    readonly preview?: SecurityPipelineResult['preview'];
  },
): SecurityPipelineResult {
  return {
    status: input.status,
    allowed: input.status === 'ALLOWED',
    ...(input.blockedReason ? { blockedReason: input.blockedReason } : {}),
    sanitizedPrompt: input.sanitizedPrompt ?? '',
    rateLimit: input.rateLimit,
    files: input.files ?? [],
    secretsPreventedCount: input.secretsPreventedCount ?? 0,
    maliciousFindings: input.maliciousFindings ?? [],
    securityScore: input.securityScore ?? 0,
    vulnerabilities: input.vulnerabilities ?? [],
    signature: input.signature ?? null,
    preview: input.preview ?? null,
  };
}

function validatePipelineInput(
  prompt: string,
  files: Array<{ path: string; content: string }>,
  clientId: string,
): string | undefined {
  if (typeof clientId !== 'string' || clientId.trim().length === 0 || clientId.length > MAX_CLIENT_ID_CHARS) {
    return 'Client identifier is invalid.';
  }
  if (typeof prompt !== 'string' || !Array.isArray(files) || files.length > MAX_INPUT_FILE_COUNT) {
    return 'Prompt or file list is invalid.';
  }

  let totalChars = prompt.length;
  for (const file of files) {
    if (typeof file?.path !== 'string' || typeof file.content !== 'string') {
      return 'Every file must have a string path and content.';
    }
    totalChars += file.content.length;
    if (totalChars > MAX_INPUT_SOURCE_CHARS) {
      return `Security pipeline input exceeds the ${MAX_INPUT_SOURCE_CHARS}-character limit.`;
    }
  }
  return undefined;
}

function hasUnresolvedVulnerabilities(vulnerabilities: readonly OwaspVulnerability[]): boolean {
  return vulnerabilities.some(vulnerability => !vulnerability.autoFixed);
}

/** Runs rate, prompt, secret, malware, OWASP, preview, and signing gates in order. */
export function runFullCodeSecurityPipeline(
  prompt: string,
  files: Array<{ path: string; content: string }>,
  clientId: string,
): SecurityPipelineResult {
  const invalidReason = validatePipelineInput(prompt, files, clientId);
  if (invalidReason) {
    recordTelemetry({ type: 'INPUT_REJECTED', clientId: typeof clientId === 'string' ? clientId.slice(0, MAX_CLIENT_ID_CHARS) : 'invalid-client' });
    return pipelineResult({
      status: 'INPUT_REJECTED',
      blockedReason: invalidReason,
      rateLimit: emptyRateDecision(),
    });
  }

  const rateLimit = checkCodingRateLimit(clientId);
  if (!rateLimit.allowed) {
    recordTelemetry({ type: 'RATE_LIMIT_BLOCKED', clientId, affectedFileCount: files.length });
    return pipelineResult({
      status: 'RATE_LIMITED',
      blockedReason: 'Client request rate limit exceeded.',
      rateLimit,
    });
  }

  const promptInspection = inspectCodingPromptSecurity(prompt, files.map(file => file.path));
  if (!promptInspection.allowed) {
    recordTelemetry({ type: 'PROMPT_BLOCKED', clientId, affectedFileCount: files.length, findingCount: 1 });
    return pipelineResult({
      status: 'BLOCKED',
      blockedReason: promptInspection.blockedReason ?? 'Prompt security policy rejected this request.',
      sanitizedPrompt: promptInspection.sanitizedPrompt,
      rateLimit,
    });
  }

  try {
    const scrubResult = scrubHardcodedSecrets([
      { path: '__prompt__.txt', content: promptInspection.sanitizedPrompt },
      ...files,
    ]);
    const sanitizedPrompt = scrubResult.scrubbedFiles[0]?.content ?? '';
    const scrubbedFiles = scrubResult.scrubbedFiles.slice(1);
    if (scrubResult.secretsPreventedCount > 0) {
      recordTelemetry({
        type: 'SECRET_SCRUBBED',
        clientId,
        affectedFileCount: files.length,
        findingCount: scrubResult.secretsPreventedCount,
      });
    }

    const malwareScan = scanForMaliciousCode(scrubbedFiles);
    if (!malwareScan.safe) {
      recordTelemetry({
        type: 'MALICIOUS_CODE_BLOCKED',
        clientId,
        affectedFileCount: files.length,
        findingCount: malwareScan.findings.length,
      });
    }

    const owaspAudit = runOwaspSecurityAudit(malwareScan.neutralizedFiles);
    const autoFixedCount = owaspAudit.vulnerabilities.filter(item => item.autoFixed).length;
    const unresolvedCount = owaspAudit.vulnerabilities.filter(item => !item.autoFixed).length;
    if (autoFixedCount > 0) {
      recordTelemetry({
        type: 'OWASP_AUTO_FIXED',
        clientId,
        affectedFileCount: files.length,
        findingCount: autoFixedCount,
        securityScore: owaspAudit.securityScore,
      });
    }
    if (unresolvedCount > 0) {
      recordTelemetry({
        type: 'OWASP_REVIEW_REQUIRED',
        clientId,
        affectedFileCount: files.length,
        findingCount: unresolvedCount,
        securityScore: owaspAudit.securityScore,
      });
    }

    let preview: SecurityPipelineResult['preview'] = null;
    const htmlFile = owaspAudit.healedFiles.find(file => /\.html?$/i.test(file.path));
    if (htmlFile) {
      const cssFile = owaspAudit.healedFiles.find(file => /\.css$/i.test(file.path));
      const isolated = createIsolatedPreviewHtml(htmlFile.content, cssFile?.content ?? '');
      preview = {
        safeSrcDoc: isolated.safeSrcDoc,
        cspHeader: isolated.cspHeader,
        iframeSandbox: PREVIEW_IFRAME_SANDBOX,
      };
      recordTelemetry({ type: 'PREVIEW_CREATED', clientId, affectedFileCount: 1 });
    }

    if (!malwareScan.safe || hasUnresolvedVulnerabilities(owaspAudit.vulnerabilities)) {
      return pipelineResult({
        status: 'BLOCKED',
        blockedReason: !malwareScan.safe
          ? 'Malicious-code findings require review; neutralized output is provided but not approved for execution.'
          : 'Unresolved OWASP findings require review before this bundle can be approved.',
        sanitizedPrompt,
        rateLimit,
        files: owaspAudit.healedFiles,
        secretsPreventedCount: scrubResult.secretsPreventedCount,
        maliciousFindings: malwareScan.findings,
        securityScore: owaspAudit.securityScore,
        vulnerabilities: owaspAudit.vulnerabilities,
        preview,
      });
    }

    let signature: SignedCodeBundle;
    try {
      signature = signGeneratedCodeBundle(owaspAudit.healedFiles);
    } catch {
      recordTelemetry({
        type: 'SIGNING_FAILED',
        clientId,
        affectedFileCount: files.length,
        securityScore: owaspAudit.securityScore,
      });
      return pipelineResult({
        status: 'SIGNING_UNAVAILABLE',
        blockedReason: 'Bundle signing could not be completed; configure the server-side signing key before approval.',
        sanitizedPrompt,
        rateLimit,
        files: owaspAudit.healedFiles,
        secretsPreventedCount: scrubResult.secretsPreventedCount,
        maliciousFindings: malwareScan.findings,
        securityScore: owaspAudit.securityScore,
        vulnerabilities: owaspAudit.vulnerabilities,
        preview,
      });
    }

    recordTelemetry({
      type: 'BUNDLE_SIGNED',
      clientId,
      affectedFileCount: files.length,
      securityScore: owaspAudit.securityScore,
    });
    return pipelineResult({
      status: 'ALLOWED',
      sanitizedPrompt,
      rateLimit,
      files: owaspAudit.healedFiles,
      secretsPreventedCount: scrubResult.secretsPreventedCount,
      maliciousFindings: malwareScan.findings,
      securityScore: owaspAudit.securityScore,
      vulnerabilities: owaspAudit.vulnerabilities,
      signature,
      preview,
    });
  } catch {
    recordTelemetry({ type: 'INPUT_REJECTED', clientId, affectedFileCount: files.length });
    return pipelineResult({
      status: 'BLOCKED',
      blockedReason: 'Security pipeline validation failed; no bundle was approved.',
      sanitizedPrompt: promptInspection.sanitizedPrompt,
      rateLimit,
    });
  }
}

/** Returns aggregate counts and the newest sanitized events from the in-memory ring buffer. */
export function getSecurityTelemetrySummary(): SecurityTelemetrySummary {
  return {
    eventsRecorded: lifetimeEventsRecorded,
    retainedEvents: ringSize,
    countsByType: { ...telemetryCounts },
    recentEvents: recentEvents(RECENT_EVENT_LIMIT),
  };
}