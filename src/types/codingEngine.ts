/** Shared contracts for the Techyonx kode coding engine. */

export type ISODateTime = string;

export type AIProviderType =
  | 'GEMINI_API'
  | 'TECHYONX_KODE_CUSTOM_API'
  | 'OPENAI_COMPATIBLE'
  | 'OFFLINE_DETERMINISTIC';

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type OperationStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'CANCELLED'
  | 'SKIPPED';

export interface TokenUsage {
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly totalTokens: number;
  readonly cachedInputTokens?: number;
}

export interface ModelRoutingConfig {
  readonly provider: AIProviderType;
  readonly modelId: string;
  /** Server-side vault reference; never the credential value. */
  readonly credentialRef?: string;
  readonly endpointUrl?: string;
  readonly apiVersion?: string;
  readonly temperature: number;
  readonly maxOutputTokens: number;
  readonly timeoutMs: number;
  readonly retryLimit: number;
  readonly supportsStreaming: boolean;
  readonly supportsStructuredOutput: boolean;
  readonly allowedTaskTypes: readonly string[];
  readonly fallbackProviders: readonly AIProviderType[];
}

export type StreamingCodeChunkKind =
  | 'TEXT'
  | 'CODE'
  | 'PATCH'
  | 'TOOL_CALL'
  | 'USAGE'
  | 'HEARTBEAT'
  | 'COMPLETE'
  | 'ERROR';

export interface StreamingCodeChunk {
  readonly requestId: string;
  readonly sequence: number;
  readonly kind: StreamingCodeChunkKind;
  readonly content: string;
  readonly filePath?: string;
  readonly language?: string;
  readonly usage?: TokenUsage;
  readonly finishReason?: 'STOP' | 'LENGTH' | 'TOOL_CALL' | 'SAFETY' | 'ERROR';
  readonly emittedAt: ISODateTime;
}

export type VirtualFileStatus = 'CLEAN' | 'ADDED' | 'MODIFIED' | 'DELETED';

export interface VirtualFile {
  readonly path: string;
  readonly content: string;
  readonly language: string;
  readonly encoding: 'utf-8' | 'base64';
  readonly sizeBytes: number;
  readonly sha256: string;
  readonly version: number;
  readonly status: VirtualFileStatus;
  readonly createdAt: ISODateTime;
  readonly modifiedAt: ISODateTime;
}

export interface VirtualDirectory {
  readonly kind: 'DIRECTORY';
  readonly name: string;
  readonly path: string;
  readonly children: readonly VirtualFileSystemNode[];
}

export interface VirtualFileNode {
  readonly kind: 'FILE';
  readonly file: VirtualFile;
}

export type VirtualFileSystemNode = VirtualDirectory | VirtualFileNode;

export interface VirtualDirectoryTree {
  readonly workspaceId: string;
  readonly root: VirtualDirectory;
  readonly version: number;
  readonly capturedAt: ISODateTime;
}

export type PatchOperation = 'CREATE' | 'UPDATE' | 'DELETE';

export interface SurgicalDiffHunk {
  readonly oldStart: number;
  readonly oldLineCount: number;
  readonly newStart: number;
  readonly newLineCount: number;
  readonly header?: string;
  readonly lines: readonly string[];
}

export interface SurgicalDiffPatch {
  readonly patchId: string;
  readonly operationId: string;
  readonly filePath: string;
  readonly operation: PatchOperation;
  readonly baseFileSha256?: string;
  readonly resultFileSha256?: string;
  readonly hunks: readonly SurgicalDiffHunk[];
  readonly unifiedDiff: string;
  readonly rationale: string;
  readonly confidence: number;
  readonly createdAt: ISODateTime;
  readonly requiresUserApproval: boolean;
}

export interface SourceLocation {
  readonly filePath: string;
  readonly startLine: number;
  readonly startColumn?: number;
  readonly endLine?: number;
  readonly endColumn?: number;
}

export interface AnalysisDiagnostic {
  readonly code: string;
  readonly message: string;
  readonly severity: Severity;
  readonly location?: SourceLocation;
  readonly source: string;
}

export interface ASTSymbol {
  readonly name: string;
  readonly kind:
    | 'CLASS'
    | 'FUNCTION'
    | 'METHOD'
    | 'VARIABLE'
    | 'TYPE'
    | 'INTERFACE'
    | 'ENUM'
    | 'PROPERTY'
    | 'OTHER';
  readonly exported: boolean;
  readonly location: SourceLocation;
}

export interface ASTImport {
  readonly source: string;
  readonly importedNames: readonly string[];
  readonly isTypeOnly: boolean;
  readonly location: SourceLocation;
}

export interface ASTAnalysisResult {
  readonly analysisId: string;
  readonly filePath: string;
  readonly language: string;
  readonly parserName: string;
  readonly parserVersion: string;
  readonly succeeded: boolean;
  readonly diagnostics: readonly AnalysisDiagnostic[];
  readonly symbols: readonly ASTSymbol[];
  readonly imports: readonly ASTImport[];
  readonly exports: readonly string[];
  readonly linesOfCode: number;
  readonly analyzedAt: ISODateTime;
}

export type BugCategory =
  | 'LOGIC'
  | 'TYPE'
  | 'RUNTIME'
  | 'SECURITY'
  | 'PERFORMANCE'
  | 'DEPENDENCY'
  | 'ACCESSIBILITY'
  | 'OTHER';

export type BugStatus = 'OPEN' | 'CONFIRMED' | 'FIXED' | 'DISMISSED';

export interface DetectedBugReport {
  readonly bugId: string;
  readonly operationId: string;
  readonly title: string;
  readonly description: string;
  readonly category: BugCategory;
  readonly severity: Severity;
  readonly confidence: number;
  readonly status: BugStatus;
  readonly location?: SourceLocation;
  readonly evidence: readonly string[];
  readonly reproductionSteps: readonly string[];
  readonly suggestedPatchId?: string;
  readonly detectedAt: ISODateTime;
}

export type TestCaseStatus = 'PASSED' | 'FAILED' | 'SKIPPED' | 'TIMED_OUT';

export interface UnitTestCaseResult {
  readonly name: string;
  readonly status: TestCaseStatus;
  readonly durationMs: number;
  readonly failureMessage?: string;
  readonly location?: SourceLocation;
}

export interface UnitTestExecutionReport {
  readonly runId: string;
  readonly operationId: string;
  readonly status: OperationStatus;
  readonly command: string;
  readonly startedAt: ISODateTime;
  readonly completedAt?: ISODateTime;
  readonly durationMs: number;
  readonly totalCount: number;
  readonly passedCount: number;
  readonly failedCount: number;
  readonly skippedCount: number;
  readonly timedOutCount: number;
  readonly cases: readonly UnitTestCaseResult[];
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode?: number;
}

export type AgentRole =
  | 'ARCHITECT'
  | 'POLYGLOT_CODER'
  | 'AST_ANALYZER'
  | 'BUG_HUNTER'
  | 'SURGICAL_PATCHER'
  | 'UNIT_TESTER'
  | 'REFACTOR_PERF'
  | 'DEPENDENCY_LINKER'
  | 'TERMINAL_HEALER'
  | 'DB_API_SCHEMA'
  | 'DOCUMENTATION';

export interface AgentStepTrace {
  readonly traceId: string;
  readonly operationId: string;
  readonly agentId: string;
  readonly role: AgentRole;
  readonly status: OperationStatus;
  readonly startedAt: ISODateTime;
  readonly completedAt?: ISODateTime;
  readonly parentAgentId?: string;
  readonly inputSummary: string;
  readonly outputSummary?: string;
  readonly affectedPaths: readonly string[];
  readonly usage?: TokenUsage;
  readonly errorCode?: string;
  readonly errorMessage?: string;
}

export type AuditDecision = 'PASS' | 'FAIL' | 'REVIEW_REQUIRED';

export interface OWASPFinding {
  readonly findingId: string;
  readonly category: string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly confidence: number;
  readonly location?: SourceLocation;
  readonly evidence: readonly string[];
  readonly remediation?: string;
  readonly detectedAt: ISODateTime;
}

export interface SecurityAuditReport {
  readonly auditId: string;
  readonly operationId: string;
  readonly decision: AuditDecision;
  readonly findings: readonly OWASPFinding[];
  readonly scannedPaths: readonly string[];
  readonly rulesetVersion: string;
  readonly startedAt: ISODateTime;
  readonly completedAt: ISODateTime;
}

export interface CleanRoomComplianceCertificate {
  readonly certificateId: string;
  readonly projectId: string;
  readonly operationId: string;
  readonly decision: AuditDecision;
  readonly policyVersion: string;
  readonly verifiedArtifactDigests: readonly string[];
  readonly evidenceReferences: readonly string[];
  readonly limitations: readonly string[];
  readonly issuedAt: ISODateTime;
  readonly expiresAt?: ISODateTime;
  readonly signerKeyId?: string;
  readonly signature?: string;
}

export type LicensePolicyDecision = 'ALLOWED' | 'DENIED' | 'REVIEW_REQUIRED' | 'UNKNOWN';

export interface SPDXLicenseCheck {
  readonly checkId: string;
  readonly packageName: string;
  readonly packageVersion: string;
  readonly spdxExpression?: string;
  readonly decision: LicensePolicyDecision;
  readonly policyVersion: string;
  readonly source: string;
  readonly checkedAt: ISODateTime;
  readonly findings: readonly string[];
}

export type GitProvider = 'GITHUB' | 'GITLAB' | 'BITBUCKET' | 'GENERIC_GIT';

export interface GitDeployPayload {
  readonly deploymentId: string;
  readonly workspaceId: string;
  readonly snapshotVersion: number;
  readonly snapshotSha256: string;
  readonly provider: GitProvider;
  readonly repositoryUrl: string;
  readonly credentialRef: string;
  readonly targetBranch: string;
  readonly expectedHeadSha?: string;
  readonly commitMessage: string;
  readonly filePaths: readonly string[];
  readonly authorizedBy: string;
  readonly authorizedAt: ISODateTime;
}

export interface GitPushResult {
  readonly deploymentId: string;
  readonly succeeded: boolean;
  readonly provider: GitProvider;
  readonly repositoryUrl: string;
  readonly targetBranch: string;
  readonly commitSha?: string;
  readonly remoteUrl?: string;
  readonly completedAt: ISODateTime;
  readonly errorCode?: string;
  readonly errorMessage?: string;
}

export interface ImmuneSystemTelemetry {
  readonly sampledAt: ISODateTime;
  readonly overallStatus: 'HEALTHY' | 'DEGRADED' | 'RECOVERING' | 'UNAVAILABLE';
  readonly activeOperations: number;
  readonly queuedOperations: number;
  readonly circuitBreakersOpen: number;
  readonly providerFallbackCount: number;
  readonly recoveredOperationCount: number;
  readonly failedOperationCount: number;
  readonly memoryUsedBytes?: number;
  readonly memoryLimitBytes?: number;
  readonly components: readonly {
    readonly componentId: string;
    readonly status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE';
    readonly lastErrorCode?: string;
    readonly lastCheckedAt: ISODateTime;
  }[];
}

export interface FinOpsTokenMetrics {
  readonly operationId: string;
  readonly provider: AIProviderType;
  readonly modelId: string;
  readonly usage: TokenUsage;
  readonly estimatedCost: number;
  readonly currency: string;
  readonly cacheReadTokens: number;
  readonly requestCount: number;
  readonly recordedAt: ISODateTime;
}