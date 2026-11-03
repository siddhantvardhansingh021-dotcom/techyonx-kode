import type { AIProviderType } from '../../types/codingEngine';

export type ProviderQuotaHealth = 'HEALTHY' | 'DEGRADED' | 'EXHAUSTED';

export interface OptimalCodingModel {
  readonly provider: string;
  readonly modelName: string;
  readonly maxTokens: number;
  readonly temperature: number;
  readonly reason: string;
}

interface ProviderCandidate {
  readonly provider: AIProviderType;
  readonly modelName: string;
  readonly supportsDeepReasoning: boolean;
  readonly costWeight: number;
  readonly latencyWeight: number;
}

interface RuntimeQuotaState {
  readonly health: ProviderQuotaHealth;
  readonly blockedUntil: number;
}

const runtimeQuotaStates = new Map<AIProviderType, RuntimeQuotaState>();

function readEnvironment(name: string): string {
  const runtime = globalThis as typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
  };
  return runtime.process?.env?.[name]?.trim() ?? '';
}

function parseWeight(value: string, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.min(parsed, 1000) : fallback;
}

function parseTokenLimit(value: string, fallback: number): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? Math.min(parsed, 32_768) : fallback;
}

function isComplexTask(taskType: string, estimatedPromptTokens: number): boolean {
  const normalizedTask = taskType.toLowerCase();
  const requestsDeepWork =
    /architect|architecture|full.?stack|multi.?file|system.?design|migration|large.?refactor|deep.?reason|complex|end.?to.?end|feature.?build/.test(
      normalizedTask,
    );
  const requestsQuickWork =
    /syntax.?fix|typo|format|lint|small.?patch|ast.?patch|single.?line|simple.?fix/.test(
      normalizedTask,
    );

  if (requestsDeepWork || estimatedPromptTokens >= 6_000) {
    return true;
  }

  return !requestsQuickWork && estimatedPromptTokens >= 2_500;
}

function healthEnvironmentKey(provider: AIProviderType): string {
  switch (provider) {
    case 'GEMINI_API':
      return 'GEMINI_QUOTA_HEALTH';
    case 'TECHYONX_KODE_CUSTOM_API':
      return 'CUSTOM_API_QUOTA_HEALTH';
    case 'OPENAI_COMPATIBLE':
      return 'OPENAI_COMPATIBLE_QUOTA_HEALTH';
    case 'OFFLINE_DETERMINISTIC':
      return '';
  }
}

function getQuotaHealth(provider: AIProviderType): ProviderQuotaHealth {
  const runtimeState = runtimeQuotaStates.get(provider);
  if (runtimeState && runtimeState.blockedUntil > Date.now()) {
    return runtimeState.health;
  }
  if (runtimeState?.health === 'EXHAUSTED') {
    runtimeQuotaStates.set(provider, { health: 'HEALTHY', blockedUntil: 0 });
    return 'HEALTHY';
  }
  if (runtimeState?.health === 'DEGRADED') {
    return 'DEGRADED';
  }

  const configuredHealth = readEnvironment(healthEnvironmentKey(provider)).toUpperCase();
  if (configuredHealth === 'EXHAUSTED' || configuredHealth === 'DEGRADED') {
    return configuredHealth;
  }
  return 'HEALTHY';
}

/** Updates process-local health after a provider call; exhausted state expires after cooldownMs. */
export function reportProviderQuotaHealth(
  provider: AIProviderType,
  health: ProviderQuotaHealth,
  cooldownMs = 60_000,
): void {
  const safeCooldownMs = Number.isFinite(cooldownMs)
    ? Math.max(0, Math.min(cooldownMs, 3_600_000))
    : 60_000;
  runtimeQuotaStates.set(provider, {
    health,
    blockedUntil: health === 'EXHAUSTED' ? Date.now() + safeCooldownMs : 0,
  });
}

function configuredCandidates(complexTask: boolean): ProviderCandidate[] {
  const candidates: ProviderCandidate[] = [];

  if (readEnvironment('GEMINI_API_KEY') || readEnvironment('GEMINI_API_KEYS_POOL')) {
    const generalModel = readEnvironment('GEMINI_MODEL');
    const fastModel = readEnvironment('GEMINI_FAST_MODEL');
    const reasoningModel = readEnvironment('GEMINI_REASONING_MODEL');
    const modelName = complexTask
      ? reasoningModel || generalModel || 'gemini-2.5-pro'
      : fastModel || generalModel || 'gemini-2.5-flash';
    const isReasoningModel = Boolean(reasoningModel) || /pro|reason|thinking/i.test(modelName);
    candidates.push({
      provider: 'GEMINI_API',
      modelName,
      supportsDeepReasoning: isReasoningModel || /pro|reason|thinking/i.test(modelName),
      costWeight: parseWeight(
        readEnvironment('GEMINI_COST_WEIGHT'),
        complexTask ? 0.8 : 0.15,
      ),
      latencyWeight: parseWeight(
        readEnvironment('GEMINI_LATENCY_WEIGHT'),
        complexTask ? 0.55 : 0.1,
      ),
    });
  }

  if (
    (readEnvironment('CUSTOM_API_KEY') || readEnvironment('CUSTOM_API_KEYS_POOL')) &&
    readEnvironment('CUSTOM_API_BASE_URL')
  ) {
    const generalModel = readEnvironment('CUSTOM_API_MODEL');
    const fastModel = readEnvironment('CUSTOM_API_FAST_MODEL');
    const reasoningModel = readEnvironment('CUSTOM_API_REASONING_MODEL');
    candidates.push({
      provider: 'TECHYONX_KODE_CUSTOM_API',
      modelName: complexTask
        ? reasoningModel || generalModel || 'default'
        : fastModel || generalModel || 'default',
      supportsDeepReasoning: Boolean(reasoningModel),
      costWeight: parseWeight(readEnvironment('CUSTOM_API_COST_WEIGHT'), 0.3),
      latencyWeight: parseWeight(readEnvironment('CUSTOM_API_LATENCY_WEIGHT'), 0.3),
    });
  }

  const openAIKey = readEnvironment('OPENAI_COMPATIBLE_API_KEY') || readEnvironment('OPENAI_API_KEY');
  const openAIBaseUrl =
    readEnvironment('OPENAI_COMPATIBLE_BASE_URL') ||
    readEnvironment('OPENAI_BASE_URL') ||
    (openAIKey ? 'https://api.openai.com/v1' : '');
  if (openAIKey && openAIBaseUrl) {
    const generalModel =
      readEnvironment('OPENAI_COMPATIBLE_MODEL') ||
      readEnvironment('OPENAI_MODEL');
    const fastModel = readEnvironment('OPENAI_COMPATIBLE_FAST_MODEL');
    const reasoningModel = readEnvironment('OPENAI_COMPATIBLE_REASONING_MODEL');
    candidates.push({
      provider: 'OPENAI_COMPATIBLE',
      modelName: complexTask
        ? reasoningModel || generalModel || 'gpt-4.1'
        : fastModel || generalModel || 'gpt-4o-mini',
      supportsDeepReasoning: Boolean(reasoningModel) ||
        (complexTask && /gpt-4\.1|reason|thinking|deep/i.test(generalModel)),
      costWeight: parseWeight(readEnvironment('OPENAI_COMPATIBLE_COST_WEIGHT'), 0.4),
      latencyWeight: parseWeight(readEnvironment('OPENAI_COMPATIBLE_LATENCY_WEIGHT'), 0.35),
    });
  }

  return candidates;
}

/** Selects a configured fast or reasoning model using task size, cost/latency weights, and quota health. */
export function selectOptimalCodingModel(
  taskType: string,
  estimatedPromptTokens: number,
): OptimalCodingModel {
  const safeTaskType = taskType.trim() || 'unspecified coding task';
  const safePromptTokens = Number.isFinite(estimatedPromptTokens)
    ? Math.max(0, Math.floor(estimatedPromptTokens))
    : 0;
  const complexTask = isComplexTask(safeTaskType, safePromptTokens);
  const configured = configuredCandidates(complexTask);
  const healthy = configured
    .map(candidate => ({ candidate, health: getQuotaHealth(candidate.provider) }))
    .filter(entry => entry.health !== 'EXHAUSTED');

  if (healthy.length === 0) {
    const reason = configured.length === 0
      ? 'No provider credentials and endpoint are configured; use deterministic offline mode.'
      : 'All configured providers are quota-exhausted; use deterministic offline mode until cooldown.';
    return {
      provider: 'OFFLINE_DETERMINISTIC',
      modelName: 'techyonx-kode-deterministic-v1',
      maxTokens: complexTask ? 8_192 : 2_048,
      temperature: 0,
      reason,
    };
  }

  const reasoningCandidates = complexTask
    ? healthy.filter(entry => entry.candidate.supportsDeepReasoning)
    : [];
  const pool = reasoningCandidates.length > 0 ? reasoningCandidates : healthy;
  const sorted = [...pool].sort((left, right) => {
    const leftHealthPenalty = left.health === 'DEGRADED' ? 0.5 : 0;
    const rightHealthPenalty = right.health === 'DEGRADED' ? 0.5 : 0;
    const leftCostRatio = complexTask ? 0.65 : 0.55;
    const leftScore =
      left.candidate.costWeight * leftCostRatio +
      left.candidate.latencyWeight * (1 - leftCostRatio) +
      leftHealthPenalty;
    const rightScore =
      right.candidate.costWeight * leftCostRatio +
      right.candidate.latencyWeight * (1 - leftCostRatio) +
      rightHealthPenalty;
    return leftScore - rightScore;
  });
  const selected = sorted[0];

  if (!selected) {
    return {
      provider: 'OFFLINE_DETERMINISTIC',
      modelName: 'techyonx-kode-deterministic-v1',
      maxTokens: complexTask ? 8_192 : 2_048,
      temperature: 0,
      reason: 'No eligible provider remains after quota and capability checks.'
    };
  }

  const maxTokens = parseTokenLimit(
    readEnvironment('AI_MAX_OUTPUT_TOKENS'),
    complexTask ? 8_192 : 2_048,
  );
  const healthReason = selected.health === 'DEGRADED' ? 'degraded quota health' : 'healthy quota';
  const taskReason = complexTask
    ? reasoningCandidates.length > 0
      ? 'deep-reasoning task'
      : 'complex task; no explicitly reasoning-capable model was configured'
    : 'latency-sensitive task';

  return {
    provider: selected.candidate.provider,
    modelName: selected.candidate.modelName,
    maxTokens,
    temperature: complexTask ? 0.2 : 0.1,
    reason: `${taskReason}; selected by configured cost/latency weights with ${healthReason}.`,
  };
}