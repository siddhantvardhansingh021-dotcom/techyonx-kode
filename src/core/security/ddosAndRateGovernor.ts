export interface CodingRateLimitDecision {
  readonly allowed: boolean;
  readonly remainingRequests: number;
  readonly resetInMs: number;
}

interface ClientRateState {
  windowStartMs: number;
  previousWindowCount: number;
  currentWindowCount: number;
  tokens: number;
  lastRefillMs: number;
  lastSeenMs: number;
}

interface RateConfiguration {
  readonly windowMs: number;
  readonly maxRequests: number;
  readonly bucketCapacity: number;
  readonly refillTokensPerMs: number;
  readonly maxClients: number;
}

const DEFAULT_WINDOW_MS = 60_000;
const DEFAULT_MAX_REQUESTS = 60;
const DEFAULT_BUCKET_CAPACITY = 30;
const DEFAULT_REFILL_PER_SECOND = 1;
const DEFAULT_MAX_CLIENTS = 50_000;
const MAX_CLIENT_ID_LENGTH = 1_024;
const clientStates = new Map<string, ClientRateState>();

function readEnvironment(name: string): string {
  const runtime = globalThis as typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
  };
  return runtime.process?.env?.[name]?.trim() ?? '';
}

function integerSetting(name: string, fallback: number, minimum: number, maximum: number): number {
  const parsed = Number(readEnvironment(name));
  return Number.isSafeInteger(parsed) && parsed >= minimum
    ? Math.min(parsed, maximum)
    : fallback;
}

function configuration(): RateConfiguration {
  const windowMs = integerSetting('CODING_RATE_WINDOW_MS', DEFAULT_WINDOW_MS, 100, 3_600_000);
  const maxRequests = integerSetting('CODING_RATE_MAX_REQUESTS', DEFAULT_MAX_REQUESTS, 1, 1_000_000);
  const bucketCapacity = integerSetting('CODING_RATE_BUCKET_CAPACITY', DEFAULT_BUCKET_CAPACITY, 1, 1_000_000);
  const refillPerSecond = integerSetting('CODING_RATE_REFILL_PER_SECOND', DEFAULT_REFILL_PER_SECOND, 1, 100_000);
  const maxClients = integerSetting('CODING_RATE_MAX_CLIENTS', DEFAULT_MAX_CLIENTS, 100, 1_000_000);
  return {
    windowMs,
    maxRequests,
    bucketCapacity,
    refillTokensPerMs: refillPerSecond / 1_000,
    maxClients,
  };
}

function evictLeastRecentlyUsedIfNeeded(maxClients: number): void {
  if (clientStates.size < maxClients) {
    return;
  }
  const oldestClient = clientStates.keys().next();
  if (!oldestClient.done && oldestClient.value !== undefined) {
    clientStates.delete(oldestClient.value);
  }
}

function createState(now: number, config: RateConfiguration): ClientRateState {
  return {
    windowStartMs: Math.floor(now / config.windowMs) * config.windowMs,
    previousWindowCount: 0,
    currentWindowCount: 0,
    tokens: config.bucketCapacity,
    lastRefillMs: now,
    lastSeenMs: now,
  };
}

function advanceWindow(state: ClientRateState, now: number, windowMs: number): void {
  if (now < state.windowStartMs) {
    state.windowStartMs = Math.floor(now / windowMs) * windowMs;
    state.previousWindowCount = 0;
    state.currentWindowCount = 0;
    return;
  }

  const elapsedWindows = Math.floor((now - state.windowStartMs) / windowMs);
  if (elapsedWindows <= 0) {
    return;
  }
  state.previousWindowCount = elapsedWindows === 1 ? state.currentWindowCount : 0;
  state.currentWindowCount = 0;
  state.windowStartMs += elapsedWindows * windowMs;
}

function refillBucket(state: ClientRateState, now: number, config: RateConfiguration): void {
  const elapsedMs = Math.max(0, now - state.lastRefillMs);
  state.tokens = Math.min(
    config.bucketCapacity,
    state.tokens + elapsedMs * config.refillTokensPerMs,
  );
  state.lastRefillMs = Math.max(state.lastRefillMs, now);
}

function weightedWindowCount(state: ClientRateState, now: number, windowMs: number): number {
  const elapsedInWindow = Math.max(0, Math.min(windowMs, now - state.windowStartMs));
  const previousWeight = 1 - elapsedInWindow / windowMs;
  return state.currentWindowCount + state.previousWindowCount * previousWeight;
}

function deniedResetMs(
  state: ClientRateState,
  now: number,
  weightedCount: number,
  config: RateConfiguration,
): number {
  const tokenWait = state.tokens >= 1
    ? 0
    : Math.ceil((1 - state.tokens) / config.refillTokensPerMs);
  const slidingWindowWait = weightedCount < config.maxRequests
    ? 0
    : Math.max(1, state.windowStartMs + config.windowMs - now);
  return Math.max(tokenWait, slidingWindowWait, 1);
}

/** Enforces both an O(1) weighted sliding-window limit and a token bucket per client key. */
export function checkCodingRateLimit(clientId: string): {
  allowed: boolean;
  remainingRequests: number;
  resetInMs: number;
} {
  const now = Date.now();
  const config = configuration();
  if (typeof clientId !== 'string' || clientId.trim().length === 0 || clientId.length > MAX_CLIENT_ID_LENGTH) {
    return { allowed: false, remainingRequests: 0, resetInMs: config.windowMs };
  }

  let state = clientStates.get(clientId);
  if (!state) {
    evictLeastRecentlyUsedIfNeeded(config.maxClients);
    state = createState(now, config);
  }
  advanceWindow(state, now, config.windowMs);
  refillBucket(state, now, config);

  const weightedCount = weightedWindowCount(state, now, config.windowMs);
  const allowed = weightedCount < config.maxRequests && state.tokens >= 1;
  if (allowed) {
    state.currentWindowCount += 1;
    state.tokens -= 1;
  }

  state.lastSeenMs = now;
  clientStates.delete(clientId);
  clientStates.set(clientId, state);

  const remainingWindowRequests = Math.max(
    0,
    Math.floor(config.maxRequests - weightedWindowCount(state, now, config.windowMs)),
  );
  const remainingBucketTokens = Math.max(0, Math.floor(state.tokens));
  const remainingRequests = Math.min(remainingWindowRequests, remainingBucketTokens);

  return {
    allowed,
    remainingRequests,
    resetInMs: allowed
      ? remainingRequests > 0
        ? 0
        : deniedResetMs(state, now, weightedWindowCount(state, now, config.windowMs), config)
      : deniedResetMs(state, now, weightedCount, config),
  };
}