import type { AIProviderType } from '../../types/codingEngine';
import {
  getActiveApiKey,
  rotateApiKeyOnQuotaLimit,
} from './apiKeyVaultManager';
import {
  reportProviderQuotaHealth,
  selectOptimalCodingModel,
  type ProviderQuotaHealth,
} from './smartModelSelector';

export interface UniversalAICallOptions {
  readonly temperature?: number;
  readonly maxOutputTokens?: number;
  readonly preferredModel?: string;
}

export interface UniversalAICallResult {
  readonly content: string;
  readonly provider: string;
  readonly modelUsed: string;
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly latencyMs: number;
}

export type UniversalModelAdapterErrorCode =
  | 'INVALID_INPUT'
  | 'INPUT_TOO_LARGE'
  | 'SERVER_ONLY'
  | 'PROVIDER_UNAVAILABLE'
  | 'PROVIDER_REQUEST_FAILED'
  | 'PROVIDER_RESPONSE_INVALID'
  | 'REQUEST_TIMEOUT';

export class UniversalModelAdapterError extends Error {
  readonly code: UniversalModelAdapterErrorCode;
  readonly statusCode?: number;

  constructor(
    code: UniversalModelAdapterErrorCode,
    message: string,
    statusCode?: number,
  ) {
    super(message);
    this.name = 'UniversalModelAdapterError';
    this.code = code;
    if (statusCode !== undefined) {
      this.statusCode = statusCode;
    }
  }
}

interface NormalizedProviderResponse {
  readonly content: string;
  readonly promptTokens: number;
  readonly completionTokens: number;
}

interface CallParameters {
  readonly model: string;
  readonly systemInstruction: string;
  readonly prompt: string;
  readonly temperature: number;
  readonly maxOutputTokens: number;
  readonly timeoutMs: number;
}

const MAX_PROMPT_CHARS = 512_000;
const MAX_SYSTEM_INSTRUCTION_CHARS = 64_000;
const MAX_MODEL_NAME_CHARS = 256;
const DEFAULT_TIMEOUT_MS = 90_000;
const MAX_TIMEOUT_MS = 180_000;

function readEnvironment(name: string): string {
  const runtime = globalThis as typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
  };
  return runtime.process?.env?.[name]?.trim() ?? '';
}

function assertServerRuntime(): void {
  if (Reflect.has(globalThis, 'window')) {
    throw new UniversalModelAdapterError(
      'SERVER_ONLY',
      'The universal model adapter can only be used in a server runtime.',
    );
  }
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function readNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? value
    : undefined;
}

function estimateTokens(value: string): number {
  return Math.max(1, Math.ceil(value.length / 4));
}

function readTokenCount(
  value: unknown,
  fallback: number,
): number {
  const parsed = readNumber(value);
  return parsed === undefined ? fallback : Math.floor(parsed);
}

function readGeminiContent(payload: unknown): string {
  const root = asRecord(payload);
  const candidates = root?.['candidates'];
  if (!Array.isArray(candidates)) {
    throw new UniversalModelAdapterError(
      'PROVIDER_RESPONSE_INVALID',
      'Gemini returned a response without candidates.',
    );
  }

  const candidate = asRecord(candidates[0]);
  const content = asRecord(candidate?.['content']);
  const parts = content?.['parts'];
  if (!Array.isArray(parts)) {
    throw new UniversalModelAdapterError(
      'PROVIDER_RESPONSE_INVALID',
      'Gemini returned no content parts.',
    );
  }

  const text = parts
    .map(part => asRecord(part)?.['text'])
    .filter((partText): partText is string => typeof partText === 'string')
    .join('');
  if (!text.trim()) {
    throw new UniversalModelAdapterError(
      'PROVIDER_RESPONSE_INVALID',
      'Gemini returned an empty text response.',
    );
  }
  return text;
}

function readOpenAIContent(payload: unknown): string {
  const root = asRecord(payload);
  const choices = root?.['choices'];
  const firstChoice = Array.isArray(choices) ? asRecord(choices[0]) : undefined;
  const message = asRecord(firstChoice?.['message']);
  const rawContent = message?.['content'];
  let text = '';

  if (typeof rawContent === 'string') {
    text = rawContent;
  } else if (Array.isArray(rawContent)) {
    text = rawContent
      .map(item => {
        const record = asRecord(item);
        return typeof record?.['text'] === 'string' ? record['text'] : '';
      })
      .join('');
  }

  if (!text.trim()) {
    throw new UniversalModelAdapterError(
      'PROVIDER_RESPONSE_INVALID',
      'The configured chat-completions endpoint returned no text content.',
    );
  }
  return text;
}

function readCustomContent(payload: unknown): string {
  const root = asRecord(payload);
  const content = root?.['content'] ?? root?.['generated_text'] ?? root?.['output_text'];
  if (typeof content !== 'string' || !content.trim()) {
    throw new UniversalModelAdapterError(
      'PROVIDER_RESPONSE_INVALID',
      'The custom model endpoint returned no text content.',
    );
  }
  return content;
}

function readUsage(
  payload: unknown,
  promptFallback: number,
  completionFallback: number,
): { promptTokens: number; completionTokens: number } {
  const root = asRecord(payload);
  const geminiUsage = asRecord(root?.['usageMetadata']);
  const providerUsage = asRecord(root?.['usage']);
  return {
    promptTokens: readTokenCount(
      geminiUsage?.['promptTokenCount'] ??
        providerUsage?.['prompt_tokens'] ??
        providerUsage?.['promptTokens'],
      promptFallback,
    ),
    completionTokens: readTokenCount(
      geminiUsage?.['candidatesTokenCount'] ??
        providerUsage?.['completion_tokens'] ??
        providerUsage?.['completionTokens'],
      completionFallback,
    ),
  };
}

function validateCallInputs(
  prompt: string,
  systemInstruction: string,
  options: UniversalAICallOptions | undefined,
): void {
  if (typeof prompt !== 'string' || prompt.trim().length === 0) {
    throw new UniversalModelAdapterError('INVALID_INPUT', 'Prompt must be a non-empty string.');
  }
  if (typeof systemInstruction !== 'string') {
    throw new UniversalModelAdapterError('INVALID_INPUT', 'System instruction must be a string.');
  }
  if (prompt.length > MAX_PROMPT_CHARS || systemInstruction.length > MAX_SYSTEM_INSTRUCTION_CHARS) {
    throw new UniversalModelAdapterError('INPUT_TOO_LARGE', 'Prompt or system instruction exceeds the configured size limit.');
  }
  if (options?.temperature !== undefined &&
    (!Number.isFinite(options.temperature) || options.temperature < 0 || options.temperature > 2)) {
    throw new UniversalModelAdapterError('INVALID_INPUT', 'Temperature must be a finite number between 0 and 2.');
  }
  if (options?.maxOutputTokens !== undefined &&
    (!Number.isSafeInteger(options.maxOutputTokens) || options.maxOutputTokens < 1 || options.maxOutputTokens > 32_768)) {
    throw new UniversalModelAdapterError('INVALID_INPUT', 'maxOutputTokens must be an integer between 1 and 32768.');
  }
  if (options?.preferredModel !== undefined &&
    (options.preferredModel.trim().length === 0 || options.preferredModel.length > MAX_MODEL_NAME_CHARS || /[\u0000-\u001f\u007f]/.test(options.preferredModel))) {
    throw new UniversalModelAdapterError('INVALID_INPUT', 'preferredModel must be a non-empty model identifier without control characters.');
  }
}

function makeOfflineResponse(prompt: string): string {
  const fencedCode = prompt.match(/```(?:[a-zA-Z0-9_+.-]+)?\s*([\s\S]*?)```/);
  if (fencedCode?.[1]?.trim()) {
    return fencedCode[1].trim();
  }

  const request = prompt.trim();
  return [
    `export const offlineGeneratedTask = ${JSON.stringify(request)};`,
    '',
    'export function describeOfflineGeneratedTask(): string {',
    '  return offlineGeneratedTask;',
    '}',
  ].join('\n');
}

function localResult(
  prompt: string,
  modelUsed: string,
  startedAt: number,
): UniversalAICallResult {
  const content = makeOfflineResponse(prompt);
  return {
    content,
    provider: 'OFFLINE_DETERMINISTIC',
    modelUsed,
    promptTokens: estimateTokens(prompt),
    completionTokens: estimateTokens(content),
    latencyMs: Math.max(0, Date.now() - startedAt),
  };
}

function resolveConfiguredEndpoint(baseUrl: string, route: 'OPENAI' | 'CUSTOM'): string {
  let endpoint: URL;
  try {
    endpoint = new URL(baseUrl);
  } catch {
    throw new UniversalModelAdapterError('PROVIDER_UNAVAILABLE', 'The configured API base URL is invalid.');
  }

  const isLocalHttp =
    endpoint.protocol === 'http:' &&
    (endpoint.hostname === 'localhost' || endpoint.hostname === '127.0.0.1' || endpoint.hostname === '[::1]') &&
    readEnvironment('NODE_ENV') !== 'production';
  if (endpoint.protocol !== 'https:' && !isLocalHttp) {
    throw new UniversalModelAdapterError('PROVIDER_UNAVAILABLE', 'Compatible API endpoints must use HTTPS; HTTP is allowed only for localhost outside production.');
  }
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new UniversalModelAdapterError('PROVIDER_UNAVAILABLE', 'The compatible API base URL cannot contain credentials, a query, or a fragment.');
  }

  const normalizedPath = endpoint.pathname.replace(/\/+$/, '');
  if (route === 'OPENAI' && !normalizedPath.endsWith('/chat/completions')) {
    endpoint.pathname = normalizedPath.endsWith('/v1')
      ? `${normalizedPath}/chat/completions`
      : `${normalizedPath}/v1/chat/completions`;
  } else if (route === 'CUSTOM' && !normalizedPath.endsWith('/v1/generate')) {
    endpoint.pathname = normalizedPath.endsWith('/v1')
      ? `${normalizedPath}/generate`
      : `${normalizedPath}/v1/generate`;
  }
  return endpoint.toString();
}

function isOpenAICompatibleProtocol(provider: AIProviderType): boolean {
  return provider === 'OPENAI_COMPATIBLE' ||
    (provider === 'TECHYONX_KODE_CUSTOM_API' &&
      readEnvironment('CUSTOM_API_PROTOCOL').toUpperCase() === 'OPENAI_COMPATIBLE');
}

function providerKey(provider: AIProviderType): string {
  switch (provider) {
    case 'GEMINI_API':
      return getActiveApiKey('GEMINI') ?? '';
    case 'TECHYONX_KODE_CUSTOM_API':
      return getActiveApiKey('CUSTOM') ?? '';
    case 'OPENAI_COMPATIBLE':
      return readEnvironment('OPENAI_COMPATIBLE_API_KEY') || readEnvironment('OPENAI_API_KEY');
    case 'OFFLINE_DETERMINISTIC':
      return '';
  }
}

function providerEndpoint(provider: AIProviderType, model: string): string {
  switch (provider) {
    case 'GEMINI_API': {
      const encodedModel = encodeURIComponent(model);
      return `https://generativelanguage.googleapis.com/v1beta/models/${encodedModel}:generateContent`;
    }
    case 'TECHYONX_KODE_CUSTOM_API':
      return resolveConfiguredEndpoint(
        readEnvironment('CUSTOM_API_BASE_URL'),
        isOpenAICompatibleProtocol(provider) ? 'OPENAI' : 'CUSTOM',
      );
    case 'OPENAI_COMPATIBLE': {
      const baseUrl =
        readEnvironment('OPENAI_COMPATIBLE_BASE_URL') ||
        readEnvironment('OPENAI_BASE_URL') ||
        'https://api.openai.com/v1';
      return resolveConfiguredEndpoint(baseUrl, 'OPENAI');
    }
    case 'OFFLINE_DETERMINISTIC':
      throw new UniversalModelAdapterError('PROVIDER_UNAVAILABLE', 'Offline mode does not have a remote endpoint.');
  }
}

function isProvider(value: string): value is AIProviderType {
  return value === 'GEMINI_API' ||
    value === 'TECHYONX_KODE_CUSTOM_API' ||
    value === 'OPENAI_COMPATIBLE' ||
    value === 'OFFLINE_DETERMINISTIC';
}

function responsePayloadToResult(
  provider: AIProviderType,
  payload: unknown,
  prompt: string,
  systemInstruction: string,
): NormalizedProviderResponse {
  const combinedPrompt = `${systemInstruction}\n${prompt}`;
  const content = provider === 'GEMINI_API'
    ? readGeminiContent(payload)
    : provider === 'TECHYONX_KODE_CUSTOM_API' && !isOpenAICompatibleProtocol(provider)
      ? readCustomContent(payload)
      : readOpenAIContent(payload);
  const usage = readUsage(
    payload,
    estimateTokens(combinedPrompt),
    estimateTokens(content),
  );
  return { content, ...usage };
}

function readRetryAfterMs(response: Response): number {
  const retryAfter = response.headers.get('retry-after');
  if (!retryAfter) {
    return 60_000;
  }
  const seconds = Number(retryAfter);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(seconds * 1000, 3_600_000);
  }
  const dateMs = Date.parse(retryAfter);
  return Number.isFinite(dateMs)
    ? Math.max(0, Math.min(dateMs - Date.now(), 3_600_000))
    : 60_000;
}

async function requestProvider(
  provider: AIProviderType,
  parameters: CallParameters,
  apiKeyOverride?: string,
  attemptedKeys: ReadonlySet<string> = new Set(),
): Promise<{ response: Response; payload: unknown }> {
  const apiKey = apiKeyOverride ?? providerKey(provider);
  if (!apiKey) {
    throw new UniversalModelAdapterError('PROVIDER_UNAVAILABLE', `No credential is configured for ${provider}.`);
  }
  const currentAttemptedKeys = new Set(attemptedKeys);
  currentAttemptedKeys.add(apiKey);

  const endpoint = providerEndpoint(provider, parameters.model);
  const isGemini = provider === 'GEMINI_API';
  const openAICompatible = isOpenAICompatibleProtocol(provider);
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (isGemini) {
    headers['x-goog-api-key'] = apiKey;
  } else {
    headers['authorization'] = `Bearer ${apiKey}`;
  }

  const body = isGemini
    ? {
        ...(parameters.systemInstruction
          ? { systemInstruction: { parts: [{ text: parameters.systemInstruction }] } }
          : {}),
        contents: [{ role: 'user', parts: [{ text: parameters.prompt }] }],
        generationConfig: {
          temperature: parameters.temperature,
          maxOutputTokens: parameters.maxOutputTokens,
        },
      }
    : openAICompatible
      ? {
        model: parameters.model,
        messages: [
          ...(parameters.systemInstruction
            ? [{ role: 'system', content: parameters.systemInstruction }]
            : []),
          { role: 'user', content: parameters.prompt },
        ],
        temperature: parameters.temperature,
        max_tokens: parameters.maxOutputTokens,
        stream: false,
      }
      : {
        model: parameters.model,
        system_instruction: parameters.systemInstruction,
        prompt: parameters.prompt,
        temperature: parameters.temperature,
        max_output_tokens: parameters.maxOutputTokens,
      };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), parameters.timeoutMs);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: 'error',
    });
    if (!response.ok) {
      if (response.status === 429) {
        reportProviderQuotaHealth(provider, 'EXHAUSTED', readRetryAfterMs(response));
        if (provider === 'GEMINI_API' || provider === 'TECHYONX_KODE_CUSTOM_API') {
          const replacementKey = rotateApiKeyOnQuotaLimit(
            provider === 'GEMINI_API' ? 'GEMINI' : 'CUSTOM',
          );
          if (replacementKey && !currentAttemptedKeys.has(replacementKey)) {
            return requestProvider(provider, parameters, replacementKey, currentAttemptedKeys);
          }
        }
      } else if (response.status >= 500) {
        reportProviderQuotaHealth(provider, 'DEGRADED');
      }
      throw new UniversalModelAdapterError(
        'PROVIDER_REQUEST_FAILED',
        `Provider request failed with HTTP ${response.status}.`,
        response.status,
      );
    }

    let payload: unknown;
    try {
      payload = await response.json() as unknown;
    } catch {
      throw new UniversalModelAdapterError(
        'PROVIDER_RESPONSE_INVALID',
        'Provider returned a response that was not valid JSON.',
        response.status,
      );
    }
    return { response, payload };
  } catch (error: unknown) {
    if (error instanceof UniversalModelAdapterError) {
      throw error;
    }
    if (controller.signal.aborted) {
      reportProviderQuotaHealth(provider, 'DEGRADED');
      throw new UniversalModelAdapterError('REQUEST_TIMEOUT', 'Provider request exceeded its timeout.');
    }
    reportProviderQuotaHealth(provider, 'DEGRADED');
    throw new UniversalModelAdapterError('PROVIDER_REQUEST_FAILED', 'Provider request could not be completed.');
  } finally {
    clearTimeout(timeout);
  }
}

/** Executes one server-side model request and normalizes provider output and usage. */
export async function executeUniversalAICall(
  prompt: string,
  systemInstruction: string,
  options?: {
    temperature?: number;
    maxOutputTokens?: number;
    preferredModel?: string;
  },
): Promise<UniversalAICallResult> {
  assertServerRuntime();
  validateCallInputs(prompt, systemInstruction, options);

  const startedAt = Date.now();
  const taskDescription = `${systemInstruction}\n${prompt}`;
  const estimatedPromptTokens = estimateTokens(taskDescription);
  const selection = selectOptimalCodingModel(taskDescription, estimatedPromptTokens);
  const model = options?.preferredModel?.trim() || selection.modelName;
  const temperature = options?.temperature ?? selection.temperature;
  const maxOutputTokens = options?.maxOutputTokens ?? selection.maxTokens;

  if (!isProvider(selection.provider)) {
    throw new UniversalModelAdapterError('PROVIDER_UNAVAILABLE', 'Model selector returned an unsupported provider.');
  }
  if (selection.provider === 'OFFLINE_DETERMINISTIC') {
    return localResult(prompt, model, startedAt);
  }

  const timeoutMsValue = Number(readEnvironment('AI_REQUEST_TIMEOUT_MS'));
  const timeoutMs = Number.isSafeInteger(timeoutMsValue) && timeoutMsValue > 0
    ? Math.min(timeoutMsValue, MAX_TIMEOUT_MS)
    : DEFAULT_TIMEOUT_MS;
  const parameters: CallParameters = {
    model,
    systemInstruction,
    prompt,
    temperature,
    maxOutputTokens,
    timeoutMs,
  };

  try {
    const { payload } = await requestProvider(selection.provider, parameters);
    const normalized = responsePayloadToResult(
      selection.provider,
      payload,
      prompt,
      systemInstruction,
    );
    reportProviderQuotaHealth(selection.provider, 'HEALTHY');
    return {
      content: normalized.content,
      provider: selection.provider,
      modelUsed: model,
      promptTokens: normalized.promptTokens,
      completionTokens: normalized.completionTokens,
      latencyMs: Math.max(0, Date.now() - startedAt),
    };
  } catch (error: unknown) {
    if (error instanceof UniversalModelAdapterError) {
      throw error;
    }
    throw new UniversalModelAdapterError('PROVIDER_RESPONSE_INVALID', 'Provider response could not be normalized.');
  }
}