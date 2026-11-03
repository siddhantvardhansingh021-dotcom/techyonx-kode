import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';

export type ApiKeyProvider = 'GEMINI' | 'CUSTOM' | 'GITHUB';
type RotatableApiKeyProvider = 'GEMINI' | 'CUSTOM';

interface EncryptedKeyEntry {
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly authenticationTagHex: string;
}

interface ProviderKeyPool {
  readonly entries: readonly EncryptedKeyEntry[];
  activeIndex: number;
}

const AES_GCM_NONCE_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const inMemoryKeyMaterial = randomBytes(32);
const VAULT_ENCRYPTION_KEY = createHash('sha256').update(inMemoryKeyMaterial).digest();
inMemoryKeyMaterial.fill(0);

const keyPools = new Map<ApiKeyProvider, ProviderKeyPool>();
let vaultInitialized = false;

function readEnvironment(name: string): string {
  const runtime = globalThis as typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
  };
  return runtime.process?.env?.[name]?.trim() ?? '';
}

function assertServerRuntime(): void {
  if (Reflect.has(globalThis, 'window')) {
    throw new Error('API key vault operations are available only in a server runtime.');
  }
}

function readPool(poolName: string, singleKeyName: string): string[] {
  const pooledKeys = readEnvironment(poolName)
    .split(',')
    .map(key => key.trim())
    .filter(Boolean);
  const singleKey = readEnvironment(singleKeyName);
  if (singleKey) {
    pooledKeys.push(singleKey);
  }
  return [...new Set(pooledKeys)];
}

function encryptKey(rawKey: string): EncryptedKeyEntry {
  const plaintext = Buffer.from(rawKey, 'utf8');
  const nonce = randomBytes(AES_GCM_NONCE_BYTES);
  try {
    const cipher = createCipheriv('aes-256-gcm', VAULT_ENCRYPTION_KEY, nonce, {
      authTagLength: AES_GCM_TAG_BYTES,
    });
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authenticationTag = cipher.getAuthTag();
    return {
      nonceHex: nonce.toString('hex'),
      ciphertextHex: ciphertext.toString('hex'),
      authenticationTagHex: authenticationTag.toString('hex'),
    };
  } finally {
    plaintext.fill(0);
    nonce.fill(0);
  }
}

function decryptKey(entry: EncryptedKeyEntry): string {
  const nonce = Buffer.from(entry.nonceHex, 'hex');
  const ciphertext = Buffer.from(entry.ciphertextHex, 'hex');
  const authenticationTag = Buffer.from(entry.authenticationTagHex, 'hex');
  let plaintext: Buffer | undefined;

  try {
    if (
      nonce.length !== AES_GCM_NONCE_BYTES ||
      authenticationTag.length !== AES_GCM_TAG_BYTES ||
      ciphertext.length === 0
    ) {
      throw new Error('Invalid encrypted entry.');
    }
    const decipher = createDecipheriv('aes-256-gcm', VAULT_ENCRYPTION_KEY, nonce, {
      authTagLength: AES_GCM_TAG_BYTES,
    });
    decipher.setAuthTag(authenticationTag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString('utf8');
  } catch {
    throw new Error('The in-memory API key entry could not be decrypted.');
  } finally {
    nonce.fill(0);
    ciphertext.fill(0);
    authenticationTag.fill(0);
    plaintext?.fill(0);
  }
}

function initializeVault(): void {
  if (vaultInitialized) {
    return;
  }

  const definitions: readonly [ApiKeyProvider, readonly string[]][] = [
    ['GEMINI', readPool('GEMINI_API_KEYS_POOL', 'GEMINI_API_KEY')],
    ['CUSTOM', readPool('CUSTOM_API_KEYS_POOL', 'CUSTOM_API_KEY')],
    ['GITHUB', [readEnvironment('GITHUB_TOKEN')].filter(Boolean)],
  ];

  for (const [provider, rawKeys] of definitions) {
    if (rawKeys.length > 0) {
      keyPools.set(provider, {
        entries: rawKeys.map(encryptKey),
        activeIndex: 0,
      });
    }
  }
  vaultInitialized = true;
}

function getProviderEntry(provider: ApiKeyProvider): EncryptedKeyEntry | undefined {
  initializeVault();
  const pool = keyPools.get(provider);
  if (!pool || pool.entries.length === 0) {
    return undefined;
  }
  return pool.entries[pool.activeIndex];
}

/** Returns the active secret for trusted server-side provider code, never for client use. */
export function getActiveApiKey(provider: ApiKeyProvider): string | null {
  assertServerRuntime();
  const entry = getProviderEntry(provider);
  return entry ? decryptKey(entry) : null;
}

/** Advances to the next configured key after quota exhaustion, returning null if no alternate exists. */
export function rotateApiKeyOnQuotaLimit(provider: RotatableApiKeyProvider): string | null {
  assertServerRuntime();
  initializeVault();
  const pool = keyPools.get(provider);
  if (!pool || pool.entries.length < 2) {
    return null;
  }
  pool.activeIndex = (pool.activeIndex + 1) % pool.entries.length;
  const entry = pool.entries[pool.activeIndex];
  return entry ? decryptKey(entry) : null;
}

/** Masks a credential while preserving at most its final four characters. */
export function maskSensitiveKey(raw: string): string {
  if (raw.length === 0) {
    return '';
  }
  if (raw.length <= 4) {
    return '*'.repeat(raw.length);
  }
  return `${'*'.repeat(Math.min(raw.length - 4, 16))}${raw.slice(-4)}`;
}