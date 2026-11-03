import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export interface CodeBundleFile {
  readonly path: string;
  readonly content: string;
}

export interface SignedCodeBundle {
  readonly bundleHash: string;
  readonly signature: string;
  readonly timestamp: string;
}

export interface CodeBundleSignatureEnvelope {
  readonly bundleHash: string;
  readonly signature: string;
  readonly timestamp: string;
}

const MAX_FILE_COUNT = 20_000;
const MAX_TOTAL_CONTENT_BYTES = 32 * 1024 * 1024;
const SIGNATURE_PREFIX = 'hmac-sha256:v1:';
const LEAF_DOMAIN = Buffer.from([0x00]);
const NODE_DOMAIN = Buffer.from([0x01]);
const EMPTY_TREE_DOMAIN = Buffer.from([0x02]);

function readEnvironment(name: string): string {
  const runtime = globalThis as typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
  };
  return runtime.process?.env?.[name]?.trim() ?? '';
}

function readSigningKey(): Buffer {
  const configuredKey = readEnvironment('TECHYONX_CODE_SIGNING_KEY');
  const key = Buffer.from(configuredKey, 'utf8');
  if (key.length < 32) {
    key.fill(0);
    throw new Error('Code bundle signing is unavailable: configure TECHYONX_CODE_SIGNING_KEY with at least 32 bytes.');
  }
  return key;
}

function normalizeAndValidateFiles(files: readonly CodeBundleFile[]): Array<{ path: string; content: string }> {
  if (!Array.isArray(files) || files.length > MAX_FILE_COUNT) {
    throw new RangeError(`Code bundle signing accepts at most ${MAX_FILE_COUNT} files.`);
  }

  let totalBytes = 0;
  const paths = new Set<string>();
  const normalized = files.map(file => {
    if (typeof file?.path !== 'string' || typeof file.content !== 'string') {
      throw new TypeError('Every bundle file must have a string path and content.');
    }
    const path = file.path.normalize('NFC');
    if (
      path.length === 0 ||
      path.length > 4_096 ||
      path.startsWith('/') ||
      path.includes('\\') ||
      path.includes('\0') ||
      path.startsWith('//') ||
      /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(path) ||
      path.split('/').some(segment => segment === '..' || segment === '.' || segment.length === 0)
    ) {
      throw new Error('Code bundle contains an unsafe or non-relative file path.');
    }
    if (paths.has(path)) {
      throw new Error('Code bundle contains duplicate paths after Unicode normalization.');
    }
    paths.add(path);
    totalBytes += Buffer.byteLength(file.content, 'utf8');
    if (totalBytes > MAX_TOTAL_CONTENT_BYTES) {
      throw new RangeError(`Code bundle exceeds the ${MAX_TOTAL_CONTENT_BYTES}-byte content limit.`);
    }
    return { path, content: file.content };
  });

  return normalized.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
}

function hashLeaf(path: string, content: string): Buffer {
  const pathBytes = Buffer.from(path, 'utf8');
  const contentHash = createHash('sha256').update(content, 'utf8').digest();
  const pathLength = Buffer.allocUnsafe(4);
  pathLength.writeUInt32BE(pathBytes.length, 0);
  return createHash('sha256')
    .update(LEAF_DOMAIN)
    .update(pathLength)
    .update(pathBytes)
    .update(contentHash)
    .digest();
}

function merkleRoot(files: readonly { path: string; content: string }[]): Buffer {
  if (files.length === 0) {
    return createHash('sha256').update(EMPTY_TREE_DOMAIN).digest();
  }

  let level = files.map(file => hashLeaf(file.path, file.content));
  while (level.length > 1) {
    const nextLevel: Buffer[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] ?? left;
      if (!left || !right) {
        throw new Error('Unable to build the code bundle Merkle tree.');
      }
      nextLevel.push(
        createHash('sha256')
          .update(NODE_DOMAIN)
          .update(left)
          .update(right)
          .digest(),
      );
    }
    level = nextLevel;
  }
  const root = level[0];
  if (!root) {
    throw new Error('Unable to build the code bundle Merkle root.');
  }
  return root;
}

function signatureMessage(bundleHash: string, timestamp: string): Buffer {
  return Buffer.from(`techyonx.kode.code-bundle.v1\0${timestamp}\0${bundleHash}`, 'utf8');
}

function signHash(bundleHash: string, timestamp: string, key: Buffer): string {
  return `${SIGNATURE_PREFIX}${createHmac('sha256', key)
    .update(signatureMessage(bundleHash, timestamp))
    .digest('hex')}`;
}

/** Computes the canonical SHA-256 Merkle root for a bundle without requiring a signing key. */
export function computeGeneratedCodeBundleHash(
  files: Array<{ path: string; content: string }>,
): string {
  return merkleRoot(normalizeAndValidateFiles(files)).toString('hex');
}

/** Signs the canonical Merkle root of a file bundle with the configured server-side HMAC key. */
export function signGeneratedCodeBundle(files: Array<{ path: string; content: string }>): {
  bundleHash: string;
  signature: string;
  timestamp: string;
} {
  const normalizedFiles = normalizeAndValidateFiles(files);
  const key = readSigningKey();
  const timestamp = new Date().toISOString();
  try {
    const bundleHash = merkleRoot(normalizedFiles).toString('hex');
    const signature = signHash(bundleHash, timestamp, key);
    return { bundleHash, signature, timestamp };
  } finally {
    key.fill(0);
  }
}

/** Verifies both the canonical bundle hash and its HMAC signature in constant time. */
export function verifyGeneratedCodeBundle(
  files: Array<{ path: string; content: string }>,
  envelope: CodeBundleSignatureEnvelope,
): boolean {
  if (
    typeof envelope?.bundleHash !== 'string' ||
    !/^[a-f0-9]{64}$/.test(envelope.bundleHash) ||
    typeof envelope.timestamp !== 'string' ||
    !Number.isFinite(Date.parse(envelope.timestamp)) ||
    typeof envelope.signature !== 'string' ||
    !envelope.signature.startsWith(SIGNATURE_PREFIX)
  ) {
    return false;
  }

  let normalizedFiles: Array<{ path: string; content: string }>;
  try {
    normalizedFiles = normalizeAndValidateFiles(files);
  } catch {
    return false;
  }

  const computedHash = merkleRoot(normalizedFiles).toString('hex');
  const expectedHash = Buffer.from(envelope.bundleHash, 'hex');
  const actualHash = Buffer.from(computedHash, 'hex');
  if (expectedHash.length !== actualHash.length || !timingSafeEqual(expectedHash, actualHash)) {
    return false;
  }

  const key = readSigningKey();
  try {
    const expectedSignature = Buffer.from(signHash(computedHash, envelope.timestamp, key), 'utf8');
    const actualSignature = Buffer.from(envelope.signature, 'utf8');
    return expectedSignature.length === actualSignature.length &&
      timingSafeEqual(expectedSignature, actualSignature);
  } finally {
    key.fill(0);
  }
}