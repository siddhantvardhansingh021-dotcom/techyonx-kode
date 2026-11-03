export interface SecretScrubInputFile {
  readonly path: string;
  readonly content: string;
}

export interface SecretScrubbedFile {
  readonly path: string;
  readonly content: string;
}

interface SecretPattern {
  readonly name: string;
  readonly expression: RegExp;
}

const MAX_FILE_COUNT = 20_000;
const MAX_TOTAL_SOURCE_CHARS = 16_000_000;

const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    name: 'PRIVATE_RSA_KEY',
    expression: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
  },
  {
    name: 'DATABASE_URL',
    expression: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss):\/\/[^\s:/@]+:[^\s/@]+@[^\s"'`<>]+/gi,
  },
  {
    name: 'GEMINI_API_KEY',
    expression: /\bAIza[0-9A-Za-z_-]{30,}\b/g,
  },
  {
    name: 'AWS_ACCESS_KEY_ID',
    expression: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    name: 'GITHUB_TOKEN',
    expression: /\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
  },
  {
    name: 'STRIPE_SECRET_KEY',
    expression: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  },
  {
    name: 'JWT_TOKEN',
    expression: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
];

const ASSIGNMENT_PATTERNS: readonly SecretPattern[] = [
  {
    name: 'AWS_SECRET_ACCESS_KEY',
    expression: /(\b(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\b\s*[:=]\s*)(['"]?)([A-Za-z0-9/+=]{32,64})\2/g,
  },
  {
    name: 'JWT_SECRET',
    expression: /(\b(?:JWT_SECRET|JWT_SIGNING_KEY|JWT_PRIVATE_SECRET)\b\s*[:=]\s*)(['"`])([^\r\n'"`]{8,})\2/g,
  },
];

const ENV_TEMPLATE = [
  '# Copy this file to .env.local and set credentials there.',
  '# Never commit populated credential values.',
  'GEMINI_API_KEY=',
  'GEMINI_API_KEYS_POOL=',
  'AWS_ACCESS_KEY_ID=',
  'AWS_SECRET_ACCESS_KEY=',
  'GITHUB_TOKEN=',
  'STRIPE_SECRET_KEY=',
  'JWT_SECRET=',
  'JWT_TOKEN=',
  'PRIVATE_RSA_KEY=',
  'DATABASE_URL=',
].join('\n');

function replaceStandaloneSecret(
  content: string,
  pattern: SecretPattern,
): { content: string; count: number } {
  const expression = new RegExp(pattern.expression.source, pattern.expression.flags);
  const matches = [...content.matchAll(expression)];
  let scrubbed = content;
  for (const match of matches.reverse()) {
    if (match.index === undefined || !match[0]) {
      continue;
    }
    let start = match.index;
    let end = match.index + match[0].length;
    const openingQuote = scrubbed[start - 1];
    const closingQuote = scrubbed[end];
    if (
      (openingQuote === '"' || openingQuote === "'" || openingQuote === '`') &&
      closingQuote === openingQuote
    ) {
      start -= 1;
      end += 1;
    }
    scrubbed = `${scrubbed.slice(0, start)}process.env.${pattern.name}${scrubbed.slice(end)}`;
  }
  return { content: scrubbed, count: matches.length };
}

function replaceAssignedSecret(
  content: string,
  pattern: SecretPattern,
): { content: string; count: number } {
  let count = 0;
  const expression = new RegExp(pattern.expression.source, pattern.expression.flags);
  const scrubbed = content.replace(expression, (_matched, prefix: string) => {
    count += 1;
    return `${prefix}process.env.${pattern.name}`;
  });
  return { content: scrubbed, count };
}

/** Scrubs recognized hardcoded credentials and returns a safe environment template. */
export function scrubHardcodedSecrets(files: Array<{ path: string; content: string }>): {
  scrubbedFiles: Array<{ path: string; content: string }>;
  secretsPreventedCount: number;
  envTemplateGenerated: string;
} {
  if (!Array.isArray(files) || files.length > MAX_FILE_COUNT) {
    throw new RangeError(`Secret scanning accepts at most ${MAX_FILE_COUNT} files.`);
  }

  let totalSourceChars = 0;
  for (const file of files) {
    if (typeof file?.path !== 'string' || typeof file.content !== 'string') {
      throw new TypeError('Every secret-scan input must have a string path and content.');
    }
    totalSourceChars += file.content.length;
    if (totalSourceChars > MAX_TOTAL_SOURCE_CHARS) {
      throw new RangeError(`Secret scanning exceeds the ${MAX_TOTAL_SOURCE_CHARS}-character source limit.`);
    }
  }

  let secretsPreventedCount = 0;
  const scrubbedFiles = files.map(file => {
    let content = file.content;
    for (const pattern of SECRET_PATTERNS) {
      const result = replaceStandaloneSecret(content, pattern);
      content = result.content;
      secretsPreventedCount += result.count;
    }
    for (const pattern of ASSIGNMENT_PATTERNS) {
      const result = replaceAssignedSecret(content, pattern);
      content = result.content;
      secretsPreventedCount += result.count;
    }
    return { path: file.path, content };
  });

  return {
    scrubbedFiles,
    secretsPreventedCount,
    envTemplateGenerated: ENV_TEMPLATE,
  };
}