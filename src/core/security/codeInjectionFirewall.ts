export type CodingPromptThreatLevel = 'NONE' | 'LOW' | 'HIGH' | 'CRITICAL';

export interface CodingPromptSecurityInspection {
  readonly allowed: boolean;
  readonly threatLevel: CodingPromptThreatLevel;
  readonly blockedReason?: string;
  readonly sanitizedPrompt: string;
}

interface PromptFinding {
  readonly start: number;
  readonly end: number;
  readonly threatLevel: Exclude<CodingPromptThreatLevel, 'NONE'>;
  readonly reason: string;
}

const MAX_PROMPT_CHARS = 512_000;
const MAX_FILE_PATHS = 20_000;
const THREAT_RANK: Readonly<Record<CodingPromptThreatLevel, number>> = {
  NONE: 0,
  LOW: 1,
  HIGH: 2,
  CRITICAL: 3,
};

const PROMPT_OVERRIDE_PATTERNS: readonly RegExp[] = [
  /\b(?:ignore|disregard|forget|override|bypass)\b[^\n]{0,100}\b(?:all\s+)?(?:previous|prior|above|earlier|system|developer)\b[^\n]{0,80}\b(?:instructions?|rules?|polic(?:y|ies)|prompts?)\b/gi,
  /\b(?:reveal|print|show|expose|repeat|leak)\b[^\n]{0,100}\b(?:hidden|system|developer|internal)\b[^\n]{0,60}\b(?:prompt|instructions?|message|policy)\b/gi,
  /\b(?:act|behave|respond)\b[^\n]{0,60}\b(?:as|like)\b[^\n]{0,60}\b(?:unrestricted|unfiltered|uncensored|jailbroken|developer mode)\b/gi,
  /\b(?:disable|turn off|remove)\b[^\n]{0,60}\b(?:safety|security|content)\b[^\n]{0,40}\b(?:filter|guard|policy|restriction)s?\b/gi,
  /<\|(?:system|developer|assistant)\|>|\b(?:SYSTEM|DEVELOPER)\s*PROMPT\s*OVERRIDE\b/gi,
  /^\s*#{1,4}\s*(?:system|developer)\s*(?:prompt|instructions?)?\s*:/gim,
];

const COMMAND_INJECTION_PATTERNS: readonly RegExp[] = [
  /(?:^|[;&|]\s*)(?:curl|wget|bash|sh|zsh|nc|ncat|netcat|python(?:3)?|perl|ruby|node)\b[^\n]{0,180}(?:\||&&|;)/gim,
  /\|\s*(?:bash|sh|zsh)\b/gim,
  /(?:\$\(|`)[^\n)]{0,180}\b(?:curl|wget|bash|sh|nc|ncat|netcat|python(?:3)?|perl|ruby)\b[^\n)]*[)`]/gim,
  /\b(?:eval|exec)\s*\(\s*[^\n)]{0,160}(?:\+\s*(?:req(?:uest)?\.|input\b|process\.env)|\$\{|\b(?:curl|wget|bash|sh|nc|netcat)\b)/gim,
];

const TRAVERSAL_PATTERN = /(?:\.\.[/\\]){1,}(?:[^\s"'<>`|;,)\]}]*)?/g;
const URL_PATTERN = /\bhttps?:\/\/[^\s"'<>`]+/gi;
const IPV4_PATTERN = /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])/g;
const LOCAL_HOST_PATTERN = /\b(?:localhost|metadata\.google\.internal|instance-data\.ec2\.internal)(?::\d{1,5})?(?:\/[\w./?=&%+-]*)?/gi;
const INTERNAL_IPV6_PATTERN = /(?<![\da-f])\[?(?:::1|fe80:[\da-f:]*|f[cd][\da-f]{2}:[\da-f:]+)(?:%[\w.-]+)?\]?(?::\d{1,5})?(?:\/[\w./?=&%+-]*)?(?![\da-f])/gi;

function safeDecode(value: string): string {
  let decoded = value;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) {
        break;
      }
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded;
}

function isPrivateIPv4(hostname: string): boolean {
  const octets = hostname.split('.').map(Number);
  if (
    octets.length !== 4 ||
    octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)
  ) {
    return false;
  }

  const [first, second, third] = octets;
  if (first === undefined || second === undefined || third === undefined) {
    return false;
  }
  return first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 198 && (second === 18 || second === 19)) ||
    (first === 192 && second === 0 && third === 0);
}

function isInternalHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  return normalized === 'localhost' ||
    normalized.endsWith('.localhost') ||
    normalized.endsWith('.local') ||
    normalized.endsWith('.internal') ||
    normalized === 'metadata.google.internal' ||
    normalized === 'instance-data.ec2.internal' ||
    normalized === '::1' ||
    normalized.startsWith('fe80:') ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fd') ||
    isPrivateIPv4(normalized);
}

function addFinding(
  findings: PromptFinding[],
  start: number,
  matchedText: string,
  threatLevel: PromptFinding['threatLevel'],
  reason: string,
): void {
  if (matchedText.length > 0) {
    findings.push({ start, end: start + matchedText.length, threatLevel, reason });
  }
}

function collectRegexFindings(
  source: string,
  pattern: RegExp,
  findings: PromptFinding[],
  threatLevel: PromptFinding['threatLevel'],
  reason: string,
): void {
  const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
  for (const match of source.matchAll(globalPattern)) {
    if (match.index !== undefined && match[0]) {
      addFinding(findings, match.index, match[0], threatLevel, reason);
    }
  }
}

function isInternalUrl(rawUrl: string): boolean {
  const candidate = rawUrl.replace(/[.,!?;:)\]}]+$/, '');
  try {
    const parsed = new URL(candidate);
    return isInternalHostname(parsed.hostname);
  } catch {
    return false;
  }
}

function isUnsafePath(path: string): boolean {
  const decoded = safeDecode(path.trim()).replace(/\\/g, '/');
  return decoded.startsWith('/') ||
    /^[a-zA-Z]:\//.test(decoded) ||
    /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(decoded) ||
    decoded.split('/').some(segment => segment === '..') ||
    decoded.startsWith('//');
}

function redactFindings(prompt: string, findings: readonly PromptFinding[]): string {
  const spans = [...findings]
    .sort((left, right) => left.start - right.start || right.end - left.end)
    .reduce<PromptFinding[]>((accepted, finding) => {
      const overlaps = accepted.some(existing =>
        finding.start < existing.end && finding.end > existing.start,
      );
      if (!overlaps) {
        accepted.push(finding);
      }
      return accepted;
    }, []);

  let sanitized = prompt;
  for (const finding of spans.sort((left, right) => right.start - left.start)) {
    sanitized = `${sanitized.slice(0, finding.start)}[BLOCKED ${finding.reason}]${sanitized.slice(finding.end)}`;
  }
  return sanitized;
}

/** Blocks prompt overrides, command injection, internal-network URLs, and traversal attempts. */
export function inspectCodingPromptSecurity(
  prompt: string,
  filePaths: string[] = [],
): {
  allowed: boolean;
  threatLevel: 'NONE' | 'LOW' | 'HIGH' | 'CRITICAL';
  blockedReason?: string;
  sanitizedPrompt: string;
} {
  if (typeof prompt !== 'string' || prompt.length > MAX_PROMPT_CHARS) {
    return {
      allowed: false,
      threatLevel: 'CRITICAL',
      blockedReason: 'Prompt is invalid or exceeds the security inspection size limit.',
      sanitizedPrompt: '',
    };
  }
  if (!Array.isArray(filePaths) || filePaths.length > MAX_FILE_PATHS || filePaths.some(path => typeof path !== 'string')) {
    return {
      allowed: false,
      threatLevel: 'HIGH',
      blockedReason: 'The file path list is invalid or exceeds the inspection limit.',
      sanitizedPrompt: prompt,
    };
  }

  const findings: PromptFinding[] = [];
  for (const pattern of PROMPT_OVERRIDE_PATTERNS) {
    collectRegexFindings(
      prompt,
      pattern,
      findings,
      'HIGH',
      'prompt-instruction override attempt',
    );
  }
  for (const pattern of COMMAND_INJECTION_PATTERNS) {
    collectRegexFindings(
      prompt,
      pattern,
      findings,
      'CRITICAL',
      'command execution payload',
    );
  }

  const decodedPrompt = safeDecode(prompt);
  const decodedHasTraversal = new RegExp(TRAVERSAL_PATTERN.source).test(decodedPrompt);
  if (decodedHasTraversal) {
    if (decodedPrompt !== prompt) {
      addFinding(findings, 0, prompt, 'HIGH', 'encoded path traversal attempt');
    } else {
      for (const match of prompt.matchAll(new RegExp(TRAVERSAL_PATTERN.source, 'g'))) {
        if (match.index !== undefined && match[0]) {
          addFinding(findings, match.index, match[0], 'HIGH', 'path traversal attempt');
        }
      }
    }
  }

  for (const match of prompt.matchAll(URL_PATTERN)) {
    if (match.index !== undefined && match[0] && isInternalUrl(match[0])) {
      addFinding(findings, match.index, match[0], 'CRITICAL', 'internal-network URL');
    }
  }
  for (const match of prompt.matchAll(IPV4_PATTERN)) {
    if (match.index !== undefined && match[0] && isPrivateIPv4(match[0])) {
      addFinding(findings, match.index, match[0], 'CRITICAL', 'private or metadata IP address');
    }
  }
  for (const pattern of [LOCAL_HOST_PATTERN, INTERNAL_IPV6_PATTERN]) {
    for (const match of prompt.matchAll(new RegExp(pattern.source, pattern.flags))) {
      if (match.index !== undefined && match[0]) {
        addFinding(findings, match.index, match[0], 'CRITICAL', 'internal host reference');
      }
    }
  }

  const unsafePaths = filePaths.filter(isUnsafePath);
  if (unsafePaths.length > 0) {
    findings.push({
      start: 0,
      end: 0,
      threatLevel: 'CRITICAL',
      reason: 'unsafe workspace file path',
    });
  }

  const threatLevel = findings.reduce<CodingPromptThreatLevel>(
    (highest, finding) => THREAT_RANK[finding.threatLevel] > THREAT_RANK[highest]
      ? finding.threatLevel
      : highest,
    'NONE',
  );
  const allowed = threatLevel === 'NONE' || threatLevel === 'LOW';
  const reasons = [...new Set(findings.map(finding => finding.reason))];
  const sanitizedPrompt = redactFindings(prompt, findings);

  return {
    allowed,
    threatLevel,
    ...(allowed ? {} : { blockedReason: reasons.join('; ') }),
    sanitizedPrompt,
  };
}