export type MaliciousCodeSeverity = 'HIGH' | 'CRITICAL';

export interface MaliciousCodeFinding {
  readonly file: string;
  readonly line: number;
  readonly pattern: string;
  readonly severity: MaliciousCodeSeverity;
}

export interface ScannedCodeFile {
  readonly path: string;
  readonly content: string;
}

export interface MaliciousCodeScanResult {
  readonly safe: boolean;
  readonly findings: MaliciousCodeFinding[];
  readonly neutralizedFiles: Array<{ path: string; content: string }>;
}

interface DetectionRule {
  readonly label: string;
  readonly expression: RegExp;
  readonly severity: MaliciousCodeSeverity;
}

const MAX_FILE_COUNT = 20_000;
const MAX_TOTAL_SOURCE_CHARS = 8_000_000;

const DIRECT_RULES: readonly DetectionRule[] = [
  {
    label: 'fork bomb or unbounded process-spawning loop',
    expression: /(?:\bfunction\s+\w+\s*\([^)]*\)\s*\{[^}]{0,240}\b\w+\s*\([^)]*\)[^}]{0,160}\b(?:fork|spawn)\s*\(|:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:|\bwhile\s*\(\s*true\s*\)[^\n]{0,100}\b(?:fork|spawn)\s*\()/i,
    severity: 'CRITICAL',
  },
  {
    label: 'reverse-shell or remote command channel',
    expression: /\b(?:nc|ncat|netcat|socat)\b[^\r\n]{0,200}(?:\s-[a-zA-Z]*e\b|\s-[a-zA-Z]*l\b|\/bin\/(?:ba)?sh)|\b(?:bash|sh)\s+-[a-zA-Z]*i\b/i,
    severity: 'CRITICAL',
  },
  {
    label: 'child-process shell execution',
    expression: /\b(?:child_process\s*\.\s*|(?:exec|execSync)\s*\(|(?:spawn|spawnSync)\s*\([^\n]{0,160}\bshell\s*:\s*true)/i,
    severity: 'HIGH',
  },
  {
    label: 'cryptocurrency-mining payload',
    expression: /\b(?:stratum\+(?:tcp|ssl)|xmrig|coinhive|cryptonight|randomx|wasm[-_ ]?miner|coin[-_ ]?miner)\b/i,
    severity: 'CRITICAL',
  },
  {
    label: 'destructive root filesystem command',
    expression: /(?:^|[;&|]\s*)(?:sudo\s+)?rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:--no-preserve-root\s+)?\/(?:\s|$|[;&|])/i,
    severity: 'CRITICAL',
  },
  {
    label: 'recursive forced filesystem deletion',
    expression: /\bRemove-Item\b[^\r\n]{0,200}\s-(?:Recurse|r)\b[^\r\n]{0,120}\s-(?:Force|f)\b[^\r\n]{0,120}(?:['"]?[A-Za-z]:\\?['"]?|['"]?\\\\\?['"]?)/i,
    severity: 'CRITICAL',
  },
  {
    label: 'recursive root filesystem deletion through a runtime API',
    expression: /\b(?:fs\.)?(?:rmSync|rm|rmdirSync|rmdir)\s*\(\s*['"]\/(?:['"]|\s*,)[^\n]{0,180}(?:recursive\s*:\s*true|recursive\s*:\s*!?0|\[?['"]recursive['"]\]?\s*,\s*!?0)/i,
    severity: 'CRITICAL',
  },
];

const ENCRYPTION_INDICATOR = /\b(?:createCipheriv|createCipher|subtle\.encrypt|encryptFile|AES[-_]?(?:128|192|256)|ChaCha20|CryptoJS\.AES)\b/i;
const DIRECTORY_WALK_INDICATOR = /\b(?:readdir(?:Sync)?|opendir(?:Sync)?|walk(?:Sync)?|glob(?:Sync)?|recursive(?:ly)?|directoryIterator)\b/i;
const ITERATION_INDICATOR = /\b(?:for\s*\([^)]*\b(?:of|in)\b|forEach\s*\(|while\s*\(|for\s*\()/i;
const FILE_MUTATION_INDICATOR = /\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|rename(?:Sync)?|unlink(?:Sync)?|createWriteStream|writeBytes|writeAllBytes)\b/i;

function getLines(content: string): string[] {
  return content.split(/\r\n|\r|\n/);
}

function addFinding(
  findings: MaliciousCodeFinding[],
  seen: Set<string>,
  file: string,
  line: number,
  pattern: string,
  severity: MaliciousCodeSeverity,
): void {
  const key = `${file}\0${line}\0${pattern}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  findings.push({ file, line, pattern, severity });
}

function isRansomwareLikeFileMutation(lines: readonly string[]): Set<number> {
  const encryptionLines: number[] = [];
  const directoryWalkLines: number[] = [];
  const iterationLines: number[] = [];
  const mutationLines: number[] = [];

  lines.forEach((line, index) => {
    if (ENCRYPTION_INDICATOR.test(line)) {
      encryptionLines.push(index);
    }
    if (DIRECTORY_WALK_INDICATOR.test(line)) {
      directoryWalkLines.push(index);
    }
    if (ITERATION_INDICATOR.test(line)) {
      iterationLines.push(index);
    }
    if (FILE_MUTATION_INDICATOR.test(line)) {
      mutationLines.push(index);
    }
  });

  if (encryptionLines.length === 0 || mutationLines.length === 0) {
    return new Set<number>();
  }

  const hasBulkTraversal = directoryWalkLines.length > 0 || iterationLines.length > 0;
  const involvedLines = new Set<number>();
  if (hasBulkTraversal) {
    for (const line of [...encryptionLines, ...directoryWalkLines, ...iterationLines, ...mutationLines]) {
      involvedLines.add(line);
    }
  }
  return involvedLines;
}

function neutralizeLines(lines: readonly string[], linesToNeutralize: ReadonlySet<number>): string {
  return lines.map((line, index) => linesToNeutralize.has(index) ? '' : line).join('\n');
}

/** Detects destructive or covert code indicators and blanks implicated lines before downstream use. */
export function scanForMaliciousCode(
  files: Array<{ path: string; content: string }>,
): {
  safe: boolean;
  findings: Array<{ file: string; line: number; pattern: string; severity: 'HIGH' | 'CRITICAL' }>;
  neutralizedFiles: Array<{ path: string; content: string }>;
} {
  if (!Array.isArray(files) || files.length > MAX_FILE_COUNT) {
    throw new RangeError(`Code scan accepts at most ${MAX_FILE_COUNT} files.`);
  }
  let totalSourceChars = 0;
  for (const file of files) {
    if (
      typeof file?.path !== 'string' ||
      typeof file.content !== 'string'
    ) {
      throw new TypeError('Every scanned file must have a string path and content.');
    }
    totalSourceChars += file.content.length;
    if (totalSourceChars > MAX_TOTAL_SOURCE_CHARS) {
      throw new RangeError(`Code scan exceeds the ${MAX_TOTAL_SOURCE_CHARS}-character source limit.`);
    }
  }

  const findings: MaliciousCodeFinding[] = [];
  const seen = new Set<string>();
  const neutralizedFiles = files.map(file => {
    const lines = getLines(file.content);
    const linesToNeutralize = new Set<number>();

    lines.forEach((line, lineIndex) => {
      for (const rule of DIRECT_RULES) {
        if (rule.expression.test(line)) {
          addFinding(
            findings,
            seen,
            file.path,
            lineIndex + 1,
            rule.label,
            rule.severity,
          );
          linesToNeutralize.add(lineIndex);
        }
      }
    });

    for (const lineIndex of isRansomwareLikeFileMutation(lines)) {
      addFinding(
        findings,
        seen,
        file.path,
        lineIndex + 1,
        'bulk file encryption with recursive filesystem mutation',
        'CRITICAL',
      );
      linesToNeutralize.add(lineIndex);
    }

    return {
      path: file.path,
      content: neutralizeLines(lines, linesToNeutralize),
    };
  });

  return {
    safe: findings.length === 0,
    findings,
    neutralizedFiles,
  };
}