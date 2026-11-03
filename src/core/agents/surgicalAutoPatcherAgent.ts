import { randomUUID } from 'node:crypto';
import type { AgentStepTrace } from '../../types/codingEngine';

export interface PatcherInputFile {
  readonly path: string;
  readonly language: string;
  readonly content: string;
}

export interface AppliedSurgicalPatch {
  readonly file: string;
  readonly line: number;
  readonly reason: string;
  readonly before: string;
  readonly after: string;
}

interface SyntaxDiagnostic {
  readonly file: string;
  readonly line: number;
  readonly message: string;
  readonly autoRepairable: boolean;
}

interface LogicalBug {
  readonly file: string;
  readonly line: number;
  readonly bugType: string;
}

interface BlockRange {
  readonly openBrace: number;
  readonly closeBrace: number;
  readonly body: string;
}

const MAX_FILE_COUNT = 2_000;
const MAX_TOTAL_SOURCE_CHARS = 10_000_000;
const MAX_DIAGNOSTICS = 20_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseSyntaxDiagnostic(value: unknown): SyntaxDiagnostic | undefined {
  if (!isRecord(value)) return undefined;
  const { file, line, message, autoRepairable } = value;
  if (typeof file !== 'string' || !Number.isSafeInteger(line) || typeof message !== 'string') return undefined;
  return { file, line: line as number, message, autoRepairable: autoRepairable === true };
}

function parseLogicalBug(value: unknown): LogicalBug | undefined {
  if (!isRecord(value)) return undefined;
  const { file, line, bugType } = value;
  if (typeof file !== 'string' || !Number.isSafeInteger(line) || typeof bugType !== 'string') return undefined;
  return { file, line: line as number, bugType };
}

function countLines(content: string): number {
  if (content.length === 0) return 0;
  const lines = content.replace(/\r\n?/g, '\n').split('\n');
  return lines.length - (lines.at(-1) === '' ? 1 : 0);
}

function sourceLineAt(source: string, index: number): number {
  let line = 1;
  for (let cursor = 0; cursor < index && cursor < source.length; cursor += 1) {
    if (source[cursor] === '\n') line += 1;
  }
  return line;
}

function locateBlock(source: string, openBrace: number): BlockRange | undefined {
  if (source[openBrace] !== '{') return undefined;
  let depth = 0;
  let quote = '';
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = openBrace; index < source.length; index += 1) {
    const character = source[index] ?? '';
    const next = source[index + 1] ?? '';
    if (lineComment) {
      if (character === '\n') lineComment = false;
      continue;
    }
    if (blockComment) {
      if (character === '*' && next === '/') {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = '';
      continue;
    }
    if (character === '/' && next === '/') {
      lineComment = true;
      index += 1;
      continue;
    }
    if (character === '/' && next === '*') {
      blockComment = true;
      index += 1;
      continue;
    }
    if (character === '"' || character === "'" || character === '`') {
      quote = character;
      continue;
    }
    if (character === '{') depth += 1;
    if (character === '}') {
      depth -= 1;
      if (depth === 0) return { openBrace, closeBrace: index, body: source.slice(openBrace + 1, index) };
    }
  }
  return undefined;
}

function asyncFunctionRanges(source: string): Array<{ line: number; block: BlockRange }> {
  const ranges: Array<{ line: number; block: BlockRange }> = [];
  const pattern = /\basync\s+(?:function\s+[A-Za-z_$][\w$]*\s*\([^)]*\)|(?:[A-Za-z_$][\w$]*\s*)?\([^)]*\)\s*=>)\s*\{/g;
  for (const match of source.matchAll(pattern)) {
    if (match.index === undefined || !match[0]) continue;
    const openBrace = source.indexOf('{', match.index + match[0].length - 1);
    const block = locateBlock(source, openBrace);
    if (!block) continue;
    const line = sourceLineAt(source, match.index);
    ranges.push({ line, block });
  }
  return ranges;
}

function closingSuffix(errors: readonly SyntaxDiagnostic[]): string {
  const closers: string[] = [];
  let closeTemplate = false;
  for (const error of errors) {
    const delimiter = error.message.match(/Unclosed delimiter '[{[(]'; expected '([})\]])'/);
    if (delimiter?.[1]) closers.push(delimiter[1]);
    if (/Unclosed template literal/.test(error.message)) closeTemplate = true;
  }
  return `${closers.join('')}${closeTemplate ? '`' : ''}`;
}

function patchFile(
  file: PatcherInputFile,
  errors: readonly SyntaxDiagnostic[],
  bugs: readonly LogicalBug[],
): { content: string; patches: AppliedSurgicalPatch[] } {
  let content = file.content;
  const patches: AppliedSurgicalPatch[] = [];

  const quoteErrors = errors
    .filter(error => error.autoRepairable && /Unclosed (single-quoted|double-quoted) string literal/.test(error.message))
    .sort((left, right) => right.line - left.line);
  const lines = content.split('\n');
  for (const error of quoteErrors) {
    const lineIndex = Math.max(0, Math.min(lines.length - 1, error.line - 1));
    const before = lines[lineIndex] ?? '';
    const quote = /single-quoted/.test(error.message) ? "'" : '"';
    if (!before.includes(quote)) continue;
    const after = `${before}${quote}`;
    lines[lineIndex] = after;
    patches.push({ file: file.path, line: lineIndex + 1, reason: 'Closed an unterminated string at the end of its diagnostic line.', before, after });
  }
  content = lines.join('\n');

  for (const bug of bugs) {
    if (bug.bugType !== 'ARRAY_OFF_BY_ONE') continue;
    const currentLines = content.split('\n');
    const lineIndex = bug.line - 1;
    const before = currentLines[lineIndex];
    if (!before || !/<=\s*[A-Za-z_$][\w$]*\.length/.test(before)) continue;
    const after = before.replace(/<=\s*([A-Za-z_$][\w$]*\.length)/, '< $1');
    currentLines[lineIndex] = after;
    content = currentLines.join('\n');
    patches.push({ file: file.path, line: bug.line, reason: 'Changed a zero-based array loop bound to exclude the out-of-range length index.', before, after });
  }

  const mapLines = content.split('\n');
  const mapPatterns = [
    /\.map\s*\(\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*=>\s*<([A-Za-z][A-Za-z0-9.]*)\b(?![^>]*\bkey\s*=)/,
    /\.map\s*\(\s*([A-Za-z_$][\w$]*)\s*=>\s*<([A-Za-z][A-Za-z0-9.]*)\b(?![^>]*\bkey\s*=)/,
  ];
  mapLines.forEach((line, index) => {
    for (const pattern of mapPatterns) {
      const match = pattern.exec(line);
      if (!match || !match[1] || !match[2]) continue;
      const after = line.replace(pattern, (_whole, item: string, tag: string) =>
        `.map((${item}, index) => <${tag} key={index}`,
      );
      mapLines[index] = after;
      patches.push({ file: file.path, line: index + 1, reason: 'Added a deterministic React key to a JSX element rendered from an array map.', before: line, after });
      break;
    }
  });
  content = mapLines.join('\n');

  const asyncBugs = bugs
    .filter(bug => bug.bugType === 'ASYNC_REJECTION_UNHANDLED')
    .sort((left, right) => right.line - left.line);
  for (const bug of asyncBugs) {
    const range = asyncFunctionRanges(content).find(candidate =>
      candidate.line <= bug.line && bug.line <= sourceLineAt(content, candidate.block.closeBrace),
    );
    if (!range || /\breturn\s+(?!;)/.test(range.block.body) || /\btry\s*\{/.test(range.block.body)) continue;
    const before = content.slice(range.block.openBrace + 1, range.block.closeBrace);
    const after = `\n    try {${before}\n    } catch (error) {\n      console.error("Async operation failed", error);\n    }\n  `;
    content = `${content.slice(0, range.block.openBrace + 1)}${after}${content.slice(range.block.closeBrace)}`;
    patches.push({ file: file.path, line: range.line, reason: 'Added a rejection boundary to a void-returning async function.', before, after });
  }

  const suffix = closingSuffix(errors);
  if (suffix) {
    const before = content.split('\n').at(-1) ?? '';
    const append = `${content.length > 0 && !content.endsWith('\n') ? '\n' : ''}${suffix}`;
    content += append;
    patches.push({ file: file.path, line: countLines(content), reason: 'Closed unmatched delimiters in lexical stack order.', before, after: `${before}${append}` });
  }

  if (errors.some(error => /use client/i.test(error.message)) && !/^\s*['"]use client['"]\s*;?/.test(content)) {
    const before = content.split('\n')[0] ?? '';
    const directive = "'use client';";
    content = `${directive}\n${content}`;
    patches.push({ file: file.path, line: 1, reason: 'React hooks require a client component directive in the Next.js App Router.', before, after: `${directive}${before ? `\n${before}` : ''}` });
  }

  return { content, patches };
}

/** Applies deterministic, narrowly scoped repairs and returns every edit for user review. */
export function runSurgicalAutoPatcherAgent(
  files: Array<{ path: string; language: string; content: string }>,
  syntaxErrors: unknown[],
  bugsFound: unknown[],
): {
  patchedFiles: Array<{ path: string; language: string; content: string; lineCount: number }>;
  appliedPatches: Array<{ file: string; line: number; reason: string; before: string; after: string }>;
  stepTrace: AgentStepTrace;
} {
  const startedAt = Date.now();
  if (!Array.isArray(files) || files.length > MAX_FILE_COUNT) throw new RangeError(`Auto-patching accepts at most ${MAX_FILE_COUNT} files.`);
  if (!Array.isArray(syntaxErrors) || !Array.isArray(bugsFound) || syntaxErrors.length + bugsFound.length > MAX_DIAGNOSTICS) {
    throw new RangeError(`Auto-patcher accepts at most ${MAX_DIAGNOSTICS} diagnostics.`);
  }

  let totalChars = 0;
  for (const file of files) {
    if (
      typeof file?.path !== 'string' ||
      typeof file.language !== 'string' ||
      typeof file.content !== 'string' ||
      file.path.length > 1_024 ||
      file.path.startsWith('/') ||
      file.path.includes('\\') ||
      file.path.split('/').some(segment => segment === '..' || segment === '.' || segment.length === 0)
    ) {
      throw new TypeError('Auto-patcher input contains an invalid relative path or file record.');
    }
    totalChars += file.content.length;
    if (totalChars > MAX_TOTAL_SOURCE_CHARS) throw new RangeError(`Auto-patching exceeds the ${MAX_TOTAL_SOURCE_CHARS}-character input limit.`);
  }

  const parsedErrors = syntaxErrors.map(parseSyntaxDiagnostic).filter((value): value is SyntaxDiagnostic => value !== undefined);
  const parsedBugs = bugsFound.map(parseLogicalBug).filter((value): value is LogicalBug => value !== undefined);
  const appliedPatches: AppliedSurgicalPatch[] = [];
  const patchedFiles = files.map(file => {
    const patched = patchFile(
      file,
      parsedErrors.filter(error => error.file === file.path),
      parsedBugs.filter(bug => bug.file === file.path),
    );
    appliedPatches.push(...patched.patches);
    return { path: file.path, language: file.language, content: patched.content, lineCount: countLines(patched.content) };
  });

  const stepTrace: AgentStepTrace = {
    traceId: randomUUID(),
    operationId: randomUUID(),
    agentId: 'surgical-auto-patcher-5',
    role: 'SURGICAL_PATCHER',
    status: 'SUCCEEDED',
    startedAt: new Date(startedAt).toISOString(),
    completedAt: new Date().toISOString(),
    inputSummary: `Reviewed ${files.length} files, ${parsedErrors.length} syntax diagnostics, and ${parsedBugs.length} bug findings.`,
    outputSummary: `Applied ${appliedPatches.length} deterministic patches; ambiguous findings were left unchanged.`,
    affectedPaths: [...new Set(appliedPatches.map(patch => patch.file))],
  };
  return { patchedFiles, appliedPatches, stepTrace };
}