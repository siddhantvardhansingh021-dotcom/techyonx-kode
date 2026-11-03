import { createHash, randomUUID } from 'node:crypto';
import type { AgentStepTrace } from '../../types/codingEngine';

export type BugSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface BugHunterFinding {
  readonly id: string;
  readonly file: string;
  readonly line: number;
  readonly severity: BugSeverity;
  readonly bugType: string;
  readonly description: string;
  readonly suggestedFix: string;
}

export interface BugHunterResult {
  readonly bugsFound: BugHunterFinding[];
  readonly stepTrace: AgentStepTrace;
}

interface CodeFile {
  readonly path: string;
  readonly language: string;
  readonly content: string;
}

interface SourceSpan {
  readonly start: number;
  readonly end: number;
  readonly body: string;
}

const MAX_FILE_COUNT = 2_000;
const MAX_TOTAL_SOURCE_CHARS = 10_000_000;
const MAX_FINDINGS = 10_000;

function lineAt(source: string, index: number): number {
  let line = 1;
  for (let cursor = 0; cursor < index && cursor < source.length; cursor += 1) {
    if (source[cursor] === '\n') line += 1;
  }
  return line;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function sourceBlock(source: string, openBrace: number): SourceSpan | undefined {
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
      if (depth === 0) {
        return { start: openBrace, end: index + 1, body: source.slice(openBrace + 1, index) };
      }
    }
  }
  return undefined;
}

function loopHasExit(source: string, matchIndex: number, matchEnd: number): boolean {
  const searchEnd = Math.min(source.length, matchIndex + 20_000);
  const openBrace = source.indexOf('{', matchEnd);
  const newline = source.indexOf('\n', matchEnd);
  if (openBrace >= 0 && openBrace < searchEnd && (newline < 0 || openBrace < newline + 500)) {
    const block = sourceBlock(source, openBrace);
    if (block) return /\b(?:break|return|throw)\b/.test(block.body);
  }
  const statementEnd = source.indexOf(';', matchEnd);
  const end = statementEnd >= 0 ? statementEnd : Math.min(source.length, matchEnd + 500);
  return /\b(?:break|return|throw)\b/.test(source.slice(matchEnd, end));
}

function addFinding(
  findings: BugHunterFinding[],
  seen: Set<string>,
  file: string,
  source: string,
  index: number,
  severity: BugSeverity,
  bugType: string,
  description: string,
  suggestedFix: string,
): void {
  if (findings.length >= MAX_FINDINGS) return;
  const line = lineAt(source, index);
  const id = createHash('sha256')
    .update(`${file}\0${line}\0${bugType}\0${description}`)
    .digest('hex')
    .slice(0, 20);
  if (seen.has(id)) return;
  seen.add(id);
  findings.push({ id, file, line, severity, bugType, description, suggestedFix });
}

function inspectLoops(file: CodeFile, findings: BugHunterFinding[], seen: Set<string>): void {
  const loopPattern = /\bwhile\s*\(\s*(?:true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\)/g;
  for (const match of file.content.matchAll(loopPattern)) {
    if (match.index === undefined || !match[0]) continue;
    if (!loopHasExit(file.content, match.index, match.index + match[0].length)) {
      addFinding(
        findings,
        seen,
        file.path,
        file.content,
        match.index,
        'HIGH',
        'INFINITE_LOOP',
        'Unconditional loop has no visible break, return, or throw exit in its body.',
        'Add a bounded iteration condition or a reachable exit that is tested under boundary inputs.',
      );
    }
  }
}

function inspectAsyncHandling(file: CodeFile, findings: BugHunterFinding[], seen: Set<string>): void {
  const asyncPattern = /\basync\s+(?:function\s+[A-Za-z_$][\w$]*\s*\([^)]*\)|\([^)]*\)\s*=>\s*\{|[A-Za-z_$][\w$]*\s*=>\s*\{)/g;
  for (const match of file.content.matchAll(asyncPattern)) {
    if (match.index === undefined || !match[0]) continue;
    const openBrace = file.content.indexOf('{', match.index + match[0].length - 1);
    const block = sourceBlock(file.content, openBrace);
    if (!block || !/\bawait\b/.test(block.body) || /\btry\s*\{/.test(block.body)) continue;
    addFinding(
      findings,
      seen,
      file.path,
      file.content,
      match.index,
      'MEDIUM',
      'ASYNC_REJECTION_UNHANDLED',
      'Async function awaits work without a visible try/catch; rejected operations may escape the intended error boundary.',
      'Catch expected failures locally or return the promise to a caller that owns an explicit rejection boundary.',
    );
  }

  const thenPattern = /\.then\s*\(/g;
  for (const match of file.content.matchAll(thenPattern)) {
    if (match.index === undefined) continue;
    const chain = file.content.slice(match.index, Math.min(file.content.length, match.index + 2_000));
    if (/\.catch\s*\(|\bawait\b/.test(chain.split(/[;\n]/, 1)[0] ?? '')) continue;
    addFinding(
      findings,
      seen,
      file.path,
      file.content,
      match.index,
      'MEDIUM',
      'PROMISE_REJECTION_UNHANDLED',
      'Promise chain has no visible catch handler before its statement boundary.',
      'Append a catch handler or await the promise inside a try/catch at the owning boundary.',
    );
  }
}

function inspectNullableDereferences(file: CodeFile, findings: BugHunterFinding[], seen: Set<string>): void {
  const assignmentPattern = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:[A-Za-z_$][\w$]*\s*\.\s*(?:get|find|findFirst|querySelector|querySelectorAll)\s*\(|[A-Za-z_$][\w$]*\s*\[[^\]]+\])/g;
  for (const match of file.content.matchAll(assignmentPattern)) {
    const variable = match[1];
    if (!variable || match.index === undefined) continue;
    const remainder = file.content.slice(match.index + match[0].length);
    const dereference = new RegExp(`\\b${variable}\\s*\\.\\s*[A-Za-z_$][\\w$]*`).exec(remainder);
    if (!dereference) continue;
    const guarded = new RegExp(`(?:if\\s*\\(\\s*!?${variable}\\b|\\b${variable}\\s*\\?\\.|\\b${variable}\\s*\\?\\?|\\b${variable}\\s*&&)`).test(remainder);
    if (guarded) continue;
    const absoluteIndex = match.index + match[0].length + dereference.index;
    addFinding(
      findings,
      seen,
      file.path,
      file.content,
      absoluteIndex,
      'MEDIUM',
      'NULLABLE_DEREFERENCE',
      `Value '${variable}' comes from a lookup that may return no result and is dereferenced without a visible null guard.`,
      `Check '${variable}' for null/undefined or use an explicit fallback before accessing its property.`,
    );
  }
}

function inspectReactEffects(file: CodeFile, findings: BugHunterFinding[], seen: Set<string>): void {
  const effectPattern = /\buseEffect\s*\(\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{/g;
  for (const match of file.content.matchAll(effectPattern)) {
    if (match.index === undefined || !match[0]) continue;
    const openBrace = file.content.indexOf('{', match.index + match[0].length - 1);
    const block = sourceBlock(file.content, openBrace);
    if (!block || !/\bset[A-Z][A-Za-z0-9_$]*\s*\(/.test(block.body)) continue;
    const afterEffectBody = file.content.slice(block.end);
    if (/^\s*,\s*\[/.test(afterEffectBody)) continue;
    addFinding(
      findings,
      seen,
      file.path,
      file.content,
      match.index,
      'HIGH',
      'REACT_EFFECT_INFINITE_RERENDER',
      'useEffect updates state but has no dependency array, so it runs after every render and can create a render loop.',
      'Add the minimal dependency array, or move derived state into render/useMemo and avoid unconditional state updates.',
    );
  }
}

function inspectResourceCleanup(file: CodeFile, findings: BugHunterFinding[], seen: Set<string>): void {
  const intervalPattern = /\b(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*)?setInterval\s*\(/g;
  for (const match of file.content.matchAll(intervalPattern)) {
    if (match.index === undefined || !match[0]) continue;
    const handle = match[1];
    const hasCleanup = handle
      ? new RegExp(`\\bclearInterval\\s*\\(\\s*${handle}\\s*\\)`).test(file.content)
      : /\bclearInterval\s*\(/.test(file.content);
    if (hasCleanup) continue;
    addFinding(
      findings,
      seen,
      file.path,
      file.content,
      match.index,
      'HIGH',
      'INTERVAL_NOT_CLEARED',
      'Interval handle has no matching clearInterval call in this file and may outlive its owning view or request.',
      'Store the interval handle and clear it in the owning lifecycle cleanup or request abort handler.',
    );
  }

  const listenerPattern = /\b([A-Za-z_$][\w$]*)\s*\.\s*addEventListener\s*\(\s*(['"`])([^'"`]+)\2\s*,\s*([A-Za-z_$][\w$]*)/g;
  for (const match of file.content.matchAll(listenerPattern)) {
    if (match.index === undefined || !match[1] || !match[3] || !match[4]) continue;
    const target = match[1];
    const eventName = match[3];
    const handler = match[4];
    const cleanupPattern = new RegExp(
      `\\b${target}\\s*\\.\\s*removeEventListener\\s*\\(\\s*(['"\x60])${escapeRegex(eventName)}\\1\\s*,\\s*${handler}\\b`,
    );
    if (cleanupPattern.test(file.content)) continue;
    addFinding(
      findings,
      seen,
      file.path,
      file.content,
      match.index,
      'MEDIUM',
      'EVENT_LISTENER_NOT_REMOVED',
      `The '${eventName}' event listener for '${target}' has no matching removeEventListener call in this file.`,
      `Remove the '${eventName}' listener with the same handler when its component, subscription, or request is disposed.`,
    );
  }
}

function inspectArrayBoundaries(file: CodeFile, findings: BugHunterFinding[], seen: Set<string>): void {
  const loopBoundPattern = /\bfor\s*\([^;\n]*;\s*([A-Za-z_$][\w$]*)\s*<=\s*([A-Za-z_$][\w$]*)\.length\s*;/g;
  for (const match of file.content.matchAll(loopBoundPattern)) {
    if (match.index === undefined || !match[1] || !match[2]) continue;
    addFinding(
      findings,
      seen,
      file.path,
      file.content,
      match.index,
      'MEDIUM',
      'ARRAY_OFF_BY_ONE',
      `Loop condition uses '${match[1]} <= ${match[2]}.length', which can access one position beyond the final array element.`,
      `Use '${match[1]} < ${match[2]}.length' when iterating valid array indexes, or explicitly handle the sentinel position.`,
    );
  }
  const directIndexPattern = /\b([A-Za-z_$][\w$]*)\s*\[\s*\1\s*\.\s*length\s*\]/g;
  for (const match of file.content.matchAll(directIndexPattern)) {
    if (match.index === undefined || !match[1]) continue;
    addFinding(
      findings,
      seen,
      file.path,
      file.content,
      match.index,
      'MEDIUM',
      'ARRAY_LENGTH_INDEX',
      `Direct access to '${match[1]}[${match[1]}.length]' is outside the valid zero-based array index range.`,
      `Use '${match[1]}.length - 1' after checking the array is non-empty, or access the intended element by a valid index.`,
    );
  }
}

/** Finds evidence-backed bug candidates without executing or modifying supplied code. */
export function runAutonomousBugHunterAgent(
  files: Array<{ path: string; language: string; content: string }>,
): {
  bugsFound: Array<{ id: string; file: string; line: number; severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; bugType: string; description: string; suggestedFix: string }>;
  stepTrace: AgentStepTrace;
} {
  const startedAt = Date.now();
  if (!Array.isArray(files) || files.length > MAX_FILE_COUNT) {
    throw new RangeError(`Bug hunting accepts at most ${MAX_FILE_COUNT} files.`);
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
      throw new TypeError('Bug-hunter input contains an invalid relative path or file record.');
    }
    totalChars += file.content.length;
    if (totalChars > MAX_TOTAL_SOURCE_CHARS) {
      throw new RangeError(`Bug hunting exceeds the ${MAX_TOTAL_SOURCE_CHARS}-character input limit.`);
    }
  }

  const bugsFound: BugHunterFinding[] = [];
  const seen = new Set<string>();
  for (const file of files) {
    inspectLoops(file, bugsFound, seen);
    inspectAsyncHandling(file, bugsFound, seen);
    inspectNullableDereferences(file, bugsFound, seen);
    inspectReactEffects(file, bugsFound, seen);
    inspectResourceCleanup(file, bugsFound, seen);
    inspectArrayBoundaries(file, bugsFound, seen);
  }

  const completedAt = new Date().toISOString();
  const stepTrace: AgentStepTrace = {
    traceId: randomUUID(),
    operationId: randomUUID(),
    agentId: 'autonomous-bug-hunter-4',
    role: 'BUG_HUNTER',
    status: 'SUCCEEDED',
    startedAt: new Date(startedAt).toISOString(),
    completedAt,
    inputSummary: `Inspected ${files.length} files and ${totalChars} source characters without executing code.`,
    outputSummary: `Reported ${bugsFound.length} evidence-backed bug candidates for review.`,
    affectedPaths: [...new Set(bugsFound.map(bug => bug.file))],
  };
  return { bugsFound, stepTrace };
}