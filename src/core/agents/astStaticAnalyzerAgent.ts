import { createHash, randomUUID } from 'node:crypto';
import type { AgentStepTrace } from '../../types/codingEngine';

export interface AnalyzerInputFile {
  readonly path: string;
  readonly language: string;
  readonly content: string;
}

export interface StaticSyntaxError {
  readonly file: string;
  readonly line: number;
  readonly message: string;
  readonly autoRepairable: boolean;
}

export interface StaticAnalyzerResult {
  readonly valid: boolean;
  readonly syntaxErrors: StaticSyntaxError[];
  readonly metrics: {
    readonly totalLines: number;
    readonly complexityScore: number;
  };
  readonly stepTrace: AgentStepTrace;
}

type TokenKind = 'identifier' | 'string' | 'punctuator';
type LexicalState = 'code' | 'single-string' | 'double-string' | 'template' | 'line-comment' | 'block-comment';

interface LexToken {
  readonly kind: TokenKind;
  readonly value: string;
  readonly line: number;
  readonly scopeId: number;
}

interface DelimiterFrame {
  readonly character: '{' | '(' | '[';
  readonly line: number;
  readonly templateInterpolation: boolean;
}

interface LexicalResult {
  readonly tokens: LexToken[];
  readonly errors: StaticSyntaxError[];
  readonly complexity: number;
}

interface FileAnalysis {
  readonly file: AnalyzerInputFile;
  readonly lexical: LexicalResult;
  readonly lineCount: number;
}

const MAX_FILE_COUNT = 2_000;
const MAX_TOTAL_SOURCE_CHARS = 10_000_000;
const MAX_FILE_PATH_CHARS = 1_024;
const DECLARATION_KEYWORDS = new Set([
  'const', 'let', 'var', 'function', 'class', 'interface', 'type', 'enum', 'namespace',
]);
const COMPLEXITY_KEYWORDS = new Set(['if', 'for', 'while', 'case', 'catch']);
const EXTENSIONS = [
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts', '.json',
  '.py', '.go', '.rs', '.sql', '.css', '.html', '.vue', '.svelte',
];

function isIdentifierStart(character: string): boolean {
  return /[A-Za-z_$]/.test(character) || character.charCodeAt(0) > 0x7f;
}

function isIdentifierPart(character: string): boolean {
  return /[A-Za-z0-9_$]/.test(character) || character.charCodeAt(0) > 0x7f;
}

function expectedClose(character: DelimiterFrame['character']): string {
  if (character === '{') return '}';
  if (character === '(') return ')';
  return ']';
}

function couldStartRegex(previousToken: LexToken | undefined): boolean {
  if (!previousToken) return true;
  if (previousToken.kind === 'identifier') {
    return ['return', 'throw', 'case', 'delete', 'typeof', 'void', 'instanceof', 'in', 'of', 'yield', 'await'].includes(previousToken.value);
  }
  return ['=', '(', '[', '{', ':', ',', ';', '!', '?', '=>', '&&', '||', '??', '+', '-', '*', '%', '&', '|'].includes(previousToken.value);
}

function skipRegexLiteral(source: string, start: number): number | undefined {
  let inCharacterClass = false;
  let escaped = false;
  for (let index = start + 1; index < source.length; index += 1) {
    const character = source[index];
    if (character === undefined || character === '\n' || character === '\r') return undefined;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === '\\') {
      escaped = true;
      continue;
    }
    if (character === '[') inCharacterClass = true;
    if (character === ']') inCharacterClass = false;
    if (character === '/' && !inCharacterClass) {
      let end = index + 1;
      while (end < source.length && /[A-Za-z]/.test(source[end] ?? '')) end += 1;
      return end;
    }
  }
  return undefined;
}

function lexFile(file: AnalyzerInputFile): LexicalResult {
  const { content, path } = file;
  const tokens: LexToken[] = [];
  const errors: StaticSyntaxError[] = [];
  const delimiters: DelimiterFrame[] = [];
  const scopeStack = [0];
  const templateReturnStates: LexicalState[] = [];
  let nextScopeId = 1;
  let line = 1;
  let state: LexicalState = 'code';
  let quoteStartLine = 0;
  let quoteStartIndex = 0;
  let blockCommentStartLine = 0;
  let escaped = false;
  let complexity = 1;

  const emit = (kind: TokenKind, value: string, tokenLine: number): void => {
    tokens.push({ kind, value, line: tokenLine, scopeId: scopeStack.at(-1) ?? 0 });
  };
  const addSyntaxError = (errorLine: number, message: string, autoRepairable: boolean): void => {
    errors.push({ file: path, line: errorLine, message, autoRepairable });
  };

  for (let index = 0; index < content.length; index += 1) {
    const character = content[index] ?? '';
    const next = content[index + 1] ?? '';

    if (state === 'line-comment') {
      if (character === '\n') {
        line += 1;
        state = 'code';
      }
      continue;
    }
    if (state === 'block-comment') {
      if (character === '*' && next === '/') {
        state = 'code';
        index += 1;
      } else if (character === '\n') {
        line += 1;
      }
      continue;
    }
    if (state === 'single-string' || state === 'double-string') {
      const quote = state === 'single-string' ? "'" : '"';
      if (character === '\n' || character === '\r') {
        addSyntaxError(quoteStartLine, `Unclosed ${state === 'single-string' ? 'single-quoted' : 'double-quoted'} string literal.`, true);
        state = 'code';
        escaped = false;
        if (character === '\n') line += 1;
        continue;
      }
      if (escaped) {
        escaped = false;
      } else if (character === '\\') {
        escaped = true;
      } else if (character === quote) {
        state = 'code';
        emit('string', content.slice(quoteStartIndex + 1, index), quoteStartLine);
      }
      continue;
    }
    if (state === 'template') {
      if (escaped) {
        escaped = false;
      } else if (character === '\\') {
        escaped = true;
      } else if (character === '`') {
        state = templateReturnStates.pop() ?? 'code';
      } else if (character === '$' && next === '{') {
        const interpolationFrame: DelimiterFrame = {
          character: '{',
          line,
          templateInterpolation: true,
        };
        delimiters.push(interpolationFrame);
        state = 'code';
        index += 1;
        emit('punctuator', '${', line);
      } else if (character === '\n') {
        line += 1;
      }
      continue;
    }

    if (character === '\n') {
      line += 1;
      continue;
    }
    if (/\s/.test(character)) continue;
    if (character === '/' && next === '/') {
      state = 'line-comment';
      index += 1;
      continue;
    }
    if (character === '/' && next === '*') {
      state = 'block-comment';
      blockCommentStartLine = line;
      index += 1;
      continue;
    }
    if (character === '/' && couldStartRegex(tokens.at(-1))) {
      const regexEnd = skipRegexLiteral(content, index);
      if (regexEnd !== undefined) {
        emit('string', '', line);
        index = regexEnd - 1;
        continue;
      }
    }
    if (character === "'" || character === '"') {
      quoteStartLine = line;
      quoteStartIndex = index;
      escaped = false;
      state = character === "'" ? 'single-string' : 'double-string';
      continue;
    }
    if (character === '`') {
      quoteStartLine = line;
      escaped = false;
      templateReturnStates.push(state);
      state = 'template';
      continue;
    }
    if (isIdentifierStart(character)) {
      const start = index;
      index += 1;
      while (index < content.length && isIdentifierPart(content[index] ?? '')) index += 1;
      const value = content.slice(start, index);
      emit('identifier', value, line);
      if (COMPLEXITY_KEYWORDS.has(value)) complexity += 1;
      index -= 1;
      continue;
    }
    if (character === '{' || character === '(' || character === '[') {
      delimiters.push({ character, line, templateInterpolation: false });
      emit('punctuator', character, line);
      if (character === '{') scopeStack.push(nextScopeId++);
      continue;
    }
    if (character === '}' || character === ')' || character === ']') {
      const top = delimiters.at(-1);
      if (!top || expectedClose(top.character) !== character) {
        const expected = top ? ` Expected '${expectedClose(top.character)}' for '${top.character}' opened on line ${top.line}.` : '';
        addSyntaxError(line, `Unexpected closing delimiter '${character}'.${expected}`, false);
      } else {
        delimiters.pop();
        if (character === '}' && !top.templateInterpolation && scopeStack.length > 1) scopeStack.pop();
        if (top.templateInterpolation) state = 'template';
      }
      emit('punctuator', character, line);
      continue;
    }

    const twoCharacterOperator = content.slice(index, index + 2);
    if (['=>', '&&', '||', '??', '?.', '++', '--', '==', '!=', '<=', '>='].includes(twoCharacterOperator)) {
      emit('punctuator', twoCharacterOperator, line);
      if (twoCharacterOperator === '&&' || twoCharacterOperator === '||' || twoCharacterOperator === '??') complexity += 1;
      index += 1;
      continue;
    }
    if (character === '?') complexity += 1;
    emit('punctuator', character, line);
  }

  if (state === 'single-string' || state === 'double-string') {
    addSyntaxError(quoteStartLine, `Unclosed ${state === 'single-string' ? 'single-quoted' : 'double-quoted'} string literal.`, true);
  } else if (state === 'template') {
    addSyntaxError(quoteStartLine, 'Unclosed template literal.', true);
  } else if (state === 'block-comment') {
    addSyntaxError(blockCommentStartLine, 'Unclosed block comment.', true);
  }
  for (let index = delimiters.length - 1; index >= 0; index -= 1) {
    const frame = delimiters[index];
    if (frame) {
      addSyntaxError(frame.line, `Unclosed delimiter '${frame.character}'; expected '${expectedClose(frame.character)}'.`, true);
    }
  }

  return { tokens, errors, complexity };
}

function addDeclarationErrors(path: string, tokens: readonly LexToken[], errors: StaticSyntaxError[]): void {
  const declarations = new Map<string, LexToken>();
  for (let index = 0; index < tokens.length - 1; index += 1) {
    const keyword = tokens[index];
    const name = tokens[index + 1];
    if (
      !keyword ||
      keyword.kind !== 'identifier' ||
      !DECLARATION_KEYWORDS.has(keyword.value) ||
      !name ||
      name.kind !== 'identifier'
    ) {
      continue;
    }
    const key = `${keyword.scopeId}:${name.value}`;
    const previous = declarations.get(key);
    if (previous) {
      errors.push({
        file: path,
        line: name.line,
        message: `Duplicate identifier declaration '${name.value}' in the same lexical block (first declared on line ${previous.line}).`,
        autoRepairable: false,
      });
    } else {
      declarations.set(key, name);
    }
  }
}

function normalizeModulePath(path: string): string | undefined {
  if (!path || path.startsWith('/') || path.includes('\\') || path.includes('\0')) return undefined;
  const parts: string[] = [];
  for (const segment of path.split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') {
      if (parts.length === 0) return undefined;
      parts.pop();
    } else {
      parts.push(segment);
    }
  }
  return parts.join('/');
}

function resolveRelativeImport(importerPath: string, importPath: string, availablePaths: ReadonlySet<string>): boolean {
  if (!importPath.startsWith('./') && !importPath.startsWith('../')) return true;
  const directory = importerPath.includes('/') ? importerPath.slice(0, importerPath.lastIndexOf('/')) : '';
  const base = normalizeModulePath(directory ? `${directory}/${importPath}` : importPath);
  if (!base) return false;
  const candidates = new Set([base]);
  for (const extension of EXTENSIONS) candidates.add(`${base}${extension}`);
  for (const extension of EXTENSIONS) candidates.add(`${base}/index${extension}`);
  return [...candidates].some(candidate => availablePaths.has(candidate));
}

function addImportErrors(
  file: AnalyzerInputFile,
  tokens: readonly LexToken[],
  availablePaths: ReadonlySet<string>,
  errors: StaticSyntaxError[],
): void {
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token || token.kind !== 'identifier' || (token.value !== 'import' && token.value !== 'export')) continue;
    const next = tokens[index + 1];
    if (token.value === 'import' && next?.value === '(') continue;
    let sourceToken: LexToken | undefined;
    if (next?.kind === 'string') {
      sourceToken = next;
    } else {
      for (let cursor = index + 1; cursor < Math.min(tokens.length, index + 80); cursor += 1) {
        const candidate = tokens[cursor];
        if (!candidate) break;
        if (candidate.value === ';') break;
        if (candidate.kind === 'identifier' && candidate.value === 'from') {
          const value = tokens[cursor + 1];
          if (value?.kind === 'string') sourceToken = value;
          break;
        }
        if (cursor > index + 1 && candidate.line > token.line + 8) break;
      }
    }
    if (!sourceToken || sourceToken.value.length === 0) continue;
    const importPath = sourceToken.value;
    if (!resolveRelativeImport(file.path, importPath, availablePaths)) {
      errors.push({
        file: file.path,
        line: token.line,
        message: `Relative import '${importPath}' does not resolve to a file in the supplied workspace manifest.`,
        autoRepairable: false,
      });
    }
  }
}

function hasUseClientDirective(source: string): boolean {
  const prefix = source.slice(0, 2_048);
  return /^\s*(?:(?:\/\/[^\r\n]*(?:\r?\n|$))|(?:\/\*[\s\S]*?\*\/\s*))*["']use client["']\s*;?/m.test(prefix);
}

function analyzeFile(file: AnalyzerInputFile): FileAnalysis {
  const lineCount = file.content.length === 0 ? 0 : file.content.split(/\r\n|\r|\n/).length;
  const lexical = lexFile(file);
  addDeclarationErrors(file.path, lexical.tokens, lexical.errors);
  if (/\.(?:tsx|jsx)$/i.test(file.path) && !hasUseClientDirective(file.content)) {
    const hook = lexical.tokens.find(token => token.kind === 'identifier' && (token.value === 'useState' || token.value === 'useEffect'));
    if (hook) {
      lexical.errors.push({
        file: file.path,
        line: hook.line,
        message: 'Client React hook is used without a top-level "use client" directive.',
        autoRepairable: true,
      });
    }
  }
  return { file, lexical, lineCount };
}

/** Performs a bounded, dependency-free lexical/structural analysis; it does not execute or rewrite source. */
export function runAstStaticAnalyzerAgent(files: Array<{ path: string; language: string; content: string }>): {
  valid: boolean;
  syntaxErrors: Array<{ file: string; line: number; message: string; autoRepairable: boolean }>;
  metrics: { totalLines: number; complexityScore: number };
  stepTrace: AgentStepTrace;
} {
  const startedAt = Date.now();
  if (!Array.isArray(files) || files.length > MAX_FILE_COUNT) {
    throw new RangeError(`Static analysis accepts at most ${MAX_FILE_COUNT} files.`);
  }
  let totalChars = 0;
  for (const file of files) {
    if (
      typeof file?.path !== 'string' ||
      typeof file.language !== 'string' ||
      typeof file.content !== 'string' ||
      file.path.length > MAX_FILE_PATH_CHARS ||
      file.path.startsWith('/') ||
      file.path.includes('\\') ||
      file.path.split('/').some(segment => segment === '..' || segment === '.' || segment.length === 0)
    ) {
      throw new TypeError('Static analysis input contains an invalid relative path or file record.');
    }
    totalChars += file.content.length;
    if (totalChars > MAX_TOTAL_SOURCE_CHARS) {
      throw new RangeError(`Static analysis exceeds the ${MAX_TOTAL_SOURCE_CHARS}-character input limit.`);
    }
  }

  const availablePaths = new Set(files.map(file => file.path));
  const analyses = files.map(analyzeFile);
  const syntaxErrors = analyses.flatMap(analysis => analysis.lexical.errors);
  for (const analysis of analyses) {
    addImportErrors(analysis.file, analysis.lexical.tokens, availablePaths, syntaxErrors);
  }
  const totalLines = analyses.reduce((total, analysis) => total + analysis.lineCount, 0);
  const rawComplexity = analyses.reduce((total, analysis) => total + analysis.lexical.complexity, 0);
  const complexityScore = Math.max(0, Math.min(100, Math.round(rawComplexity / Math.max(1, analyses.length))));
  const completedAt = new Date().toISOString();
  const stepTrace: AgentStepTrace = {
    traceId: randomUUID(),
    operationId: randomUUID(),
    agentId: 'ast-static-analyzer-3',
    role: 'AST_ANALYZER',
    status: syntaxErrors.length === 0 ? 'SUCCEEDED' : 'FAILED',
    startedAt: new Date(startedAt).toISOString(),
    completedAt,
    inputSummary: `Analyzed ${files.length} files and ${totalLines} source lines without model calls.`,
    outputSummary: `Found ${syntaxErrors.length} diagnostics; complexity score ${complexityScore}.`,
    affectedPaths: files.map(file => file.path),
  };
  return {
    valid: syntaxErrors.length === 0,
    syntaxErrors,
    metrics: { totalLines, complexityScore },
    stepTrace,
  };
}