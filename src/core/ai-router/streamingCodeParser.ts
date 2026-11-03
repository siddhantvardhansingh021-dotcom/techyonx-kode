export interface ParsedVirtualFile {
  readonly path: string;
  readonly language: string;
  readonly content: string;
  readonly lineCount: number;
}

export interface ParsedCodeResponse {
  readonly files: ParsedVirtualFile[];
  readonly summary: string;
}

export interface ExtractedSurgicalPatch {
  readonly path?: string;
  readonly search: string;
  readonly replacement: string;
  readonly startLine: number;
  readonly endLine: number;
}

const MAX_RESPONSE_CHARS = 4_000_000;
const MAX_PATH_CHARS = 1_024;

const LANGUAGE_BY_EXTENSION: Readonly<Record<string, string>> = {
  c: 'c',
  cc: 'cpp',
  cpp: 'cpp',
  cs: 'csharp',
  css: 'css',
  go: 'go',
  h: 'c',
  hpp: 'cpp',
  html: 'html',
  java: 'java',
  js: 'javascript',
  jsx: 'javascriptreact',
  json: 'json',
  kt: 'kotlin',
  md: 'markdown',
  mjs: 'javascript',
  mts: 'typescript',
  py: 'python',
  rb: 'ruby',
  rs: 'rust',
  scss: 'scss',
  sh: 'shellscript',
  sql: 'sql',
  svelte: 'svelte',
  swift: 'swift',
  ts: 'typescript',
  tsx: 'typescriptreact',
  vue: 'vue',
  yml: 'yaml',
  yaml: 'yaml',
};

const LANGUAGE_ALIASES: Readonly<Record<string, string>> = {
  csharp: 'csharp',
  'c++': 'cpp',
  'c#': 'csharp',
  js: 'javascript',
  jsx: 'javascriptreact',
  md: 'markdown',
  py: 'python',
  sh: 'shellscript',
  ts: 'typescript',
  tsx: 'typescriptreact',
  yml: 'yaml',
};

interface ParsedFenceHeader {
  readonly language: string;
  readonly path?: string;
}

interface InternalFile {
  readonly path: string;
  readonly language: string;
  content: string;
}

function normalizeCandidatePath(candidate: string): string | undefined {
  let path = candidate.trim().replace(/^['"`]|['"`]$/g, '');
  path = path.replace(/^(?:file|path|filename)\s*[:=]\s*/i, '');
  path = path.replace(/^\.\//, '');
  if (
    path.length === 0 ||
    path.length > MAX_PATH_CHARS ||
    path.includes('\0') ||
    path.includes('\\') ||
    path.includes('//') ||
    path.startsWith('/') ||
    /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(path) ||
    /^[a-zA-Z]:/.test(path) ||
    path.split('/').some(segment => segment === '..' || segment === '.')
  ) {
    return undefined;
  }
  return path;
}

function pathFromHeader(header: string): string | undefined {
  const explicit = header.match(/(?:filename|file|path)\s*[:=]\s*([^\s,;]+)/i);
  if (explicit?.[1]) {
    return normalizeCandidatePath(explicit[1]);
  }

  const tokens = header.trim().split(/\s+/).filter(Boolean);
  const candidate = tokens.find(token =>
    token.includes('/') || /\.[a-zA-Z0-9]{1,12}$/.test(token),
  );
  return candidate ? normalizeCandidatePath(candidate.replace(/[,;]+$/, '')) : undefined;
}

function parseFenceHeader(header: string): ParsedFenceHeader {
  const path = pathFromHeader(header);
  const languageToken = header
    .replace(/(?:filename|file|path)\s*[:=]\s*[^\s,;]+/gi, '')
    .split(/\s+/)
    .find(token => token && token !== path);
  const normalizedLanguage = languageToken?.toLowerCase().replace(/^\./, '') ?? '';
  return {
    language: LANGUAGE_ALIASES[normalizedLanguage] ?? normalizedLanguage,
    ...(path ? { path } : {}),
  };
}

function languageFromPath(path: string, fallback: string): string {
  const fileName = path.split('/').at(-1) ?? path;
  const extension = fileName.includes('.') ? fileName.split('.').at(-1)?.toLowerCase() : undefined;
  return (extension && LANGUAGE_BY_EXTENSION[extension]) || fallback || 'plaintext';
}

function trimCodeBoundaryNewlines(content: string): string {
  return content.replace(/^(?:\r?\n)+/, '').replace(/(?:\r?\n)+$/, '');
}

function isFenceClose(line: string, fenceCharacter: string, fenceLength: number): boolean {
  const trimmed = line.trim();
  const match = trimmed.match(/^(`+|~+)\s*$/);
  return Boolean(
    match &&
    match[1] &&
    match[1][0] === fenceCharacter &&
    match[1].length >= fenceLength,
  );
}

function parseFileHeading(line: string): string | undefined {
  const match = line.match(/^\s{0,3}#{1,6}\s*(?:FILE|File)\s*:\s*(.*?)\s*#*\s*$/i);
  return match?.[1] ? normalizeCandidatePath(match[1]) : undefined;
}

function collectFiles(rawOutput: string): { files: InternalFile[]; summaryLines: string[] } {
  const lines = rawOutput.split(/\r?\n/);
  const filesByPath = new Map<string, InternalFile>();
  const summaryLines: string[] = [];
  let pendingPath: string | undefined;
  let activePatch = false;
  let fenceCharacter = '';
  let fenceLength = 0;
  let fenceHeader: ParsedFenceHeader | undefined;
  let codeLines: string[] = [];
  let inFence = false;

  const commitFence = (): void => {
    const content = trimCodeBoundaryNewlines(codeLines.join('\n'));
    const path = pendingPath ?? fenceHeader?.path;
    if (path && content.length > 0) {
      const language = languageFromPath(path, fenceHeader?.language ?? '');
      const previous = filesByPath.get(path);
      if (!previous) {
        filesByPath.set(path, { path, language, content });
      } else if (previous.content !== content && !previous.content.endsWith(content)) {
        previous.content = `${previous.content}\n${content}`;
      }
    }
    pendingPath = undefined;
    codeLines = [];
    fenceHeader = undefined;
  };

  for (const line of lines) {
    if (inFence) {
      if (isFenceClose(line, fenceCharacter, fenceLength)) {
        commitFence();
        inFence = false;
      } else {
        codeLines.push(line);
      }
      continue;
    }

    if (activePatch) {
      if (/^\s*>>>>>>>\s*REPLACE\s*$/.test(line)) {
        activePatch = false;
      }
      continue;
    }
    if (/^\s*<<<<<<<\s*SEARCH\s*$/.test(line)) {
      activePatch = true;
      continue;
    }

    const headingPath = parseFileHeading(line);
    if (headingPath) {
      pendingPath = headingPath;
      continue;
    }

    const fenceStart = line.match(/^\s{0,3}(`{3,}|~{3,})(.*)$/);
    if (fenceStart?.[1]) {
      fenceCharacter = fenceStart[1][0] ?? '`';
      fenceLength = fenceStart[1].length;
      fenceHeader = parseFenceHeader(fenceStart[2] ?? '');
      inFence = true;
      continue;
    }

    summaryLines.push(line);
  }

  if (inFence) {
    commitFence();
  }

  return { files: [...filesByPath.values()], summaryLines };
}

function cleanSummary(lines: readonly string[]): string {
  const boilerplate = /^(?:sure[,!:. ]*|certainly[,!:. ]*|here(?:'s| is)\b|below is\b|i(?:'ve| have)\s+(?:created|updated|implemented|generated)\b|this (?:is|implements) the (?:requested|updated)\b)/i;
  return lines
    .map(line => line.trim())
    .filter(line => line.length > 0 && !boilerplate.test(line))
    .join('\n')
    .trim();
}

/** Parses named Markdown code blocks into path-safe file snapshots and retains non-code summary text. */
export function parseMultiFileCodeResponse(rawOutput: string): {
  files: Array<{ path: string; language: string; content: string; lineCount: number }>;
  summary: string;
} {
  if (typeof rawOutput !== 'string') {
    throw new TypeError('Model output must be a string.');
  }
  if (rawOutput.length > MAX_RESPONSE_CHARS) {
    throw new RangeError(`Model output exceeds the ${MAX_RESPONSE_CHARS}-character parsing limit.`);
  }

  const { files, summaryLines } = collectFiles(rawOutput);
  return {
    files: files.map(file => ({
      path: file.path,
      language: file.language,
      content: file.content,
      lineCount: file.content.length === 0 ? 0 : file.content.split(/\r\n|\r|\n/).length,
    })),
    summary: cleanSummary(summaryLines),
  };
}

/** Extracts SEARCH/REPLACE patch blocks without applying them to workspace content. */
export function extractSurgicalPatches(rawOutput: string): ExtractedSurgicalPatch[] {
  if (typeof rawOutput !== 'string') {
    throw new TypeError('Model output must be a string.');
  }
  if (rawOutput.length > MAX_RESPONSE_CHARS) {
    throw new RangeError(`Model output exceeds the ${MAX_RESPONSE_CHARS}-character parsing limit.`);
  }

  const lines = rawOutput.split(/\r?\n/);
  const patches: ExtractedSurgicalPatch[] = [];
  let activePath: string | undefined;
  let index = 0;

  while (index < lines.length) {
    const headingPath = parseFileHeading(lines[index] ?? '');
    if (headingPath) {
      activePath = headingPath;
      index += 1;
      continue;
    }
    if (!/^\s*<<<<<<<\s*SEARCH\s*$/.test(lines[index] ?? '')) {
      index += 1;
      continue;
    }

    const startLine = index + 1;
    index += 1;
    const searchLines: string[] = [];
    while (index < lines.length && !/^\s*=======\s*$/.test(lines[index] ?? '')) {
      searchLines.push(lines[index] ?? '');
      index += 1;
    }
    if (index >= lines.length) {
      break;
    }

    index += 1;
    const replacementLines: string[] = [];
    while (index < lines.length && !/^\s*>>>>>>>\s*REPLACE\s*$/.test(lines[index] ?? '')) {
      replacementLines.push(lines[index] ?? '');
      index += 1;
    }
    if (index >= lines.length) {
      break;
    }

    const endLine = index + 1;
    const search = trimCodeBoundaryNewlines(searchLines.join('\n'));
    const replacement = trimCodeBoundaryNewlines(replacementLines.join('\n'));
    patches.push({
      ...(activePath ? { path: activePath } : {}),
      search,
      replacement,
      startLine,
      endLine,
    });
    index += 1;
  }

  return patches;
}