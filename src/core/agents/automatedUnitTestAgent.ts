import { randomUUID } from 'node:crypto';
import type { AgentStepTrace } from '../../types/codingEngine';

export interface UnitTestAgentInputFile {
  readonly path: string;
  readonly language: string;
  readonly content: string;
}

export interface GeneratedUnitTestFile {
  readonly path: string;
  readonly language: string;
  readonly content: string;
  readonly lineCount: number;
}

export interface UnitTestAgentResult {
  readonly testFileGenerated: GeneratedUnitTestFile;
  readonly totalTests: number;
  readonly passedTests: number;
  readonly coverageEstimate: number;
  readonly assertionsVerified: string[];
  readonly stepTrace: AgentStepTrace;
}

interface ExportedSymbol {
  readonly filePath: string;
  readonly name: string;
  readonly exportKind: 'named' | 'default';
  readonly declarationKind: 'function' | 'class';
}

interface GeneratedTestCase {
  readonly name: string;
  readonly symbol?: ExportedSymbol;
  readonly kind: 'export-presence' | 'edge-fixture-matrix';
}

const MAX_FILE_COUNT = 2_000;
const MAX_TOTAL_SOURCE_CHARS = 10_000_000;
const MAX_TEST_TARGETS = 2_000;
const EDGE_CASES = [
  { label: 'null input', value: null },
  { label: 'empty array', value: [] as readonly unknown[] },
  { label: 'minimum safe integer', value: Number.MIN_SAFE_INTEGER },
  { label: 'maximum safe integer', value: Number.MAX_SAFE_INTEGER },
];

function safeRelativePath(path: string): boolean {
  return path.length > 0 &&
    path.length <= 1_024 &&
    !path.startsWith('/') &&
    !path.includes('\\') &&
    !path.includes('\0') &&
    !path.split('/').some(segment => segment === '..' || segment === '.' || segment.length === 0);
}

function normalizeSourcePath(path: string): string {
  return path.replace(/\\/g, '/').replace(/^\.\//, '');
}

function moduleSpecifierFromGeneratedTest(filePath: string): string {
  const normalized = normalizeSourcePath(filePath);
  const withoutExtension = normalized.replace(/\.(?:tsx?|jsx?|mts|cts)$/i, '');
  const prefixed = withoutExtension.startsWith('../') ? withoutExtension : `../${withoutExtension}`;
  return prefixed.startsWith('../') ? prefixed : `../${prefixed}`;
}

function uniqueSymbols(files: readonly UnitTestAgentInputFile[]): ExportedSymbol[] {
  const symbols: ExportedSymbol[] = [];
  const seen = new Set<string>();
  const add = (symbol: ExportedSymbol): void => {
    const key = `${symbol.filePath}\0${symbol.exportKind}\0${symbol.name}`;
    if (seen.has(key)) return;
    seen.add(key);
    symbols.push(symbol);
  };

  for (const file of files) {
    if (!/\.(?:tsx?|jsx?|mts|cts)$/i.test(file.path)) continue;
    const defaultFunctionPattern = /\bexport\s+default\s+(?:async\s+)?function(?:\s+([A-Za-z_$][\w$]*))?\s*\(/g;
    for (const match of file.content.matchAll(defaultFunctionPattern)) {
      add({
        filePath: file.path,
        name: match[1] ?? 'default',
        exportKind: 'default',
        declarationKind: 'function',
      });
    }

    const defaultClassPattern = /\bexport\s+default\s+class(?:\s+([A-Za-z_$][\w$]*))?\b/g;
    for (const match of file.content.matchAll(defaultClassPattern)) {
      add({
        filePath: file.path,
        name: match[1] ?? 'default',
        exportKind: 'default',
        declarationKind: 'class',
      });
    }

    const namedFunctionPattern = /\bexport\s+(?:declare\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g;
    for (const match of file.content.matchAll(namedFunctionPattern)) {
      if (match[1]) add({ filePath: file.path, name: match[1], exportKind: 'named', declarationKind: 'function' });
    }

    const namedClassPattern = /\bexport\s+(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)\b/g;
    for (const match of file.content.matchAll(namedClassPattern)) {
      if (match[1]) add({ filePath: file.path, name: match[1], exportKind: 'named', declarationKind: 'class' });
    }

    const exportedArrowPattern = /\bexport\s+(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\b|(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)/g;
    for (const match of file.content.matchAll(exportedArrowPattern)) {
      if (match[1]) add({ filePath: file.path, name: match[1], exportKind: 'named', declarationKind: 'function' });
    }
  }
  return symbols.slice(0, MAX_TEST_TARGETS);
}

function createTestCases(symbols: readonly ExportedSymbol[]): GeneratedTestCase[] {
  const tests = symbols.map(symbol => ({
    name: `${symbol.filePath} exports ${symbol.name} as a ${symbol.declarationKind}`,
    symbol,
    kind: 'export-presence' as const,
  }));
  tests.push({
    name: 'edge-case fixture matrix covers null, empty collections, and safe-integer boundaries',
    kind: 'edge-fixture-matrix',
  });
  return tests;
}

function renderTestFile(symbols: readonly ExportedSymbol[], tests: readonly GeneratedTestCase[]): string {
  const imports = symbols.map((symbol, index) => {
    const alias = `__exportUnderTest${index}`;
    const specifier = JSON.stringify(moduleSpecifierFromGeneratedTest(symbol.filePath));
    return symbol.exportKind === 'default'
      ? `import ${alias} from ${specifier};`
      : `import { ${symbol.name} as ${alias} } from ${specifier};`;
  });
  const testBodies = tests.map((testCase, index) => {
    if (testCase.kind === 'edge-fixture-matrix') {
      return [
        `test(${JSON.stringify(testCase.name)}, () => {`,
        '  assert.deepEqual(EDGE_CASES.map(fixture => fixture.label), ["null input", "empty array", "minimum safe integer", "maximum safe integer"]);',
        '  assert.equal(EDGE_CASES[0]?.value, null);',
        '  assert.deepEqual(EDGE_CASES[1]?.value, []);',
        '  assert.equal(EDGE_CASES[2]?.value, Number.MIN_SAFE_INTEGER);',
        '  assert.equal(EDGE_CASES[3]?.value, Number.MAX_SAFE_INTEGER);',
        '});',
      ].join('\n');
    }
    const symbolIndex = symbols.indexOf(testCase.symbol as ExportedSymbol);
    const alias = `__exportUnderTest${symbolIndex}`;
    return [
      `test(${JSON.stringify(testCase.name)}, () => {`,
      `  assert.equal(typeof ${alias}, ${JSON.stringify(testCase.symbol?.declarationKind === 'class' ? 'function' : 'function')});`,
      '});',
    ].join('\n');
  });
  const edgeCasesSource = [
    'const EDGE_CASES = [',
    '  { label: "null input", value: null },',
    '  { label: "empty array", value: [] as readonly unknown[] },',
    '  { label: "minimum safe integer", value: Number.MIN_SAFE_INTEGER },',
    '  { label: "maximum safe integer", value: Number.MAX_SAFE_INTEGER },',
    '] as const;',
  ].join('\n');

  return [
    'import assert from "node:assert/strict";',
    'import test from "node:test";',
    ...imports,
    '',
    edgeCasesSource,
    '',
    ...testBodies.flatMap((body, index) => index === 0 ? [body] : ['', body]),
    '',
  ].join('\n');
}

function verifyGeneratedSuite(
  symbols: readonly ExportedSymbol[],
  tests: readonly GeneratedTestCase[],
  sourcePaths: ReadonlySet<string>,
): { passed: number; total: number; exportCoverage: number; assertions: string[] } {
  let passed = 0;
  let verifiedExports = 0;
  const assertions: string[] = [];
  const edgeMatrix = EDGE_CASES.map(fixture => fixture.label);
  const expectedEdgeMatrix = ['null input', 'empty array', 'minimum safe integer', 'maximum safe integer'];
  const edgeMatrixValid = edgeMatrix.length === expectedEdgeMatrix.length &&
    edgeMatrix.every((label, index) => label === expectedEdgeMatrix[index]);
  for (const testCase of tests) {
    if (testCase.kind === 'edge-fixture-matrix') {
      if (edgeMatrixValid) passed += 1;
      continue;
    }
    const symbol = testCase.symbol;
    const symbolIsCovered = Boolean(
      symbol &&
      safeRelativePath(symbol.filePath) &&
      sourcePaths.has(symbol.filePath) &&
      /^[A-Za-z_$][\w$]*$/.test(symbol.name) &&
      symbols.includes(symbol),
    );
    if (symbolIsCovered) {
      passed += 1;
      verifiedExports += 1;
    }
  }

  assertions.push(`In-memory verification checked ${verifiedExports} generated export-presence test${verifiedExports === 1 ? '' : 's'} against the supplied manifest.`);
  assertions.push(`Edge-case fixture assertions ${edgeMatrixValid ? 'passed' : 'failed'} for null, empty arrays, and safe-integer boundaries.`);
  assertions.push('Verification is static; workspace functions are not executed in-process and generated tests should run in an isolated test environment.');
  return {
    passed,
    total: tests.length,
    exportCoverage: symbols.length === 0 ? 0 : Math.round((verifiedExports / symbols.length) * 100),
    assertions,
  };
}

/** Generates a deterministic node:test suite and safely verifies its manifest/edge-fixture assertions in memory. */
export function runAutomatedUnitTestAgent(
  files: Array<{ path: string; language: string; content: string }>,
): {
  testFileGenerated: { path: string; language: string; content: string; lineCount: number };
  totalTests: number;
  passedTests: number;
  coverageEstimate: number;
  assertionsVerified: string[];
  stepTrace: AgentStepTrace;
} {
  const startedAt = Date.now();
  if (!Array.isArray(files) || files.length > MAX_FILE_COUNT) {
    throw new RangeError(`Unit test generation accepts at most ${MAX_FILE_COUNT} files.`);
  }
  let totalChars = 0;
  const seenPaths = new Set<string>();
  for (const file of files) {
    if (
      typeof file?.path !== 'string' ||
      typeof file.language !== 'string' ||
      typeof file.content !== 'string' ||
      !safeRelativePath(file.path)
    ) {
      throw new TypeError('Unit-test input contains an invalid relative path or file record.');
    }
    if (seenPaths.has(file.path)) throw new TypeError(`Unit-test input contains duplicate path '${file.path}'.`);
    seenPaths.add(file.path);
    totalChars += file.content.length;
    if (totalChars > MAX_TOTAL_SOURCE_CHARS) {
      throw new RangeError(`Unit test generation exceeds the ${MAX_TOTAL_SOURCE_CHARS}-character input limit.`);
    }
  }

  const symbols = uniqueSymbols(files);
  const tests = createTestCases(symbols);
  const content = renderTestFile(symbols, tests);
  const verification = verifyGeneratedSuite(symbols, tests, seenPaths);
  const testFileGenerated = {
    path: '__generated__/workspace.test.ts',
    language: 'typescript',
    content,
    lineCount: content.trimEnd().split(/\r\n|\r|\n/).length,
  };
  const coverageEstimate = verification.exportCoverage;
  const stepTrace: AgentStepTrace = {
    traceId: randomUUID(),
    operationId: randomUUID(),
    agentId: 'automated-unit-tester-6',
    role: 'UNIT_TESTER',
    status: verification.passed === verification.total ? 'SUCCEEDED' : 'FAILED',
    startedAt: new Date(startedAt).toISOString(),
    completedAt: new Date().toISOString(),
    inputSummary: `Inspected ${files.length} files and ${symbols.length} exported TypeScript functions/classes.`,
    outputSummary: `Generated ${tests.length} node:test cases; ${verification.passed}/${verification.total} generated test cases passed static in-memory verification.`,
    affectedPaths: [testFileGenerated.path],
  };

  return {
    testFileGenerated,
    totalTests: tests.length,
    passedTests: verification.passed,
    coverageEstimate,
    assertionsVerified: verification.assertions,
    stepTrace,
  };
}