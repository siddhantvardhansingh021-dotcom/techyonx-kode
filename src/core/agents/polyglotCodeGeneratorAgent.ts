import { randomUUID } from 'node:crypto';
import type { AgentStepTrace, TokenUsage } from '../../types/codingEngine';
import { executeUniversalAICall, type UniversalAICallResult } from '../ai-router/universalModelAdapter';
import { parseMultiFileCodeResponse } from '../ai-router/streamingCodeParser';
import { inspectCodingPromptSecurity } from '../security/codeInjectionFirewall';
import { scanForMaliciousCode } from '../security/maliciousCodeDetector';
import { scrubHardcodedSecrets } from '../security/secretLeakPrevention';
import { enforcePrivacyComplianceInCode } from '../compliance/dpdpGdprCodeCompliance';
import {
  createRequirementBlueprint,
  parseRequirementBlueprint,
  type ArchitectPlannedFile,
  type RequirementArchitectureBlueprint,
} from './requirementArchitectAgent';

export interface GeneratedCodeFile {
  readonly path: string;
  readonly language: string;
  readonly content: string;
  readonly lineCount: number;
}

export interface PolyglotCodeGeneratorResult {
  readonly files: GeneratedCodeFile[];
  readonly tokensUsed: number;
  readonly provider: string;
  readonly modelUsed: string;
  readonly stepTrace: AgentStepTrace;
}

interface ExistingFile {
  readonly path: string;
  readonly content: string;
}

interface TemplateContext {
  readonly blueprint: RequirementArchitectureBlueprint;
  readonly userPrompt: string;
}

const MAX_PROMPT_CHARS = 100_000;
const MAX_PLANNED_FILES = 100;
const MAX_EXISTING_FILES = 100;
const MAX_EXISTING_SOURCE_CHARS = 500_000;
const MAX_MODEL_OUTPUT_CHARS = 4_000_000;
const PLACEHOLDER_PATTERN = /\b(?:TODO|FIXME|PLACEHOLDER|TBD)\b|<your\s+(?:api|secret|key|value|domain)[^>]*>/i;

const LANGUAGE_BY_EXTENSION: Readonly<Record<string, string>> = {
  css: 'css',
  go: 'go',
  html: 'html',
  js: 'javascript',
  json: 'json',
  md: 'markdown',
  py: 'python',
  rs: 'rust',
  sql: 'sql',
  toml: 'toml',
  ts: 'typescript',
  tsx: 'typescriptreact',
  yml: 'yaml',
  yaml: 'yaml',
};

function safeRelativePath(path: string): boolean {
  return path.length > 0 &&
    path.length <= 1_024 &&
    enforcePrivacyComplianceInCode(path).piiRedactedCount === 0 &&
    !path.startsWith('/') &&
    !path.includes('\\') &&
    !path.includes('\0') &&
    !path.includes('//') &&
    !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(path) &&
    !path.split('/').some(segment => segment === '..' || segment === '.' || segment.length === 0);
}

function preferenceFromUnknown(value: unknown): string {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return '';
  }
  const record = value as Record<string, unknown>;
  if (typeof record['stackPreference'] === 'string') {
    return record['stackPreference'].slice(0, 256);
  }
  if (Array.isArray(record['targetTechStack'])) {
    return record['targetTechStack']
      .filter((item): item is string => typeof item === 'string')
      .join(', ')
      .slice(0, 256);
  }
  if (typeof record['blueprintSummary'] === 'string') {
    return record['blueprintSummary'].slice(0, 256);
  }
  return '';
}

function normalizeBlueprint(
  userPrompt: string,
  source: unknown,
): RequirementArchitectureBlueprint {
  const parsed = parseRequirementBlueprint(source);
  if (parsed) {
    return parsed;
  }

  const fallback = createRequirementBlueprint(userPrompt, preferenceFromUnknown(source));
  if (typeof source !== 'object' || source === null || Array.isArray(source)) {
    return fallback;
  }

  const record = source as Record<string, unknown>;
  const rawFiles = record['plannedFiles'];
  if (!Array.isArray(rawFiles) || rawFiles.length === 0 || rawFiles.length > MAX_PLANNED_FILES) {
    return fallback;
  }
  const plannedFiles: ArchitectPlannedFile[] = [];
  for (const candidate of rawFiles) {
    if (typeof candidate !== 'object' || candidate === null || Array.isArray(candidate)) {
      return fallback;
    }
    const file = candidate as Record<string, unknown>;
    if (
      typeof file['path'] !== 'string' ||
      !safeRelativePath(file['path']) ||
      typeof file['responsibility'] !== 'string' ||
      file['responsibility'].length > 2_000
    ) {
      return fallback;
    }
    plannedFiles.push({ path: file['path'], responsibility: file['responsibility'] });
  }

  const uniqueFiles = new Map(plannedFiles.map(file => [file.path, file]));
  return {
    ...fallback,
    ...(typeof record['projectTitle'] === 'string' ? { projectTitle: record['projectTitle'].slice(0, 200) } : {}),
    plannedFiles: [...uniqueFiles.values()],
  };
}

function normalizeExistingFiles(files: readonly ExistingFile[] | undefined): ExistingFile[] {
  if (!files) return [];
  if (!Array.isArray(files) || files.length > MAX_EXISTING_FILES) {
    throw new RangeError(`Existing-file context accepts at most ${MAX_EXISTING_FILES} files.`);
  }
  let totalChars = 0;
  const normalized: ExistingFile[] = [];
  for (const file of files) {
    if (typeof file?.path !== 'string' || typeof file.content !== 'string' || !safeRelativePath(file.path)) {
      throw new TypeError('Existing-file context contains an invalid relative path or content value.');
    }
    totalChars += file.content.length;
    if (totalChars > MAX_EXISTING_SOURCE_CHARS) {
      throw new RangeError(`Existing-file context exceeds the ${MAX_EXISTING_SOURCE_CHARS}-character limit.`);
    }
    normalized.push({ path: file.path, content: file.content });
  }
  return normalized;
}

function languageForPath(path: string): string {
  const baseName = path.split('/').at(-1) ?? path;
  if (baseName === 'Dockerfile') return 'dockerfile';
  if (baseName === '.env.example') return 'dotenv';
  const extension = baseName.split('.').at(-1)?.toLowerCase() ?? '';
  return LANGUAGE_BY_EXTENSION[extension] ?? 'plaintext';
}

function countLines(content: string): number {
  if (content.length === 0) return 0;
  const lines = content.replace(/\r\n?/g, '\n').split('\n');
  return lines.length - (lines.at(-1) === '' ? 1 : 0);
}

function jsonString(value: string): string {
  return JSON.stringify(value);
}

function metricCardTemplate(): string {
  return [
    "import type { DashboardMetric } from '../lib/dashboard-data';",
    '',
    'interface MetricCardProps {',
    '  readonly metric: DashboardMetric;',
    '}',
    '',
    'export function MetricCard({ metric }: MetricCardProps) {',
    '  const trendColor = metric.trend === "up" ? "text-emerald-700" : "text-rose-700";',
    '  return (',
    '    <article className="min-w-0 border border-slate-200 bg-white p-5 shadow-sm">',
    '      <p className="text-sm font-medium text-slate-600">{metric.label}</p>',
    '      <p className="mt-3 truncate text-2xl font-semibold tracking-normal text-slate-950">{metric.value}</p>',
    '      <p className={`mt-2 text-sm font-medium ${trendColor}`}>{metric.change} vs. prior period</p>',
    '    </article>',
    '  );',
    '}',
  ].join('\n');
}

function analyticsChartTemplate(): string {
  return [
    'export interface SeriesPoint {',
    '  readonly label: string;',
    '  readonly value: number;',
    '}',
    '',
    'interface AnalyticsChartProps {',
    '  readonly data: readonly SeriesPoint[];',
    '  readonly label: string;',
    '}',
    '',
    'export function AnalyticsChart({ data, label }: AnalyticsChartProps) {',
    '  const maximum = Math.max(1, ...data.map(point => Math.max(0, point.value)));',
    '  return (',
    '    <figure className="border border-slate-200 bg-white p-5 shadow-sm">',
    '      <figcaption className="mb-5 text-sm font-semibold text-slate-900">{label}</figcaption>',
    '      <div role="img" aria-label={label} className="flex h-48 items-end gap-3 border-b border-l border-slate-200 px-2">',
    '        {data.map(point => {',
    '          const height = Math.max(4, Math.round((Math.max(0, point.value) / maximum) * 100));',
    '          return (',
    '            <div key={point.label} className="flex h-full min-w-0 flex-1 flex-col justify-end">',
    '              <div className="w-full bg-teal-700" style={{ height: `${height}%` }} title={`${point.label}: ${point.value}`} />',
    '              <span className="mt-2 truncate text-center text-xs text-slate-600">{point.label}</span>',
    '            </div>',
    '          );',
    '        })}',
    '      </div>',
    '    </figure>',
    '  );',
    '}',
  ].join('\n');
}

function nextPageTemplate(context: TemplateContext): string {
  if (context.blueprint.featureSignals.dashboard) {
    return [
      "import { AnalyticsChart } from '../components/AnalyticsChart';",
      "import { MetricCard } from '../components/MetricCard';",
      "import { dashboardMetrics, revenueSeries } from '../lib/dashboard-data';",
      '',
      'export default function HomePage() {',
      '  return (',
      '    <main className="min-h-screen bg-slate-50 text-slate-950">',
      '      <div className="mx-auto max-w-7xl px-5 py-8 sm:px-8">',
      '        <header className="flex flex-wrap items-end justify-between gap-4 border-b border-slate-200 pb-6">',
      `          <div><p className="text-sm font-semibold uppercase tracking-wide text-teal-800">${context.blueprint.featureSignals.finance ? 'Finance' : 'Analytics'} workspace</p><h1 className="mt-2 text-3xl font-semibold">{${jsonString(context.blueprint.projectTitle)}}</h1></div>`,
      '          <p className="text-sm text-slate-600">Updated from deterministic demo data</p>',
      '        </header>',
      '        <section aria-label="Key metrics" className="mt-7 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">',
      '          {dashboardMetrics.map(metric => <MetricCard key={metric.label} metric={metric} />)}',
      '        </section>',
      '        <section className="mt-7 grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(16rem,1fr)]">',
      '          <AnalyticsChart data={revenueSeries} label="Monthly activity" />',
      '          <aside className="border border-slate-200 bg-white p-5 shadow-sm">',
      '            <h2 className="text-base font-semibold">Operational notes</h2>',
      '            <p className="mt-3 text-sm leading-6 text-slate-600">Sample values are local demo data. Connect an authenticated data source before using this workspace for financial decisions.</p>',
      '          </aside>',
      '        </section>',
      '      </div>',
      '    </main>',
      '  );',
      '}',
    ].join('\n');
  }
  return [
    'export default function HomePage() {',
    '  return (',
    '    <main className="mx-auto min-h-screen max-w-5xl px-6 py-12">',
    `      <p className="text-sm font-semibold text-teal-800">Techyonx kode workspace</p><h1 className="mt-3 text-3xl font-semibold text-slate-950">{${jsonString(context.blueprint.projectTitle)}}</h1>`,
    `      <p className="mt-4 max-w-2xl text-base leading-7 text-slate-600">{${jsonString(context.blueprint.requestSummary)}}</p>`,
    '      <section className="mt-8 border border-slate-200 bg-white p-6">',
    '        <h2 className="text-lg font-semibold">Workspace status</h2>',
    '        <p className="mt-2 text-sm text-slate-600">The application shell is ready for its typed feature modules and validated data contracts.</p>',
    '      </section>',
    '    </main>',
    '  );',
    '}',
  ].join('\n');
}

function templateForFile(file: ArchitectPlannedFile, context: TemplateContext): string {
  const { path } = file;
  const profile = context.blueprint.stackProfile;

  if (profile === 'NEXTJS') {
    switch (path) {
      case 'README.md':
        return `# ${context.blueprint.projectTitle}\n\n${context.blueprint.requestSummary}\n\n## Local setup\n\nUse Node.js 20 or newer. Install the exact dependencies in package.json, then run npm run dev. Configure only the server-side variables listed in .env.example.\n\n## Data and security\n\nThe initial dashboard uses deterministic demonstration data. It is not connected to a bank, payment processor, or production identity provider. Add an audited server-side integration before using real personal or financial data. Validate every API input, enforce authorization on the server, and never commit populated environment files.\n`;
      case 'package.json':
        return JSON.stringify({
          name: 'techyonx-kode-generated-app',
          version: '1.0.0',
          private: true,
          scripts: { dev: 'next dev', build: 'next build', start: 'next start', typecheck: 'tsc --noEmit', test: 'vitest run' },
          dependencies: { next: '15.2.4', react: '19.0.0', 'react-dom': '19.0.0', 'lucide-react': '0.468.0' },
          devDependencies: { '@tailwindcss/postcss': '4.0.0', '@types/node': '22.13.4', '@types/react': '19.0.8', '@types/react-dom': '19.0.3', postcss: '8.5.1', tailwindcss: '4.0.0', typescript: '5.7.3', vitest: '3.0.5' },
        }, null, 2);
      case 'tsconfig.json':
        return JSON.stringify({
          compilerOptions: {
            target: 'ES2022', lib: ['dom', 'dom.iterable', 'esnext'], allowJs: false, skipLibCheck: true,
            strict: true, noUncheckedIndexedAccess: true, exactOptionalPropertyTypes: true,
            noEmit: true, esModuleInterop: true, module: 'esnext', moduleResolution: 'bundler',
            resolveJsonModule: true, isolatedModules: true, jsx: 'preserve', incremental: true,
            plugins: [{ name: 'next' }], paths: { '@/*': ['./src/*'] },
          },
          include: ['next-env.d.ts', '.next/types/**/*.ts', '**/*.ts', '**/*.tsx'],
          exclude: ['node_modules'],
        }, null, 2);
      case 'next.config.ts':
        return [
          "import type { NextConfig } from 'next';",
          '',
          'const nextConfig: NextConfig = {',
          '  poweredByHeader: false,',
          '  reactStrictMode: true,',
          '  async headers() {',
          '    return [{',
          '      source: "/:path*",',
          '      headers: [',
          '        { key: "X-Content-Type-Options", value: "nosniff" },',
          '        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },',
          '        { key: "X-Frame-Options", value: "DENY" },',
          '        { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },',
          '      ],',
          '    }];',
          '  },',
          '};',
          '',
          'export default nextConfig;',
        ].join('\n');
      case 'postcss.config.mjs':
        return [
          'const config = { plugins: { "@tailwindcss/postcss": {} } };',
          'export default config;',
        ].join('\n');
      case 'src/app/layout.tsx':
        return [
          "import type { Metadata } from 'next';",
          "import type { ReactNode } from 'react';",
          "import './globals.css';",
          '',
          `export const metadata: Metadata = { title: ${jsonString(context.blueprint.projectTitle)}, description: ${jsonString(context.blueprint.requestSummary.slice(0, 160))} };`,
          '',
          'export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {',
          '  return <html lang="en"><body>{children}</body></html>;',
          '}',
        ].join('\n');
      case 'src/app/page.tsx':
        return nextPageTemplate(context);
      case 'src/app/globals.css':
        return [
          '@import "tailwindcss";',
          '',
          ':root { color-scheme: light; background: #f8fafc; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }',
          '* { box-sizing: border-box; }',
          'body { margin: 0; min-height: 100vh; }',
          'button, a { -webkit-tap-highlight-color: transparent; }',
          ':focus-visible { outline: 3px solid #0f766e; outline-offset: 3px; }',
        ].join('\n');
      case 'src/lib/formatters.ts':
        return [
          'export function formatCurrency(amountMinor: number, currency = "INR", locale = "en-IN"): string {',
          '  if (!Number.isSafeInteger(amountMinor)) throw new TypeError("Currency amount must be a safe integer in minor units.");',
          '  return new Intl.NumberFormat(locale, { style: "currency", currency, maximumFractionDigits: 2 }).format(amountMinor / 100);',
          '}',
          '',
          'export function formatCompactNumber(value: number, locale = "en-IN"): string {',
          '  if (!Number.isFinite(value)) throw new TypeError("Metric value must be finite.");',
          '  return new Intl.NumberFormat(locale, { notation: "compact", maximumFractionDigits: 1 }).format(value);',
          '}',
          '',
          'export function formatDate(value: string, locale = "en-IN"): string {',
          '  const date = new Date(value);',
          '  if (Number.isNaN(date.getTime())) throw new TypeError("Date value is invalid.");',
          '  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeZone: "UTC" }).format(date);',
          '}',
        ].join('\n');
      case 'src/components/MetricCard.tsx':
        return metricCardTemplate();
      case 'src/components/AnalyticsChart.tsx':
        return analyticsChartTemplate();
      case 'src/lib/dashboard-data.ts':
        return [
          'export interface DashboardMetric {',
          '  readonly label: string;',
          '  readonly value: string;',
          '  readonly change: string;',
          '  readonly trend: "up" | "down";',
          '}',
          '',
          'export const dashboardMetrics: readonly DashboardMetric[] = [',
          '  { label: "Processed volume", value: "₹ 24.7M", change: "+8.2%", trend: "up" },',
          '  { label: "Settled transactions", value: "18,420", change: "+4.6%", trend: "up" },',
          '  { label: "Pending review", value: "126", change: "-2.1%", trend: "down" },',
          '  { label: "Reconciliation rate", value: "99.4%", change: "+0.7%", trend: "up" },',
          '];',
          '',
          'export const revenueSeries = [',
          '  { label: "Jan", value: 42 }, { label: "Feb", value: 56 }, { label: "Mar", value: 49 },',
          '  { label: "Apr", value: 68 }, { label: "May", value: 74 }, { label: "Jun", value: 63 },',
          '  { label: "Jul", value: 81 }, { label: "Aug", value: 88 }, { label: "Sep", value: 76 },',
          '  { label: "Oct", value: 94 }, { label: "Nov", value: 86 }, { label: "Dec", value: 100 },',
          '] as const;',
        ].join('\n');
      case 'src/app/api/health/route.ts':
        return [
          'export const dynamic = "force-dynamic";',
          '',
          'export function GET(): Response {',
          '  return Response.json({ status: "ok", service: "techyonx-kode-app" }, {',
          '    headers: { "Cache-Control": "no-store" },',
          '  });',
          '}',
        ].join('\n');
      case 'src/app/api/metrics/route.ts':
        return [
          ...(context.blueprint.featureSignals.authentication
            ? ['import { readSession } from "../../../lib/auth/session";', '']
            : []),
          'import { dashboardMetrics, revenueSeries } from "../../../lib/dashboard-data";',
          '',
          'export const dynamic = "force-dynamic";',
          '',
          'export function GET(request: Request): Response {',
          ...(context.blueprint.featureSignals.authentication
            ? ['  if (!readSession(request)) return Response.json({ error: "unauthorized" }, { status: 401 });']
            : []),
          '  return Response.json({ metrics: dashboardMetrics, activity: revenueSeries }, {',
          '    headers: { "Cache-Control": "private, no-store" },',
          '  });',
          '}',
        ].join('\n');
      case 'src/lib/auth/session.ts':
        return [
          'import { createHmac, timingSafeEqual } from "node:crypto";',
          '',
          'export interface SessionClaims { readonly subject: string; readonly expiresAt: number; readonly roles: readonly string[]; }',
          'const COOKIE_NAME = "txk_session";',
          '',
          'function signingKey(): Buffer {',
          '  const secret = process.env.SESSION_SIGNING_KEY ?? "";',
          '  const key = Buffer.from(secret, "utf8");',
          '  if (key.length < 32) throw new Error("SESSION_SIGNING_KEY must contain at least 32 bytes.");',
          '  return key;',
          '}',
          '',
          'function signature(payload: string, key: Buffer): Buffer {',
          '  return createHmac("sha256", key).update(payload).digest();',
          '}',
          '',
          'export function createSessionToken(claims: SessionClaims): string {',
          '  if (!claims.subject || !Number.isSafeInteger(claims.expiresAt) || claims.expiresAt <= Date.now()) throw new TypeError("Session claims are invalid.");',
          '  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");',
          '  const key = signingKey();',
          '  try { return `${payload}.${signature(payload, key).toString("base64url")}`; } finally { key.fill(0); }',
          '}',
          '',
          'export function readSession(request: Request): SessionClaims | null {',
          '  const cookie = request.headers.get("cookie")?.split(";").map(part => part.trim()).find(part => part.startsWith(`${COOKIE_NAME}=`));',
          '  const token = cookie?.slice(COOKIE_NAME.length + 1);',
          '  if (!token) return null;',
          '  const [payload, encodedSignature, extra] = token.split(".");',
          '  if (!payload || !encodedSignature || extra !== undefined) return null;',
          '  let key: Buffer;',
          '  try { key = signingKey(); } catch { return null; }',
          '  try {',
          '    const actual = Buffer.from(encodedSignature, "base64url");',
          '    const expected = signature(payload, key);',
          '    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;',
          '    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Partial<SessionClaims>;',
          '    if (typeof claims.subject !== "string" || !claims.subject || !Number.isSafeInteger(claims.expiresAt) || (claims.expiresAt ?? 0) <= Date.now() || !Array.isArray(claims.roles)) return null;',
          '    return { subject: claims.subject, expiresAt: claims.expiresAt as number, roles: claims.roles.filter((role): role is string => typeof role === "string") };',
          '  } catch { return null; } finally { key.fill(0); }',
          '}',
        ].join('\n');
      case 'src/app/api/auth/session/route.ts':
        return [
          'import { readSession } from "../../../../lib/auth/session";',
          '',
          'export const dynamic = "force-dynamic";',
          '',
          'export function GET(request: Request): Response {',
          '  const session = readSession(request);',
          '  return Response.json({ authenticated: session !== null, roles: session?.roles ?? [] }, {',
          '    headers: { "Cache-Control": "private, no-store", "Vary": "Cookie" },',
          '  });',
          '}',
        ].join('\n');
      case 'src/lib/finance/money.ts':
        return [
          'export interface Money { readonly minorUnits: bigint; readonly currency: string; }',
          '',
          'export function makeMoney(minorUnits: bigint, currency = "INR"): Money {',
          '  if (!/^[A-Z]{3}$/.test(currency)) throw new TypeError("Currency must be an ISO 4217 code.");',
          '  return { minorUnits, currency };',
          '}',
          '',
          'export function addMoney(left: Money, right: Money): Money {',
          '  if (left.currency !== right.currency) throw new TypeError("Cannot add amounts in different currencies.");',
          '  return { minorUnits: left.minorUnits + right.minorUnits, currency: left.currency };',
          '}',
          '',
          'export function serializeMoney(value: Money): { minorUnits: string; currency: string } {',
          '  return { minorUnits: value.minorUnits.toString(), currency: value.currency };',
          '}',
        ].join('\n');
      case 'src/db/schema.sql':
        return [
          'CREATE TABLE IF NOT EXISTS accounts (',
          '  id UUID PRIMARY KEY,',
          '  currency CHAR(3) NOT NULL CHECK (currency ~ \'^[A-Z]{3}$\'),',
          '  created_at TIMESTAMPTZ NOT NULL DEFAULT now()',
          ');',
          '',
          'CREATE TABLE IF NOT EXISTS ledger_entries (',
          '  id UUID PRIMARY KEY,',
          '  account_id UUID NOT NULL REFERENCES accounts(id),',
          '  amount_minor BIGINT NOT NULL,',
          '  currency CHAR(3) NOT NULL CHECK (currency ~ \'^[A-Z]{3}$\'),',
          '  idempotency_key TEXT NOT NULL UNIQUE,',
          '  created_at TIMESTAMPTZ NOT NULL DEFAULT now()',
          ');',
          '',
          'CREATE INDEX IF NOT EXISTS ledger_entries_account_created_idx ON ledger_entries(account_id, created_at DESC);',
        ].join('\n');
      case 'src/lib/realtime/events.ts':
        return [
          'export interface DashboardEvent { readonly id: string; readonly type: "metric.updated"; readonly occurredAt: string; readonly metric: string; readonly value: number; }',
          '',
          'export function isDashboardEvent(value: unknown): value is DashboardEvent {',
          '  if (typeof value !== "object" || value === null) return false;',
          '  const event = value as Record<string, unknown>;',
          '  return typeof event["id"] === "string" && event["type"] === "metric.updated" &&',
          '    typeof event["occurredAt"] === "string" && typeof event["metric"] === "string" &&',
          '    typeof event["value"] === "number" && Number.isFinite(event["value"]);',
          '}',
        ].join('\n');
      case 'src/app/api/events/route.ts':
        return [
          'import { readSession } from "../../../lib/auth/session";',
          '',
          'export const dynamic = "force-dynamic";',
          '',
          'export function GET(request: Request): Response {',
          '  if (!readSession(request)) return Response.json({ error: "unauthorized" }, { status: 401 });',
          '  let heartbeat: ReturnType<typeof setInterval> | undefined;',
          '  const stream = new ReadableStream<Uint8Array>({',
          '    start(controller) {',
          '      const encoder = new TextEncoder();',
          '      heartbeat = setInterval(() => {',
          '        try { controller.enqueue(encoder.encode(": keep-alive\\n\\n")); } catch { if (heartbeat) clearInterval(heartbeat); }',
          '      }, 15_000);',
          '      request.signal.addEventListener("abort", () => { if (heartbeat) clearInterval(heartbeat); try { controller.close(); } catch {} }, { once: true });',
          '      controller.enqueue(encoder.encode("event: ready\\ndata: {\\"status\\":\\"connected\\"}\\n\\n"));',
          '    },',
          '    cancel() { if (heartbeat) clearInterval(heartbeat); },',
          '  });',
          '  return new Response(stream, { headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive" } });',
          '}',
        ].join('\n');
      case 'tests/unit/formatters.test.ts':
        return [
          'import { describe, expect, it } from "vitest";',
          'import { formatCompactNumber, formatCurrency, formatDate } from "../../src/lib/formatters";',
          '',
          'describe("formatters", () => {',
          '  it("formats minor currency units", () => { expect(formatCurrency(12345, "INR")).toContain("123.45"); });',
          '  it("rejects unsafe currency values", () => { expect(() => formatCurrency(Number.NaN)).toThrow(TypeError); });',
          '  it("formats compact metrics", () => { expect(formatCompactNumber(1200, "en-US")).toContain("1.2"); });',
          '  it("formats UTC dates", () => { expect(formatDate("2025-01-15T00:00:00.000Z", "en-US")).toContain("2025"); });',
          '});',
        ].join('\n');
      case '.env.example':
        return [
          '# Copy to .env.local; provide values only in an uncommitted local environment file.',
          'SESSION_SIGNING_KEY=',
          'DATABASE_URL=',
        ].join('\n');
    }
  }

  if (profile === 'FASTAPI') {
    switch (path) {
      case 'README.md':
        return `# ${context.blueprint.projectTitle}\n\n${context.blueprint.requestSummary}\n\nInstall the pinned dependencies from pyproject.toml and run python -m uvicorn app.main:app --reload. The service validates requests and exposes a minimal health endpoint. Configure secrets outside source control.\n`;
      case 'pyproject.toml':
        return [
          '[project]',
          'name = "techyonx-kode-service"',
          'version = "1.0.0"',
          'requires-python = ">=3.12"',
          'dependencies = ["fastapi==0.115.8", "pydantic==2.10.6", "uvicorn==0.34.0"]',
          '',
          '[project.optional-dependencies]',
          'test = ["pytest==8.3.4", "httpx==0.28.1"]',
        ].join('\n');
      case 'app/__init__.py': return '';
      case 'app/main.py':
        return [
          'from fastapi import FastAPI',
          'from app.routes.health import router as health_router',
          '',
          `app = FastAPI(title=${jsonString(context.blueprint.projectTitle)}, version="1.0.0", docs_url="/docs")`,
          'app.include_router(health_router)',
          '',
          '@app.get("/", include_in_schema=False)',
          'def root() -> dict[str, str]:',
          '    return {"service": "techyonx-kode-service", "status": "ok"}',
        ].join('\n');
      case 'app/schemas.py':
        return [
          'from pydantic import BaseModel, ConfigDict, Field',
          '',
          'class HealthResponse(BaseModel):',
          '    model_config = ConfigDict(extra="forbid")',
          '    status: str = Field(pattern="^ok$")',
          '    service: str = Field(min_length=1, max_length=80)',
        ].join('\n');
      case 'app/routes/health.py':
        return [
          'from fastapi import APIRouter',
          'from app.schemas import HealthResponse',
          '',
          'router = APIRouter(tags=["health"])',
          '',
          '@router.get("/api/health", response_model=HealthResponse)',
          'def get_health() -> HealthResponse:',
          '    return HealthResponse(status="ok", service="techyonx-kode-service")',
        ].join('\n');
      case 'tests/test_health.py':
        return [
          'from fastapi.testclient import TestClient',
          'from app.main import app',
          '',
          'client = TestClient(app)',
          '',
          'def test_health_returns_validated_status() -> None:',
          '    response = client.get("/api/health")',
          '    assert response.status_code == 200',
          '    assert response.json()["status"] == "ok"',
        ].join('\n');
      case '.env.example': return 'APP_ENV=development\n';
    }
  }

  if (profile === 'RUST') {
    switch (path) {
      case 'README.md': return `# ${context.blueprint.projectTitle}\n\n${context.blueprint.requestSummary}\n\nBuild with cargo build and run with cargo run. Configuration is read from the process environment.\n`;
      case 'Cargo.toml':
        return [
          '[package]',
          'name = "techyonx-kode-service"',
          'version = "1.0.0"',
          'edition = "2021"',
          '',
          '[dependencies]',
          'axum = "0.8.1"',
          'tokio = { version = "1.43.0", features = ["macros", "rt-multi-thread", "net"] }',
          'serde = { version = "1.0.217", features = ["derive"] }',
          'serde_json = "1.0.138"',
        ].join('\n');
      case 'src/main.rs':
        return [
          'use axum::{routing::get, Json, Router};',
          'use serde::Serialize;',
          'use std::net::SocketAddr;',
          '',
          '#[derive(Serialize)]',
          'struct Health { status: &\'static str, service: &\'static str }',
          '',
          'async fn health() -> Json<Health> {',
          '    Json(Health { status: "ok", service: "techyonx-kode-service" })',
          '}',
          '',
          '#[tokio::main]',
          'async fn main() -> Result<(), Box<dyn std::error::Error>> {',
          '    let app = Router::new().route("/api/health", get(health));',
          '    let address: SocketAddr = "127.0.0.1:3000".parse()?;',
          '    let listener = tokio::net::TcpListener::bind(address).await?;',
          '    axum::serve(listener, app).await?;',
          '    Ok(())',
          '}',
        ].join('\n');
      case 'src/lib.rs': return 'pub fn service_name() -> &\'static str { "techyonx-kode-service" }\n';
      case 'src/routes/health.rs': return 'pub const HEALTH_PATH: &str = "/api/health";\n';
      case 'tests/health_test.rs': return '#[test]\nfn service_name_is_stable() {\n    assert_eq!(techyonx_kode_service::service_name(), "techyonx-kode-service");\n}\n';
      case '.env.example': return 'APP_ENV=development\n';
    }
  }

  if (profile === 'GO') {
    switch (path) {
      case 'README.md': return `# ${context.blueprint.projectTitle}\n\n${context.blueprint.requestSummary}\n\nRun go test ./... and go run ./cmd/server. The HTTP server uses bounded timeouts and a minimal health endpoint.\n`;
      case 'go.mod': return 'module techyonx-kode-service\n\ngo 1.23.0\n';
      case 'cmd/server/main.go':
        return [
          'package main',
          '',
          'import (',
          '    "context"',
          '    "log"',
          '    "net/http"',
          '    "os"',
          '    "os/signal"',
          '    "syscall"',
          '    "time"',
          ')',
          '',
          'func main() {',
          '    mux := http.NewServeMux()',
          '    mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {',
          '        w.Header().Set("Content-Type", "application/json")',
          '        w.Header().Set("Cache-Control", "no-store")',
          '        _, _ = w.Write([]byte(`{"status":"ok","service":"techyonx-kode-service"}`))',
          '    })',
          '    server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}',
          '    stopped := make(chan os.Signal, 1)',
          '    signal.Notify(stopped, syscall.SIGINT, syscall.SIGTERM)',
          '    go func() { <-stopped; ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second); defer cancel(); _ = server.Shutdown(ctx) }()',
          '    if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed { log.Fatal(err) }',
          '}',
        ].join('\n');
      case 'internal/health/handler.go':
        return [
          'package health',
          '',
          'import ("encoding/json"; "net/http")',
          '',
          'type response struct { Status string `json:"status"`; Service string `json:"service"` }',
          '',
          'func Handler(w http.ResponseWriter, r *http.Request) {',
          '    w.Header().Set("Content-Type", "application/json")',
          '    w.Header().Set("Cache-Control", "no-store")',
          '    w.WriteHeader(http.StatusOK)',
          '    _ = json.NewEncoder(w).Encode(response{Status: "ok", Service: "techyonx-kode-service"})',
          '}',
        ].join('\n');
      case 'internal/health/handler_test.go':
        return [
          'package health',
          '',
          'import ("net/http/httptest"; "testing")',
          '',
          'func TestHandlerReturnsOk(t *testing.T) {',
          '    request := httptest.NewRequest("GET", "/api/health", nil)',
          '    recorder := httptest.NewRecorder()',
          '    Handler(recorder, request)',
          '    if recorder.Code != 200 { t.Fatalf("status = %d, want 200", recorder.Code) }',
          '}',
        ].join('\n');
      case '.env.example': return 'APP_ENV=development\n';
    }
  }

  return genericTemplate(file, context);
}

function genericTemplate(file: ArchitectPlannedFile, context: TemplateContext): string {
  const name = file.path.split('/').at(-1) ?? file.path;
  const extension = name.split('.').at(-1)?.toLowerCase() ?? '';
  if (extension === 'ts' || extension === 'tsx') {
    if (extension === 'tsx' || file.path.includes('/components/')) {
      return [
        'interface FeaturePanelProps { readonly title?: string; }',
        '',
        'export function FeaturePanel({ title = "Workspace overview" }: FeaturePanelProps) {',
        '  return <section aria-labelledby="feature-panel-title" className="border border-slate-200 bg-white p-5">',
        '    <h2 id="feature-panel-title" className="text-lg font-semibold">{title}</h2>',
        `    <p className="mt-2 text-sm text-slate-600">${context.blueprint.projectTitle} is ready for validated feature data.</p>`,
        '  </section>;',
        '}',
      ].join('\n');
    }
    return [
      'export interface ValidationResult { readonly valid: boolean; readonly message?: string; }',
      '',
      'export function validateNonEmptyText(value: unknown): ValidationResult {',
      '  if (typeof value !== "string" || value.trim().length === 0) return { valid: false, message: "A non-empty string is required." };',
      '  if (value.length > 10_000) return { valid: false, message: "Text exceeds the supported length." };',
      '  return { valid: true };',
      '}',
    ].join('\n');
  }
  if (extension === 'py') {
    return [
      'from pydantic import BaseModel, ConfigDict, Field',
      '',
      'class FeatureRequest(BaseModel):',
      '    model_config = ConfigDict(extra="forbid")',
      '    name: str = Field(min_length=1, max_length=120)',
      '',
      'def normalize_feature_name(value: str) -> str:',
      '    return " ".join(value.split())',
    ].join('\n');
  }
  if (extension === 'rs') return 'pub fn validate_non_empty(value: &str) -> bool { !value.trim().is_empty() }\n';
  if (extension === 'go') return 'package feature\n\nimport "strings"\n\nfunc IsNonEmpty(value string) bool { return strings.TrimSpace(value) != "" }\n';
  if (extension === 'sql') return 'CREATE TABLE IF NOT EXISTS workspace_records (id UUID PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT now());\n';
  if (extension === 'css') return ':root { color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; }\n';
  if (extension === 'json') return JSON.stringify({ name: 'techyonx-kode-generated-app', version: '1.0.0', private: true }, null, 2);
  if (extension === 'md') return `# ${context.blueprint.projectTitle}\n\n${context.blueprint.requestSummary}\n`;
  if (extension === 'example') return 'APP_ENV=development\n';
  return `export const ${name.replace(/[^A-Za-z0-9]/g, '_').replace(/^[^A-Za-z_]+/, '_') || 'feature'}Description = ${jsonString(file.responsibility)};\n`;
}

function makeSystemInstruction(): string {
  return [
    'You are the Polyglot Principal Code Generator Agent for Techyonx kode.',
    'Generate complete source files that satisfy the supplied blueprint and strict TypeScript/security requirements.',
    'Return only Markdown code blocks, each introduced by a line exactly like ### FILE: relative/path.ext followed by a fenced code block.',
    'Do not emit secrets, personal data, shell execution payloads, TODO/FIXME/TBD markers, placeholder text, or explanatory prose.',
    'Use only files in the approved planned-file manifest. Keep every path relative and do not overwrite unlisted files.',
    'Use runtime input validation, server-only credentials, accessible UI, explicit error handling, and deterministic tests.',
  ].join('\n');
}

function makeModelPrompt(
  userPrompt: string,
  blueprint: RequirementArchitectureBlueprint,
  existingFiles: readonly ExistingFile[],
): string {
  const plan = blueprint.plannedFiles
    .map(file => `- ${file.path}: ${file.responsibility}`)
    .join('\n');
  const existing = existingFiles.length === 0
    ? 'No existing files were supplied.'
    : existingFiles.map(file => `### EXISTING FILE: ${file.path}\n\`\`\`\n${file.content}\n\`\`\``).join('\n\n');
  return [
    `USER REQUEST:\n${userPrompt}`,
    `ARCHITECTURE BLUEPRINT:\n${blueprint.requestSummary}\n\nStack: ${blueprint.targetTechStack.join(', ')}\n\nComponents: ${blueprint.componentHierarchy.join(' > ')}`,
    `APPROVED FILE MANIFEST:\n${plan}`,
    `EXISTING FILE CONTEXT (read-only):\n${existing}`,
    'Produce the complete contents for the approved files. Implement the actual requested behavior; do not describe future work.',
  ].join('\n\n');
}

function tokenUsage(result: UniversalAICallResult): TokenUsage {
  return {
    inputTokens: result.promptTokens,
    outputTokens: result.completionTokens,
    totalTokens: result.promptTokens + result.completionTokens,
  };
}

function containsPlaceholder(content: string): boolean {
  return PLACEHOLDER_PATTERN.test(content);
}

function finalizeFiles(
  plannedFiles: readonly ArchitectPlannedFile[],
  modelFiles: readonly { path: string; language: string; content: string }[],
  context: TemplateContext,
): GeneratedCodeFile[] {
  const plannedByPath = new Map(plannedFiles.map(file => [file.path, file]));
  const modelByPath = new Map<string, string>();
  for (const file of modelFiles) {
    if (plannedByPath.has(file.path) && safeRelativePath(file.path) && !containsPlaceholder(file.content)) {
      modelByPath.set(file.path, file.content);
    }
  }

  return plannedFiles.map(planned => {
    const content = modelByPath.get(planned.path) ?? templateForFile(planned, context);
    return {
      path: planned.path,
      language: languageForPath(planned.path),
      content: content.endsWith('\n') ? content : `${content}\n`,
      lineCount: countLines(content),
    };
  });
}

function traceForResult(input: {
  readonly startedAt: number;
  readonly userPrompt: string;
  readonly files: readonly GeneratedCodeFile[];
  readonly provider: string;
  readonly modelUsed: string;
  readonly usage?: TokenUsage;
  readonly fallbackReason?: string;
}): AgentStepTrace {
  const trace: AgentStepTrace = {
    traceId: randomUUID(),
    operationId: randomUUID(),
    agentId: 'polyglot-code-generator-2',
    role: 'POLYGLOT_CODER',
    status: 'SUCCEEDED',
    startedAt: new Date(input.startedAt).toISOString(),
    completedAt: new Date().toISOString(),
    inputSummary: `Generated from a ${input.userPrompt.length}-character request using ${input.provider}.`,
    outputSummary: `${input.files.length} planned files generated by ${input.modelUsed}.${input.fallbackReason ? ` Fallback: ${input.fallbackReason}.` : ''}`,
    affectedPaths: input.files.map(file => file.path),
    ...(input.usage ? { usage: input.usage } : {}),
    ...(input.fallbackReason ? { errorCode: input.fallbackReason } : {}),
  };
  return trace;
}

/** Generates planned files with the universal model router and a deterministic offline template engine. */
export async function runPolyglotCodeGeneratorAgent(
  userPrompt: string,
  blueprint: unknown,
  existingFiles?: Array<{ path: string; content: string }>,
): Promise<{
  files: Array<{ path: string; language: string; content: string; lineCount: number }>;
  tokensUsed: number;
  provider: string;
  modelUsed: string;
  stepTrace: AgentStepTrace;
}> {
  if (typeof userPrompt !== 'string' || userPrompt.trim().length === 0 || userPrompt.length > MAX_PROMPT_CHARS) {
    throw new TypeError('Generator prompt must be non-empty and within the configured size limit.');
  }
  const startedAt = Date.now();
  const normalizedBlueprint = normalizeBlueprint(userPrompt, blueprint);
  if (normalizedBlueprint.plannedFiles.length === 0 || normalizedBlueprint.plannedFiles.length > MAX_PLANNED_FILES) {
    throw new RangeError('Generator blueprint must contain between 1 and 100 planned files.');
  }
  const plannedPaths = normalizedBlueprint.plannedFiles.map(file => file.path);
  const inspection = inspectCodingPromptSecurity(userPrompt, plannedPaths);
  if (!inspection.allowed) {
    throw new Error('Generator request was rejected by the coding prompt security policy.');
  }

  const normalizedExistingFiles = normalizeExistingFiles(existingFiles);
  const privacyPrompt = enforcePrivacyComplianceInCode(inspection.sanitizedPrompt).compliantText;
  const redactText = (value: string): string => enforcePrivacyComplianceInCode(value).compliantText;
  const privacySafeExistingFiles = normalizedExistingFiles.map(file => ({
    path: file.path,
    content: enforcePrivacyComplianceInCode(file.content).compliantText,
  }));
  const promptAndExistingSecretScan = scrubHardcodedSecrets([
    { path: '__request__.txt', content: privacyPrompt },
    ...privacySafeExistingFiles,
  ]);
  const secretSafePrompt = promptAndExistingSecretScan.scrubbedFiles[0]?.content ?? '';
  const secretSafeExistingFiles = promptAndExistingSecretScan.scrubbedFiles.slice(1);
  const blueprintForPrompt: RequirementArchitectureBlueprint = {
    ...normalizedBlueprint,
    projectTitle: redactText(normalizedBlueprint.projectTitle),
    targetTechStack: normalizedBlueprint.targetTechStack.map(redactText),
    plannedFiles: normalizedBlueprint.plannedFiles.map(file => ({
      path: file.path,
      responsibility: redactText(file.responsibility),
    })),
    componentHierarchy: normalizedBlueprint.componentHierarchy.map(redactText),
    apiContract: normalizedBlueprint.apiContract.map(redactText),
    edgeCases: normalizedBlueprint.edgeCases.map(redactText),
    securityRequirements: normalizedBlueprint.securityRequirements.map(redactText),
    requestSummary: redactText(normalizedBlueprint.requestSummary),
  };
  const blueprintSecurityText = [
    blueprintForPrompt.requestSummary,
    ...blueprintForPrompt.componentHierarchy,
    ...blueprintForPrompt.apiContract,
    ...blueprintForPrompt.edgeCases,
    ...blueprintForPrompt.securityRequirements,
    ...blueprintForPrompt.plannedFiles.map(file => file.responsibility),
  ].join('\n');
  if (!inspectCodingPromptSecurity(blueprintSecurityText, plannedPaths).allowed) {
    throw new Error('Untrusted blueprint description was rejected by the coding prompt security policy.');
  }
  const modelPrompt = makeModelPrompt(secretSafePrompt, blueprintForPrompt, secretSafeExistingFiles);
  if (modelPrompt.length > MAX_MODEL_OUTPUT_CHARS) {
    throw new RangeError('Model context exceeds the configured generator limit.');
  }

  let modelResult: UniversalAICallResult | undefined;
  let fallbackReason = '';
  try {
    modelResult = await executeUniversalAICall(
      modelPrompt,
      makeSystemInstruction(),
      { temperature: 0.2, maxOutputTokens: 12_000 },
    );
    if (modelResult.content.length > MAX_MODEL_OUTPUT_CHARS) {
      fallbackReason = 'MODEL_OUTPUT_LIMIT';
    } else if (modelResult.provider === 'OFFLINE_DETERMINISTIC') {
      fallbackReason = 'NO_REMOTE_PROVIDER_CONFIGURED';
    }
  } catch (error: unknown) {
    fallbackReason = error instanceof Error && 'code' in error && typeof error.code === 'string'
      ? error.code
      : 'MODEL_REQUEST_FAILED';
  }

  let parsedFiles: Array<{ path: string; language: string; content: string }> = [];
  if (modelResult && modelResult.provider !== 'OFFLINE_DETERMINISTIC' && modelResult.content.length <= MAX_MODEL_OUTPUT_CHARS) {
    try {
      const parsed = parseMultiFileCodeResponse(modelResult.content);
      const plannedPathSet = new Set(plannedPaths);
      parsedFiles = parsed.files
        .filter(file => plannedPathSet.has(file.path) && safeRelativePath(file.path))
        .map(file => ({ path: file.path, language: file.language, content: file.content }));
      if (parsedFiles.length === 0) {
        fallbackReason = 'MODEL_RESPONSE_CONTAINED_NO_APPROVED_FILES';
      }
    } catch {
      fallbackReason = 'MODEL_RESPONSE_PARSE_FAILED';
    }
  }

  const context: TemplateContext = {
    blueprint: blueprintForPrompt,
    userPrompt: privacyPrompt,
  };
  let generatedFiles = finalizeFiles(normalizedBlueprint.plannedFiles, parsedFiles, context);
  const generatedSecretScan = scrubHardcodedSecrets(generatedFiles);
  generatedFiles = generatedSecretScan.scrubbedFiles.map(file => ({
    ...file,
    language: languageForPath(file.path),
    lineCount: file.content.length === 0 ? 0 : file.content.split(/\r\n|\r|\n/).length,
  }));
  generatedFiles = generatedFiles.map(file => {
    const compliantText = enforcePrivacyComplianceInCode(file.content).compliantText;
    return {
      ...file,
      content: compliantText,
      lineCount: countLines(compliantText),
    };
  });

  const malwareScan = scanForMaliciousCode(generatedFiles);
  if (!malwareScan.safe) {
    fallbackReason = 'MODEL_OUTPUT_REJECTED_BY_MALICIOUS_CODE_SCAN';
    parsedFiles = [];
    generatedFiles = finalizeFiles(normalizedBlueprint.plannedFiles, [], context);
  }

  if (generatedFiles.some(file => containsPlaceholder(file.content))) {
    throw new Error('Deterministic generator produced a forbidden placeholder marker.');
  }

  const usedRemoteFiles = Boolean(
    modelResult &&
    modelResult.provider !== 'OFFLINE_DETERMINISTIC' &&
    parsedFiles.length > 0 &&
    fallbackReason !== 'MODEL_OUTPUT_LIMIT' &&
    fallbackReason !== 'MODEL_RESPONSE_PARSE_FAILED' &&
    fallbackReason !== 'MODEL_RESPONSE_CONTAINED_NO_APPROVED_FILES' &&
    fallbackReason !== 'MODEL_OUTPUT_REJECTED_BY_MALICIOUS_CODE_SCAN',
  );
  const provider = usedRemoteFiles && modelResult ? modelResult.provider : 'OFFLINE_DETERMINISTIC';
  const modelUsed = usedRemoteFiles && modelResult ? modelResult.modelUsed : 'techyonx-kode-template-engine-v1';
  const tokensUsed = modelResult && modelResult.provider !== 'OFFLINE_DETERMINISTIC'
    ? modelResult.promptTokens + modelResult.completionTokens
    : 0;
  const usage = modelResult && modelResult.provider !== 'OFFLINE_DETERMINISTIC'
    ? tokenUsage(modelResult)
    : undefined;
  const stepTrace = traceForResult({
    startedAt,
    userPrompt,
    files: generatedFiles,
    provider,
    modelUsed,
    ...(usage ? { usage } : {}),
    ...(fallbackReason ? { fallbackReason } : {}),
  });

  return { files: generatedFiles, tokensUsed, provider, modelUsed, stepTrace };
}