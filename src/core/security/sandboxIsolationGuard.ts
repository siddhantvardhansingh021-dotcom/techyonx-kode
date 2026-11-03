import { createHash } from 'node:crypto';

export const PREVIEW_IFRAME_SANDBOX = 'allow-scripts' as const;

const MAX_PREVIEW_SOURCE_CHARS = 1_000_000;
const CSP_BASE_DIRECTIVES = [
  "default-src 'none'",
  "base-uri 'none'",
  "object-src 'none'",
  "connect-src 'none'",
  "img-src data: blob:",
  "font-src data:",
  "media-src data: blob:",
  "frame-src 'none'",
  "form-action 'none'",
  "navigate-to 'none'",
];

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeAttribute(value: string): string {
  return escapeHtml(value);
}

function isReactSource(source: string): boolean {
  return /(?:\bfrom\s*["']react["']|\bimport\s+React\b|\bclassName\s*=|\bexport\s+default\s+(?:function|class)\b|\breturn\s*\(?\s*<)/.test(source);
}

function stripDocumentWrappers(html: string): string {
  return html
    .replace(/<!doctype\s+html[^>]*>/gi, '')
    .replace(/<\/?(?:html|head|body)\b[^>]*>/gi, '')
    .replace(/<base\b[^>]*>/gi, '')
    .replace(/<meta\b(?=[^>]*\bhttp-equiv\s*=\s*["']?refresh)[^>]*>/gi, '')
    .replace(/<link\b[^>]*>/gi, '');
}

function removeExternalScripts(html: string): string {
  return html.replace(
    /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi,
    (wholeTag, attributes: string, scriptBody: string) => {
      if (/\bsrc\s*=/i.test(attributes)) {
        return '';
      }
      if (/\btype\s*=\s*["']?(?:application\/json|application\/ld\+json|text\/template)/i.test(attributes)) {
        return wholeTag;
      }
      return `<script${attributes}>${scriptBody}</script>`;
    },
  ).replace(/<script\b[^>]*\bsrc\s*=[^>]*\/?\s*>/gi, '');
}

function collectInlineScriptHashes(html: string): string[] {
  const hashes = new Set<string>();
  const scriptPattern = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  for (const match of html.matchAll(scriptPattern)) {
    const attributes = match[1] ?? '';
    const scriptBody = match[2] ?? '';
    if (
      /\bsrc\s*=/i.test(attributes) ||
      /\btype\s*=\s*["']?(?:application\/json|application\/ld\+json|text\/template)/i.test(attributes)
    ) {
      continue;
    }
    const normalizedBody = scriptBody.replace(/\r\n?/g, '\n');
    const digest = createHash('sha256').update(normalizedBody, 'utf8').digest('base64');
    hashes.add(`'sha256-${digest}'`);
  }
  return [...hashes].sort();
}

function buildPolicy(scriptHashes: readonly string[], includeHeaderOnly: boolean): string {
  const scriptSources = scriptHashes.length > 0 ? scriptHashes.join(' ') : "'none'";
  const directives = [
    ...CSP_BASE_DIRECTIVES,
    `script-src ${scriptSources}`,
    "style-src 'unsafe-inline'",
  ];
  if (includeHeaderOnly) {
    directives.push("frame-ancestors 'none'", 'sandbox allow-scripts');
  }
  return directives.join('; ');
}

/** Builds an inert React-source view or a network-restricted, hash-CSP HTML preview. */
export function createIsolatedPreviewHtml(
  htmlOrReactCode: string,
  cssCode = '',
): { safeSrcDoc: string; cspHeader: string } {
  if (typeof htmlOrReactCode !== 'string' || typeof cssCode !== 'string') {
    throw new TypeError('Preview source and CSS must be strings.');
  }
  if (htmlOrReactCode.length + cssCode.length > MAX_PREVIEW_SOURCE_CHARS) {
    throw new RangeError(`Preview content exceeds the ${MAX_PREVIEW_SOURCE_CHARS}-character limit.`);
  }

  const reactSource = isReactSource(htmlOrReactCode);
  const suppliedHtml = reactSource
    ? `<pre class="source-view"><code>${escapeHtml(htmlOrReactCode)}</code></pre>`
    : removeExternalScripts(stripDocumentWrappers(htmlOrReactCode));
  const scriptHashes = reactSource ? [] : collectInlineScriptHashes(suppliedHtml);
  const cspHeader = buildPolicy(scriptHashes, true);
  const metaPolicy = buildPolicy(scriptHashes, false)
    .replace(/"/g, '&quot;');
  const safeCss = cssCode
    .replace(/</g, '\\3C ')
    .replace(/&/g, '\\26 ');
  const sourceViewCss = reactSource
    ? 'body{margin:0;padding:16px;background:#111827;color:#e5e7eb;font:13px/1.6 ui-monospace,monospace}.source-view{white-space:pre-wrap;overflow-wrap:anywhere}'
    : '';

  const safeSrcDoc = [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    `<meta http-equiv="Content-Security-Policy" content="${metaPolicy}">`,
    '<meta name="referrer" content="no-referrer">',
    `<style>${sourceViewCss}\n${safeCss}</style>`,
    '</head>',
    `<body>${suppliedHtml}</body>`,
    '</html>',
  ].join('');

  return { safeSrcDoc, cspHeader };
}

export function getPreviewIframeSandboxAttribute(): string {
  return `sandbox="${escapeAttribute(PREVIEW_IFRAME_SANDBOX)}"`;
}