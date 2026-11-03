export interface LicenseAuditInputFile {
  readonly path: string;
  readonly content: string;
}

export type LicenseAuditResult = {
  compliant: boolean;
  detectedLicenses: string[];
  spdxIdentifier: string;
  recommendation: string;
};

const MAX_FILE_COUNT = 20_000;
const MAX_TOTAL_SOURCE_CHARS = 16_000_000;
const APPROVED_COMMERCIAL_LICENSES = new Set([
  'MIT',
  'Apache-2.0',
  'BSD-3-Clause',
]);

const SPDX_LICENSE_TOKEN = /\b(?:AGPL|GPL|LGPL|MPL|EPL|CDDL|SSPL|BUSL|OSL|MIT|Apache|BSD|ISC|Unlicense|0BSD|CC0|CC-BY-SA|CC-BY-NC)(?:-[A-Za-z0-9.]+)*(?:-(?:only|or-later))?\b/gi;
const SPDX_HEADER = /SPDX-License-Identifier\s*:\s*([^\r\n*]+)/gi;
const LICENSE_TEXT_PATTERNS: readonly { readonly pattern: RegExp; readonly identifier: string }[] = [
  { pattern: /GNU AFFERO GENERAL PUBLIC LICENSE[^\n]{0,80}(?:VERSION\s*3|V3|3\.0)/i, identifier: 'AGPL-3.0-only' },
  { pattern: /GNU GENERAL PUBLIC LICENSE[^\n]{0,80}(?:VERSION\s*3|V3|3\.0)/i, identifier: 'GPL-3.0-only' },
  { pattern: /GNU LESSER GENERAL PUBLIC LICENSE[^\n]{0,80}(?:VERSION\s*3|V3|3\.0)/i, identifier: 'LGPL-3.0-only' },
  { pattern: /GNU AFFERO GENERAL PUBLIC LICENSE/i, identifier: 'AGPL' },
  { pattern: /GNU GENERAL PUBLIC LICENSE/i, identifier: 'GPL' },
  { pattern: /GNU LESSER GENERAL PUBLIC LICENSE/i, identifier: 'LGPL' },
  { pattern: /Mozilla Public License\s*(?:Version\s*)?2\.0/i, identifier: 'MPL-2.0' },
  { pattern: /Eclipse Public License\s*(?:Version\s*)?2\.0/i, identifier: 'EPL-2.0' },
  { pattern: /Server Side Public License/i, identifier: 'SSPL' },
  { pattern: /Business Source License/i, identifier: 'BUSL' },
  { pattern: /Apache License\s*(?:Version\s*)?2\.0/i, identifier: 'Apache-2.0' },
  { pattern: /BSD 3-Clause License/i, identifier: 'BSD-3-Clause' },
  { pattern: /BSD 2-Clause License/i, identifier: 'BSD-2-Clause' },
  { pattern: /The MIT License/i, identifier: 'MIT' },
];

function normalizeLicenseToken(token: string): string {
  const normalized = token.trim().replace(/_/g, '-');
  const upper = normalized.toUpperCase();
  if (upper === 'GPLV3' || upper === 'GPL-3' || upper === 'GPL-3.0') return 'GPL-3.0-only';
  if (upper === 'AGPLV3' || upper === 'AGPL-3' || upper === 'AGPL-3.0') return 'AGPL-3.0-only';
  if (upper === 'LGPLV3' || upper === 'LGPL-3' || upper === 'LGPL-3.0') return 'LGPL-3.0-only';
  if (upper === 'APACHE-2.0' || upper === 'APACHE-2') return 'Apache-2.0';
  if (upper === 'BSD-3-CLAUSE') return 'BSD-3-Clause';
  if (upper === 'BSD-2-CLAUSE') return 'BSD-2-Clause';
  if (upper === 'MIT') return 'MIT';
  if (upper === 'ISC') return 'ISC';
  if (upper === 'UNLICENSE') return 'Unlicense';
  if (upper === '0BSD') return '0BSD';
  return normalized;
}

function collectFromPackageJson(content: string, detected: Set<string>, expressions: Set<string>): void {
  let manifest: unknown;
  try {
    manifest = JSON.parse(content) as unknown;
  } catch {
    return;
  }
  if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest)) {
    return;
  }
  const root = manifest as Record<string, unknown>;
  const license = root['license'];
  const addLicenseValue = (value: unknown): void => {
    if (typeof value === 'string') {
      expressions.add(value.trim());
      for (const match of value.matchAll(SPDX_LICENSE_TOKEN)) {
        if (match[0]) detected.add(normalizeLicenseToken(match[0]));
      }
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const type = (value as Record<string, unknown>)['type'];
      if (typeof type === 'string') addLicenseValue(type);
    }
  };
  addLicenseValue(license);

  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencyMap = root[field];
    if (typeof dependencyMap !== 'object' || dependencyMap === null || Array.isArray(dependencyMap)) {
      continue;
    }
    for (const dependencyName of Object.keys(dependencyMap)) {
      const dependencyLicenses = root['dependencyLicenses'];
      if (typeof dependencyLicenses === 'object' && dependencyLicenses !== null && !Array.isArray(dependencyLicenses)) {
        addLicenseValue((dependencyLicenses as Record<string, unknown>)[dependencyName]);
      }
    }
  }
}

function collectLicenses(files: readonly LicenseAuditInputFile[]): {
  detected: Set<string>;
  expressions: Set<string>;
  hasUnknownAssertion: boolean;
} {
  const detected = new Set<string>();
  const expressions = new Set<string>();
  let hasUnknownAssertion = false;

  for (const file of files) {
    if (/\.json$/i.test(file.path) && /(?:^|\/)package\.json$/i.test(file.path)) {
      collectFromPackageJson(file.content, detected, expressions);
    }

    for (const headerMatch of file.content.matchAll(SPDX_HEADER)) {
      const expression = (headerMatch[1] ?? '').trim();
      if (expression.length > 0) {
        expressions.add(expression);
        if (/\b(?:NOASSERTION|NONE)\b/i.test(expression)) {
          hasUnknownAssertion = true;
        }
        const tokens = [...expression.matchAll(SPDX_LICENSE_TOKEN)].map(match => match[0]);
        if (tokens.length === 0) {
          hasUnknownAssertion = true;
        }
        for (const token of tokens) detected.add(normalizeLicenseToken(token));
      }
    }

    for (const licenseText of LICENSE_TEXT_PATTERNS) {
      if (licenseText.pattern.test(file.content)) {
        detected.add(licenseText.identifier);
        expressions.add(licenseText.identifier);
      }
    }
    for (const match of file.content.matchAll(SPDX_LICENSE_TOKEN)) {
      if (match[0]) detected.add(normalizeLicenseToken(match[0]));
    }
  }

  return { detected, expressions, hasUnknownAssertion };
}

function hasRestrictiveLicense(licenses: ReadonlySet<string>): boolean {
  return [...licenses].some(license =>
    /^(?:AGPL|GPL|LGPL|SSPL|BUSL|OSL|CC-BY-SA|CC-BY-NC)(?:-|$)/i.test(license) ||
    /^(?:MPL|EPL|CDDL)(?:-|$)/i.test(license),
  );
}

function toSpdxSummary(expressions: ReadonlySet<string>, licenses: ReadonlySet<string>): string {
  if (expressions.size === 1) {
    const [expression] = expressions;
    return expression ?? 'NOASSERTION';
  }
  if (expressions.size > 1) {
    return [...licenses].sort().join(' AND ') || 'NOASSERTION';
  }
  return [...licenses].sort().join(' AND ') || 'NOASSERTION';
}

/** Audits only license evidence supplied in files; absent dependency metadata remains unverified. */
export function auditOpenSourceLicenses(files: Array<{ path: string; content: string }>): {
  compliant: boolean;
  detectedLicenses: string[];
  spdxIdentifier: string;
  recommendation: string;
} {
  if (!Array.isArray(files) || files.length > 20_000) {
    throw new RangeError('License audit accepts at most 20000 files.');
  }
  let totalSourceChars = 0;
  for (const file of files) {
    if (typeof file?.path !== 'string' || typeof file.content !== 'string') {
      throw new TypeError('Every license-audit input must have a string path and content.');
    }
    totalSourceChars += file.content.length;
    if (totalSourceChars > MAX_TOTAL_SOURCE_CHARS) {
      throw new RangeError(`License audit exceeds the ${MAX_TOTAL_SOURCE_CHARS}-character input limit.`);
    }
  }

  const { detected, expressions, hasUnknownAssertion } = collectLicenses(files);
  const detectedLicenses = [...detected].sort();
  const restrictive = hasRestrictiveLicense(detected);
  const unsupported = detectedLicenses.filter(license => !APPROVED_COMMERCIAL_LICENSES.has(license));
  const hasEvidence = detected.size > 0 && !hasUnknownAssertion;
  const compliant = hasEvidence && !restrictive && unsupported.length === 0;

  let recommendation: string;
  if (restrictive) {
    recommendation = 'Restrictive or reciprocal license evidence was detected. Stop redistribution and obtain license counsel review; do not remove attribution or license texts to bypass obligations.';
  } else if (!hasEvidence) {
    recommendation = 'No complete license evidence was supplied. Add an explicit approved SPDX identifier (MIT, Apache-2.0, or BSD-3-Clause) and audit dependency licenses separately.';
  } else if (!compliant) {
    recommendation = `The detected license set is outside the configured permissive allowlist (${unsupported.join(', ')}). Obtain review or select a compatible approved license for the applicable work.`;
  } else {
    recommendation = 'Detected license evidence is within the MIT, Apache-2.0, BSD-3-Clause allowlist. Licenses for dependencies without supplied metadata remain unverified.';
  }

  return {
    compliant,
    detectedLicenses,
    spdxIdentifier: toSpdxSummary(expressions, detected),
    recommendation,
  };
}