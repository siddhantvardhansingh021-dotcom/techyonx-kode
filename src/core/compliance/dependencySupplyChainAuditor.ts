export interface DependencyAuditInputFile {
  readonly path: string;
  readonly content: string;
}

export interface FlaggedDependency {
  readonly name: string;
  readonly reason: string;
  readonly safeReplacement?: string;
}

export interface DependencyAuditOutputFile {
  readonly path: string;
  readonly content: string;
}

export interface DependencyAuditResult {
  readonly safe: boolean;
  readonly verifiedPackages: string[];
  readonly flaggedPackages: FlaggedDependency[];
  readonly healedFiles: DependencyAuditOutputFile[];
}

type DependencyEcosystem = 'npm' | 'pypi' | 'cargo';

interface TrustedPackage {
  readonly approvedVersion: string;
  readonly replacement?: string;
  readonly deprecated?: boolean;
}

interface ParsedVersion {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly prerelease?: string;
  readonly text: string;
}

interface DependencyDecision {
  readonly pinnedVersion?: string;
  readonly flag?: FlaggedDependency;
  readonly unresolved: boolean;
  readonly verifiedName?: string;
}

const MAX_FILE_COUNT = 20_000;
const MAX_TOTAL_SOURCE_CHARS = 16_000_000;

const TRUSTED_PACKAGES: Readonly<Record<DependencyEcosystem, Readonly<Record<string, TrustedPackage>>>> = {
  npm: {
    '@playwright/test': { approvedVersion: '1.50.1' },
    '@prisma/client': { approvedVersion: '6.3.1' },
    '@tanstack/react-query': { approvedVersion: '5.66.0' },
    '@types/node': { approvedVersion: '22.13.4' },
    '@types/react': { approvedVersion: '19.0.8' },
    '@types/react-dom': { approvedVersion: '19.0.3' },
    axios: { approvedVersion: '1.7.9' },
    bcrypt: { approvedVersion: '5.1.1' },
    cors: { approvedVersion: '2.8.5' },
    dotenv: { approvedVersion: '16.4.7' },
    'drizzle-orm': { approvedVersion: '0.39.3' },
    eslint: { approvedVersion: '9.19.0' },
    'eslint-config-next': { approvedVersion: '15.2.4' },
    express: { approvedVersion: '5.0.1' },
    fastify: { approvedVersion: '5.2.1' },
    helmet: { approvedVersion: '8.0.0' },
    jose: { approvedVersion: '5.9.6' },
    'lucide-react': { approvedVersion: '0.468.0' },
    lodash: { approvedVersion: '4.17.21' },
    next: { approvedVersion: '15.2.4' },
    'node-uuid': { approvedVersion: '1.4.8', replacement: 'uuid', deprecated: true },
    pg: { approvedVersion: '8.13.3' },
    prisma: { approvedVersion: '6.3.1' },
    react: { approvedVersion: '19.0.0' },
    'react-dom': { approvedVersion: '19.0.0' },
    request: { approvedVersion: '2.88.2', replacement: 'undici', deprecated: true },
    'react-hook-form': { approvedVersion: '7.54.2' },
    tailwindcss: { approvedVersion: '4.0.0' },
    tsx: { approvedVersion: '4.19.2' },
    typescript: { approvedVersion: '5.7.3' },
    undici: { approvedVersion: '7.3.0' },
    uuid: { approvedVersion: '11.0.5' },
    vite: { approvedVersion: '6.1.0' },
    vitest: { approvedVersion: '3.0.5' },
    zod: { approvedVersion: '3.24.2' },
  },
  pypi: {
    bcrypt: { approvedVersion: '4.2.1' },
    cryptography: { approvedVersion: '44.0.0' },
    django: { approvedVersion: '5.1.6' },
    fastapi: { approvedVersion: '0.115.8' },
    flask: { approvedVersion: '3.1.0' },
    'google-genai': { approvedVersion: '1.2.0' },
    httpx: { approvedVersion: '0.28.1' },
    numpy: { approvedVersion: '2.2.2' },
    pydantic: { approvedVersion: '2.10.6' },
    'pycrypto': { approvedVersion: '2.6.1', replacement: 'cryptography', deprecated: true },
    pytest: { approvedVersion: '8.3.4' },
    requests: { approvedVersion: '2.32.3' },
    sqlalchemy: { approvedVersion: '2.0.37' },
    uvicorn: { approvedVersion: '0.34.0' },
  },
  cargo: {
    anyhow: { approvedVersion: '1.0.95' },
    axum: { approvedVersion: '0.8.1' },
    bytes: { approvedVersion: '1.9.0' },
    clap: { approvedVersion: '4.5.27' },
    reqwest: { approvedVersion: '0.12.12' },
    serde: { approvedVersion: '1.0.217' },
    'serde_json': { approvedVersion: '1.0.138' },
    thiserror: { approvedVersion: '2.0.11' },
    tokio: { approvedVersion: '1.43.0' },
    tracing: { approvedVersion: '0.1.41' },
    uuid: { approvedVersion: '1.12.1' },
  },
};

const MANIFEST_ECOSYSTEMS: Readonly<Record<string, DependencyEcosystem>> = {
  'package.json': 'npm',
  'requirements.txt': 'pypi',
  'cargo.toml': 'cargo',
};

type TrustedPackageCatalog = Record<DependencyEcosystem, Record<string, TrustedPackage>>;
let trustedPackageCatalogCache: TrustedPackageCatalog | undefined;

function readEnvironment(name: string): string {
  const runtime = globalThis as typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
  };
  return runtime.process?.env?.[name]?.trim() ?? '';
}

function trustedPackageCatalog(): TrustedPackageCatalog {
  if (trustedPackageCatalogCache) {
    return trustedPackageCatalogCache;
  }

  const catalog: TrustedPackageCatalog = {
    npm: { ...TRUSTED_PACKAGES.npm },
    pypi: { ...TRUSTED_PACKAGES.pypi },
    cargo: { ...TRUSTED_PACKAGES.cargo },
  };
  const overrideJson = readEnvironment('TECHYONX_TRUSTED_PACKAGE_REGISTRY');
  if (overrideJson) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(overrideJson) as unknown;
    } catch {
      throw new Error('Trusted package registry configuration is invalid JSON.');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('Trusted package registry configuration must be an ecosystem map.');
    }

    for (const ecosystem of ['npm', 'pypi', 'cargo'] as const) {
      const entries = (parsed as Record<string, unknown>)[ecosystem];
      if (entries === undefined) {
        continue;
      }
      if (typeof entries !== 'object' || entries === null || Array.isArray(entries)) {
        throw new Error(`Trusted package registry ${ecosystem} entries must be an object.`);
      }
      for (const [rawName, rawVersion] of Object.entries(entries)) {
        const name = canonicalPackageName(ecosystem, rawName);
        const version = typeof rawVersion === 'string' ? parseVersion(rawVersion) : undefined;
        if (!name || !version || version.prerelease) {
          throw new Error(`Trusted package registry contains an invalid ${ecosystem} package version.`);
        }
        catalog[ecosystem][name] = {
          ...catalog[ecosystem][name],
          approvedVersion: version.text,
        };
      }
    }
  }

  trustedPackageCatalogCache = catalog;
  return catalog;
}

function canonicalPackageName(ecosystem: DependencyEcosystem, name: string): string {
  const lowered = name.trim().toLowerCase();
  return ecosystem === 'pypi' ? lowered.replace(/[-_.]+/g, '-') : lowered;
}

function parseVersion(raw: string): ParsedVersion | undefined {
  const match = raw.trim().replace(/^v/i, '').match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) {
    return undefined;
  }
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (![major, minor, patch].every(Number.isSafeInteger)) {
    return undefined;
  }
  const prerelease = match[4];
  return {
    major,
    minor,
    patch,
    ...(prerelease ? { prerelease } : {}),
    text: `${major}.${minor}.${patch}${prerelease ? `-${prerelease}` : ''}`,
  };
}

function lowerBoundFromSpec(spec: string): { version?: ParsedVersion; unsupported: boolean } {
  const trimmed = spec.trim();
  if (!trimmed) {
    return { unsupported: false };
  }
  if (/^(?:workspace:|file:|link:|git\+|git:|https?:|github:|npm:)/i.test(trimmed)) {
    return { unsupported: true };
  }
  const match = trimmed.match(/^(?:\^|~|~>|>=|>|=|==|===)?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/);
  if (!match?.[1]) {
    return { unsupported: true };
  }
  const version = parseVersion(match[1]);
  if (!version) {
    return { unsupported: true };
  }
  if (/\|\||\*|\b(?:latest|next|canary)\b/i.test(trimmed)) {
    return { unsupported: true };
  }
  return { version, unsupported: false };
}

function editDistance(left: string, right: string): number {
  const previous = Array.from({ length: right.length + 1 }, (_value, index) => index);
  let current = new Array<number>(right.length + 1).fill(0);
  for (let leftIndex = 1; leftIndex <= left.length; leftIndex += 1) {
    current[0] = leftIndex;
    for (let rightIndex = 1; rightIndex <= right.length; rightIndex += 1) {
      const substitutionCost = left[leftIndex - 1] === right[rightIndex - 1] ? 0 : 1;
      current[rightIndex] = Math.min(
        (current[rightIndex - 1] ?? 0) + 1,
        (previous[rightIndex] ?? 0) + 1,
        (previous[rightIndex - 1] ?? 0) + substitutionCost,
      );
    }
    for (let index = 0; index < previous.length; index += 1) {
      previous[index] = current[index] ?? leftIndex;
    }
  }
  return previous[right.length] ?? Math.max(left.length, right.length);
}

function nearestTrustedPackage(ecosystem: DependencyEcosystem, packageName: string): string | undefined {
  const candidate = canonicalPackageName(ecosystem, packageName);
  const catalog = trustedPackageCatalog()[ecosystem];
  let nearest: string | undefined;
  let minimumDistance = Number.POSITIVE_INFINITY;
  for (const trustedName of Object.keys(catalog)) {
    const distance = editDistance(candidate, trustedName);
    const threshold = candidate.length >= 6 ? 2 : 1;
    if (distance <= threshold && distance < minimumDistance) {
      nearest = trustedName;
      minimumDistance = distance;
    }
  }
  return nearest;
}

function resolveDependency(
  ecosystem: DependencyEcosystem,
  rawName: string,
  versionSpec: string,
): DependencyDecision {
  const name = canonicalPackageName(ecosystem, rawName);
  const catalog = trustedPackageCatalog()[ecosystem];
  const entry = catalog[name];
  if (!entry) {
    const nearest = nearestTrustedPackage(ecosystem, name);
    const safeReplacement = nearest
      ? `${nearest}@${catalog[nearest]?.approvedVersion ?? ''}`
      : undefined;
    return {
      unresolved: true,
      flag: {
        name: rawName,
        reason: nearest
          ? `Package is absent from the trusted ${ecosystem} catalog and is a possible typo-squat of ${nearest}; verify package ownership and registry identity.`
          : `Package is absent from the trusted ${ecosystem} catalog; existence, ownership, version, and advisories are unverified.`,
        ...(safeReplacement ? { safeReplacement } : {}),
      },
    };
  }

  if (/^(?:workspace:|file:|link:|git\+|git:|https?:|github:|npm:)/i.test(versionSpec.trim())) {
    return {
      unresolved: true,
      flag: {
        name: rawName,
        reason: 'Git, local, workspace, alias, or URL dependency sources require commit, origin, and integrity verification beyond a semver pin.',
      },
    };
  }

  if (entry.deprecated) {
    const replacement = entry.replacement;
    const replacementVersion = replacement
      ? catalog[replacement]?.approvedVersion
      : undefined;
    return {
      unresolved: true,
      flag: {
        name: rawName,
        reason: 'Package is marked deprecated in the local supply-chain catalog.',
        ...(replacement && replacementVersion ? { safeReplacement: `${replacement}@${replacementVersion}` } : {}),
      },
    };
  }

  const approvedVersion = parseVersion(entry.approvedVersion);
  if (!approvedVersion) {
    return {
      unresolved: true,
      flag: { name: rawName, reason: 'Trusted package catalog contains an invalid approved version.' },
    };
  }

  const requested = lowerBoundFromSpec(versionSpec);
  if (requested.unsupported || !requested.version) {
    return {
      pinnedVersion: entry.approvedVersion,
      verifiedName: `${rawName}@${entry.approvedVersion}`,
      unresolved: false,
      flag: {
        name: rawName,
        reason: `Unverifiable or unbounded version source was replaced with the catalog-approved exact version ${entry.approvedVersion}.`,
        safeReplacement: `${rawName}@${entry.approvedVersion}`,
      },
    };
  }

  if (
    requested.version.major !== approvedVersion.major
  ) {
    return {
      unresolved: true,
      flag: {
        name: rawName,
        reason: `Requested major version is outside the cataloged major ${approvedVersion.major}; review the upgrade or migration before selecting an approved version.`,
        safeReplacement: `${rawName}@${entry.approvedVersion}`,
      },
    };
  }

  const changed = requested.version.prerelease !== undefined ||
    requested.version.text !== approvedVersion.text ||
    versionSpec.trim() !== approvedVersion.text;
  return {
    pinnedVersion: approvedVersion.text,
    verifiedName: `${rawName}@${approvedVersion.text}`,
    unresolved: false,
    ...(changed
      ? {
          flag: {
            name: rawName,
            reason: `Version was pinned to the exact catalog-approved semver ${approvedVersion.text}.`,
            safeReplacement: `${rawName}@${approvedVersion.text}`,
          },
        }
      : {}),
  };
}

function addDecision(
  decision: DependencyDecision,
  verifiedPackages: Set<string>,
  flaggedPackages: Map<string, FlaggedDependency>,
  unresolvedNames: Set<string>,
): void {
  if (decision.verifiedName) {
    verifiedPackages.add(decision.verifiedName);
  }
  if (decision.flag) {
    const key = `${decision.flag.name}\0${decision.flag.reason}`;
    flaggedPackages.set(key, decision.flag);
    if (decision.unresolved) {
      unresolvedNames.add(decision.flag.name);
    }
  }
}

function processPackageJson(
  content: string,
  verifiedPackages: Set<string>,
  flaggedPackages: Map<string, FlaggedDependency>,
  unresolvedNames: Set<string>,
): string {
  let manifest: unknown;
  try {
    manifest = JSON.parse(content) as unknown;
  } catch {
    flaggedPackages.set('package.json\0invalid-json', {
      name: 'package.json',
      reason: 'Manifest is invalid JSON and its dependency declarations cannot be audited.',
    });
    unresolvedNames.add('package.json');
    return content;
  }
  if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest)) {
    flaggedPackages.set('package.json\0invalid-root', {
      name: 'package.json',
      reason: 'Manifest root must be a JSON object.',
    });
    unresolvedNames.add('package.json');
    return content;
  }

  const root = manifest as Record<string, unknown>;
  let changed = false;
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencies = root[field];
    if (typeof dependencies !== 'object' || dependencies === null || Array.isArray(dependencies)) {
      continue;
    }
    const dependencyMap = dependencies as Record<string, unknown>;
    for (const [name, rawSpec] of Object.entries(dependencyMap)) {
      if (typeof rawSpec !== 'string') {
        flaggedPackages.set(`${name}\0invalid-spec`, {
          name,
          reason: `Dependency declaration in ${field} must be a string semver or a supported registry entry.`,
        });
        unresolvedNames.add(name);
        continue;
      }
      const decision = resolveDependency('npm', name, rawSpec);
      addDecision(decision, verifiedPackages, flaggedPackages, unresolvedNames);
      if (decision.pinnedVersion && decision.pinnedVersion !== rawSpec) {
        dependencyMap[name] = decision.pinnedVersion;
        changed = true;
      }
    }
  }

  if (!changed) {
    return content;
  }
  const indentMatch = content.match(/\n([\t ]+)"[^"\n]+"\s*:/);
  const indent = indentMatch?.[1] ?? '  ';
  const trailingNewline = content.endsWith('\n') ? '\n' : '';
  return `${JSON.stringify(root, null, indent)}${trailingNewline}`;
}

function processRequirementsTxt(
  content: string,
  verifiedPackages: Set<string>,
  flaggedPackages: Map<string, FlaggedDependency>,
  unresolvedNames: Set<string>,
): string {
  return content.split(/\r\n|\r|\n/).map(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      return line;
    }
    if (/^(?:-|\.|\/)/.test(trimmed)) {
      const name = trimmed.split(/[\s=<>]/, 1)[0] ?? 'requirements directive';
      flaggedPackages.set(`${name}\0unsupported-source`, {
        name,
        reason: 'Editable, local-path, nested-file, or index directives require separate source and registry verification.',
      });
      unresolvedNames.add(name);
      return line;
    }

    const match = line.match(/^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]+\])?(\s*)(.*)$/);
    if (!match?.[2]) {
      return line;
    }
    const [, indentation = '', rawName = '', extras = '', spacing = '', rest = ''] = match;
    const markerIndex = rest.indexOf(';');
    const commentMatch = rest.match(/\s+#/);
    const suffixStart = [markerIndex >= 0 ? markerIndex : rest.length, commentMatch?.index ?? rest.length]
      .filter(index => index >= 0)
      .reduce((minimum, index) => Math.min(minimum, index), rest.length);
    const versionSpec = rest.slice(0, suffixStart).trim();
    const suffix = rest.slice(suffixStart);

    if (/--hash(?:=|\s)/i.test(rest)) {
      flaggedPackages.set(`${rawName}\0hash-requires-review`, {
        name: rawName,
        reason: 'Hashed requirements need hash regeneration after version pinning; manifest was left unchanged.',
      });
      unresolvedNames.add(rawName);
      return line;
    }

    const decision = resolveDependency('pypi', rawName, versionSpec);
    addDecision(decision, verifiedPackages, flaggedPackages, unresolvedNames);
    if (!decision.pinnedVersion) {
      return line;
    }
    const normalizedSpacing = spacing || '';
    return `${indentation}${rawName}${extras}${normalizedSpacing}==${decision.pinnedVersion}${suffix}`;
  }).join('\n');
}

function processCargoToml(
  content: string,
  verifiedPackages: Set<string>,
  flaggedPackages: Map<string, FlaggedDependency>,
  unresolvedNames: Set<string>,
): string {
  let dependencySection = false;
  return content.split(/\r\n|\r|\n/).map(line => {
    const trimmed = line.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      dependencySection = /^\[(?:dev-|build-)?dependencies\]$/i.test(trimmed) || /\.dependencies\]$/i.test(trimmed);
      return line;
    }
    if (!dependencySection || !trimmed || trimmed.startsWith('#')) {
      return line;
    }

    const entry = line.match(/^(\s*)(?:(["'])([^"']+)\2|([A-Za-z0-9_.-]+))\s*=\s*(.*?)(\s+#.*)?$/);
    const rawName = entry?.[3] ?? entry?.[4];
    if (!entry || !rawName) {
      return line;
    }
    const [, prefix = '', quote = '', , , value = '', comment = ''] = entry;
    let packageName = rawName;
    const packageField = value.match(/\bpackage\s*=\s*(["'])([^"']+)\1/);
    if (packageField?.[2]) {
      packageName = packageField[2];
    }

    if (/^["']/.test(value)) {
      const versionMatch = value.match(/^(["'])([^"']+)\1(.*)$/);
      if (!versionMatch?.[2]) {
        return line;
      }
      const decision = resolveDependency('cargo', packageName, versionMatch[2]);
      addDecision(decision, verifiedPackages, flaggedPackages, unresolvedNames);
      return decision.pinnedVersion
        ? `${prefix}${quote || ''}${rawName}${quote || ''} = ${quote || '"'}${decision.pinnedVersion}${quote || '"'}${comment}`
        : line;
    }

    const versionField = value.match(/(\bversion\s*=\s*)(["'])([^"']+)\2/);
      const hasExternalSource = /\b(?:git|path|registry)\s*=/.test(value);
      if (hasExternalSource) {
        flaggedPackages.set(`${packageName}\0external-source`, {
          name: packageName,
          reason: 'Cargo Git, path, or alternate-registry sources require origin and integrity verification beyond a semver pin.',
        });
        unresolvedNames.add(packageName);
        return line;
      }
      const versionSpec = versionField?.[3] ?? '';
    const decision = resolveDependency('cargo', packageName, versionSpec);
    addDecision(decision, verifiedPackages, flaggedPackages, unresolvedNames);
    if (!decision.pinnedVersion) {
      return line;
    }
    if (versionField?.[3]) {
      const healedValue = value.replace(versionField[0], `${versionField[1]}${versionField[2]}${decision.pinnedVersion}${versionField[2]}`);
      return `${prefix}${quote || ''}${rawName}${quote || ''} = ${healedValue}${comment}`;
    }
    const existingAttributes = value.trim().startsWith('{')
      ? value.trim().slice(1).replace(/}\s*$/, '').trim()
      : '';
    const attributeSuffix = existingAttributes ? `, ${existingAttributes}` : '';
    const healedValue = `{ version = "${decision.pinnedVersion}"${attributeSuffix} }`;
    return `${prefix}${quote || ''}${rawName}${quote || ''} = ${healedValue}${comment}`;
  }).join('\n');
}

/** Audits supported manifests against a bundled trust catalog and pins recognized ranges to exact versions. */
export function auditDependencyManifest(files: Array<{ path: string; content: string }>): {
  safe: boolean;
  verifiedPackages: string[];
  flaggedPackages: Array<{ name: string; reason: string; safeReplacement?: string }>;
  healedFiles: Array<{ path: string; content: string }>;
} {
  if (!Array.isArray(files) || files.length > MAX_FILE_COUNT) {
    throw new RangeError(`Dependency audit accepts at most ${MAX_FILE_COUNT} files.`);
  }
  let totalSourceChars = 0;
  for (const file of files) {
    if (typeof file?.path !== 'string' || typeof file.content !== 'string') {
      throw new TypeError('Every dependency-audit input must have a string path and content.');
    }
    totalSourceChars += file.content.length;
    if (totalSourceChars > MAX_TOTAL_SOURCE_CHARS) {
      throw new RangeError(`Dependency audit exceeds the ${MAX_TOTAL_SOURCE_CHARS}-character input limit.`);
    }
  }

  const verifiedPackages = new Set<string>();
  const flaggedPackages = new Map<string, FlaggedDependency>();
  const unresolvedNames = new Set<string>();
  const healedFiles = files.map(file => {
    const baseName = file.path.split('/').at(-1)?.toLowerCase() ?? '';
    const ecosystem = MANIFEST_ECOSYSTEMS[baseName];
    if (!ecosystem) {
      return { path: file.path, content: file.content };
    }
    const content = ecosystem === 'npm'
      ? processPackageJson(file.content, verifiedPackages, flaggedPackages, unresolvedNames)
      : ecosystem === 'pypi'
        ? processRequirementsTxt(file.content, verifiedPackages, flaggedPackages, unresolvedNames)
        : processCargoToml(file.content, verifiedPackages, flaggedPackages, unresolvedNames);
    return { path: file.path, content };
  });

  return {
    safe: unresolvedNames.size === 0,
    verifiedPackages: [...verifiedPackages].sort(),
    flaggedPackages: [...flaggedPackages.values()],
    healedFiles,
  };
}