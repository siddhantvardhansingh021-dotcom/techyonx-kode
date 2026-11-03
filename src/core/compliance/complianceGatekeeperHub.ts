import { computeGeneratedCodeBundleHash } from '../security/cryptographicCodeSigner';
import { enforcePrivacyComplianceInCode } from './dpdpGdprCodeCompliance';
import {
  verifyCleanRoomOriginality,
  type CleanRoomOutputFile,
} from './cleanRoomCodeVerifier';
import {
  auditOpenSourceLicenses,
  type LicenseAuditResult,
} from './openSourceLicenseGuard';
import {
  auditDependencyManifest,
  type DependencyAuditResult,
} from './dependencySupplyChainAuditor';
import {
  generateIpOwnershipCertificate,
  verifyIpOwnershipCertificate,
  type IpOwnershipCertificate,
} from './ipOwnershipCertificateGenerator';

export type ComplianceGateStatus = 'APPROVED' | 'BLOCKED';

export interface MasterComplianceGateResult {
  readonly status: ComplianceGateStatus;
  readonly compliant: boolean;
  readonly projectName: string;
  readonly inputBundleHash: string;
  readonly inputBundleHashVerified: boolean;
  readonly healedBundleHash: string | null;
  readonly healedFiles: Array<{ path: string; content: string }>;
  readonly piiRedactedCount: number;
  readonly regulationsMet: string[];
  readonly cleanRoomAudit: {
    readonly passed: boolean;
    readonly originalityScore: number;
    readonly auditNotes: string[];
  };
  readonly licenseAudit: LicenseAuditResult;
  readonly supplyChainStatus: Pick<DependencyAuditResult, 'safe' | 'verifiedPackages' | 'flaggedPackages'>;
  readonly ipCertificate: IpOwnershipCertificate | null;
  readonly blockedReasons: string[];
}

const MAX_PROJECT_NAME_CHARS = 200;
const SHA256_HEX = /^[a-f0-9]{64}$/i;

function normalizeProjectName(projectName: string): string {
  return projectName
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .trim();
}

function makeEmptyLicenseAudit(recommendation: string): LicenseAuditResult {
  return {
    compliant: false,
    detectedLicenses: [],
    spdxIdentifier: 'NOASSERTION',
    recommendation,
  };
}

function makeEmptySupplyChainStatus(): Pick<DependencyAuditResult, 'safe' | 'verifiedPackages' | 'flaggedPackages'> {
  return { safe: false, verifiedPackages: [], flaggedPackages: [] };
}

function emptyCleanRoomAudit(note: string): MasterComplianceGateResult['cleanRoomAudit'] {
  return { passed: false, originalityScore: 0, auditNotes: [note] };
}

function result(input: {
  readonly status: ComplianceGateStatus;
  readonly projectName: string;
  readonly inputBundleHash: string;
  readonly inputBundleHashVerified: boolean;
  readonly healedBundleHash?: string | null;
  readonly healedFiles?: Array<{ path: string; content: string }>;
  readonly piiRedactedCount?: number;
  readonly regulationsMet?: string[];
  readonly cleanRoomAudit?: MasterComplianceGateResult['cleanRoomAudit'];
  readonly licenseAudit?: LicenseAuditResult;
  readonly supplyChainStatus?: MasterComplianceGateResult['supplyChainStatus'];
  readonly ipCertificate?: IpOwnershipCertificate | null;
  readonly blockedReasons?: string[];
}): MasterComplianceGateResult {
  return {
    status: input.status,
    compliant: input.status === 'APPROVED',
    projectName: input.projectName,
    inputBundleHash: input.inputBundleHash,
    inputBundleHashVerified: input.inputBundleHashVerified,
    healedBundleHash: input.healedBundleHash ?? null,
    healedFiles: input.healedFiles ?? [],
    piiRedactedCount: input.piiRedactedCount ?? 0,
    regulationsMet: input.regulationsMet ?? [],
    cleanRoomAudit: input.cleanRoomAudit ?? emptyCleanRoomAudit('Compliance pipeline did not complete clean-room verification.'),
    licenseAudit: input.licenseAudit ?? makeEmptyLicenseAudit('License audit did not complete.'),
    supplyChainStatus: input.supplyChainStatus ?? makeEmptySupplyChainStatus(),
    ipCertificate: input.ipCertificate ?? null,
    blockedReasons: input.blockedReasons ?? [],
  };
}

/** Verifies the source digest, sanitizes data, runs legal/supply-chain gates, and certifies only the healed bundle. */
export function runMasterComplianceGatekeeper(
  projectName: string,
  files: Array<{ path: string; content: string }>,
  bundleHash: string,
): MasterComplianceGateResult {
  let normalizedProjectName = typeof projectName === 'string'
    ? normalizeProjectName(projectName)
    : '';
  const blockedReasons: string[] = [];

  if (
    !normalizedProjectName ||
    normalizedProjectName.length > MAX_PROJECT_NAME_CHARS ||
    !Array.isArray(files) ||
    typeof bundleHash !== 'string' ||
    !SHA256_HEX.test(bundleHash)
  ) {
    return result({
      status: 'BLOCKED',
      projectName: '',
      inputBundleHash: typeof bundleHash === 'string' ? bundleHash : '',
      inputBundleHashVerified: false,
      blockedReasons: ['Project name, file list, or SHA-256 bundle hash is invalid.'],
    });
  }

  const projectPrivacy = enforcePrivacyComplianceInCode(normalizedProjectName);
  normalizedProjectName = projectPrivacy.compliantText;
  let totalPiiRedactedCount = projectPrivacy.piiRedactedCount;
  const regulationsMet = [...projectPrivacy.regulationsMet];

  let actualInputBundleHash: string;
  try {
    actualInputBundleHash = computeGeneratedCodeBundleHash(files);
  } catch {
    return result({
      status: 'BLOCKED',
      projectName: normalizedProjectName,
      inputBundleHash: bundleHash,
      inputBundleHashVerified: false,
      blockedReasons: ['Input files failed canonical path, size, uniqueness, or content validation.'],
    });
  }
  const inputBundleHashVerified = actualInputBundleHash === bundleHash.toLowerCase();
  if (!inputBundleHashVerified) {
    blockedReasons.push('Supplied bundle hash does not match the canonical SHA-256 Merkle root of the input files.');
  }

  let privacyCleanedFiles: Array<{ path: string; content: string }>;
  try {
    privacyCleanedFiles = files.map(file => {
      const privacyResult = enforcePrivacyComplianceInCode(file.content);
      totalPiiRedactedCount += privacyResult.piiRedactedCount;
      for (const regulation of privacyResult.regulationsMet) {
        if (!regulationsMet.includes(regulation)) {
          regulationsMet.push(regulation);
        }
      }
      return { path: file.path, content: privacyResult.compliantText };
    });
  } catch {
    return result({
      status: 'BLOCKED',
      projectName: '',
      inputBundleHash: bundleHash,
      inputBundleHashVerified,
      piiRedactedCount: totalPiiRedactedCount,
      regulationsMet,
      blockedReasons: [...blockedReasons, 'Privacy inspection rejected an oversized or invalid input.'],
    });
  }

  let cleanRoomResult: ReturnType<typeof verifyCleanRoomOriginality>;
  try {
    cleanRoomResult = verifyCleanRoomOriginality(privacyCleanedFiles);
  } catch {
    return result({
      status: 'BLOCKED',
      projectName: normalizedProjectName,
      inputBundleHash: bundleHash,
      inputBundleHashVerified,
      piiRedactedCount: totalPiiRedactedCount,
      regulationsMet,
      blockedReasons: [...blockedReasons, 'Clean-room provenance verification failed input validation.'],
    });
  }

  let supplyChainResult: DependencyAuditResult;
  try {
    supplyChainResult = auditDependencyManifest(cleanRoomResult.cleanedFiles);
  } catch {
    return result({
      status: 'BLOCKED',
      projectName: normalizedProjectName,
      inputBundleHash: bundleHash,
      inputBundleHashVerified,
      healedFiles: cleanRoomResult.cleanedFiles,
      piiRedactedCount: totalPiiRedactedCount,
      regulationsMet,
      cleanRoomAudit: {
        passed: cleanRoomResult.passed,
        originalityScore: cleanRoomResult.originalityScore,
        auditNotes: cleanRoomResult.auditNotes,
      },
      blockedReasons: [...blockedReasons, 'Dependency supply-chain audit failed input validation.'],
    });
  }

  const healedFiles: CleanRoomOutputFile[] = supplyChainResult.healedFiles;
  const licenseAudit = auditOpenSourceLicenses(healedFiles);
  if (!cleanRoomResult.passed) {
    blockedReasons.push('Clean-room provenance review did not pass.');
  }
  if (!licenseAudit.compliant) {
    blockedReasons.push(licenseAudit.recommendation);
  }
  if (!supplyChainResult.safe) {
    blockedReasons.push('One or more dependencies are untrusted, deprecated, or require source review.');
  }

  let healedBundleHash: string;
  try {
    healedBundleHash = computeGeneratedCodeBundleHash(healedFiles);
  } catch {
    return result({
      status: 'BLOCKED',
      projectName: normalizedProjectName,
      inputBundleHash: bundleHash,
      inputBundleHashVerified,
      healedFiles,
      piiRedactedCount: totalPiiRedactedCount,
      regulationsMet,
      cleanRoomAudit: {
        passed: cleanRoomResult.passed,
        originalityScore: cleanRoomResult.originalityScore,
        auditNotes: cleanRoomResult.auditNotes,
      },
      licenseAudit,
      supplyChainStatus: {
        safe: supplyChainResult.safe,
        verifiedPackages: supplyChainResult.verifiedPackages,
        flaggedPackages: supplyChainResult.flaggedPackages,
      },
      blockedReasons: [...blockedReasons, 'Healed output could not be canonically hashed.'],
    });
  }

  let ipCertificate: IpOwnershipCertificate | null = null;
  if (inputBundleHashVerified && blockedReasons.length === 0) {
    try {
      ipCertificate = generateIpOwnershipCertificate(
        normalizedProjectName,
        healedBundleHash,
        cleanRoomResult.originalityScore,
        licenseAudit.spdxIdentifier,
      );
      if (!verifyIpOwnershipCertificate(
        normalizedProjectName,
        healedBundleHash,
        cleanRoomResult.originalityScore,
        ipCertificate,
      )) {
        ipCertificate = null;
        blockedReasons.push('Generated IP provenance certificate failed local digest verification.');
      }
    } catch {
      blockedReasons.push('IP provenance certificate could not be generated from the audited license evidence.');
    }
  }
  if (!ipCertificate && blockedReasons.length === 0) {
    blockedReasons.push('IP provenance certificate was not issued.');
  }

  return result({
    status: blockedReasons.length === 0 ? 'APPROVED' : 'BLOCKED',
    projectName: normalizedProjectName,
    inputBundleHash: bundleHash.toLowerCase(),
    inputBundleHashVerified,
    healedBundleHash,
    healedFiles,
    piiRedactedCount: totalPiiRedactedCount,
    regulationsMet,
    cleanRoomAudit: {
      passed: cleanRoomResult.passed,
      originalityScore: cleanRoomResult.originalityScore,
      auditNotes: cleanRoomResult.auditNotes,
    },
    licenseAudit,
    supplyChainStatus: {
      safe: supplyChainResult.safe,
      verifiedPackages: supplyChainResult.verifiedPackages,
      flaggedPackages: supplyChainResult.flaggedPackages,
    },
    ipCertificate,
    blockedReasons,
  });
}