import { createHash, timingSafeEqual } from 'node:crypto';

export interface IpOwnershipCertificate {
  readonly certificateId: string;
  readonly issuedBy: string;
  readonly legalStatement: string;
  readonly spdxLicense: string;
  readonly issuedAt: string;
}

const ISSUER = 'Techyonx kode, Techyonx Global Private Limited';
const CERTIFICATE_PREFIX = 'sha256:v1:';
const ALLOWED_SPDX_LICENSES = new Set(['MIT', 'Apache-2.0', 'BSD-3-Clause', 'NOASSERTION']);

interface CertificatePayload {
  readonly version: 1;
  readonly projectName: string;
  readonly bundleHash: string;
  readonly originalityScore: number;
  readonly issuedBy: string;
  readonly legalStatement: string;
  readonly spdxLicense: string;
  readonly issuedAt: string;
}

function normalizeCertificateInputs(
  projectName: string,
  bundleHash: string,
  originalityScore: number,
  spdxLicense: string,
): { projectName: string; bundleHash: string; originalityScore: number; spdxLicense: string } {
  if (typeof projectName !== 'string') {
    throw new TypeError('Project name must be a string.');
  }
  const normalizedProjectName = projectName
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .trim()
    .slice(0, 200);
  if (!normalizedProjectName) {
    throw new TypeError('Project name must not be empty.');
  }
  if (typeof bundleHash !== 'string' || !/^[a-f0-9]{64}$/i.test(bundleHash)) {
    throw new TypeError('Bundle hash must be a 64-character SHA-256 hexadecimal digest.');
  }
  if (!Number.isFinite(originalityScore) || originalityScore < 0 || originalityScore > 100) {
    throw new RangeError('Originality score must be between 0 and 100.');
  }
  if (!ALLOWED_SPDX_LICENSES.has(spdxLicense)) {
    throw new TypeError('SPDX license must be an approved identifier or NOASSERTION.');
  }
  return {
    projectName: normalizedProjectName,
    bundleHash: bundleHash.toLowerCase(),
    originalityScore: Math.round(originalityScore * 100) / 100,
    spdxLicense,
  };
}

function createLegalStatement(
  projectName: string,
  bundleHash: string,
  originalityScore: number,
  spdxLicense: string,
): string {
  return [
    `Techyonx kode records that it generated or processed the code bundle for project "${projectName}".`,
    `The recorded bundle SHA-256 Merkle root is ${bundleHash}; the clean-room originality heuristic score is ${originalityScore.toFixed(2)}%.`,
    `The supplied SPDX license evidence is ${spdxLicense}. This record does not transfer or guarantee copyright, exclusivity, clean-room authorship, or 100% commercial rights.`,
    'Rights remain subject to the user-provided inputs, third-party notices and licenses, contributor agreements, applicable terms, and applicable law. This record is not legal advice or proof of ownership.',
  ].join(' ');
}

function canonicalCertificatePayload(payload: CertificatePayload): string {
  return JSON.stringify({
    version: payload.version,
    projectName: payload.projectName,
    bundleHash: payload.bundleHash,
    originalityScore: payload.originalityScore,
    issuedBy: payload.issuedBy,
    legalStatement: payload.legalStatement,
    spdxLicense: payload.spdxLicense,
    issuedAt: payload.issuedAt,
  });
}

function calculateCertificateId(payload: CertificatePayload): string {
  return `${CERTIFICATE_PREFIX}${createHash('sha256')
    .update(canonicalCertificatePayload(payload), 'utf8')
    .digest('hex')}`;
}

/** Issues a tamper-evident digest/provenance record; it does not certify legal title or ownership. */
export function generateIpOwnershipCertificate(
  projectName: string,
  bundleHash: string,
  originalityScore: number,
  spdxLicense = 'NOASSERTION',
): {
  certificateId: string;
  issuedBy: string;
  legalStatement: string;
  spdxLicense: string;
  issuedAt: string;
} {
  const normalized = normalizeCertificateInputs(projectName, bundleHash, originalityScore, spdxLicense);
  const issuedAt = new Date().toISOString();
  const legalStatement = createLegalStatement(
    normalized.projectName,
    normalized.bundleHash,
    normalized.originalityScore,
    normalized.spdxLicense,
  );
  const payload: CertificatePayload = {
    version: 1,
    ...normalized,
    issuedBy: ISSUER,
    legalStatement,
    issuedAt,
  };
  return {
    certificateId: calculateCertificateId(payload),
    issuedBy: ISSUER,
    legalStatement,
    spdxLicense: normalized.spdxLicense,
    issuedAt,
  };
}

/** Recomputes the certificate digest against independently supplied project and bundle evidence. */
export function verifyIpOwnershipCertificate(
  projectName: string,
  bundleHash: string,
  originalityScore: number,
  certificate: IpOwnershipCertificate,
): boolean {
  try {
    if (
      typeof certificate?.certificateId !== 'string' ||
      !certificate.certificateId.startsWith(CERTIFICATE_PREFIX) ||
      certificate.issuedBy !== ISSUER ||
      typeof certificate.issuedAt !== 'string' ||
      !Number.isFinite(Date.parse(certificate.issuedAt))
    ) {
      return false;
    }
    const normalized = normalizeCertificateInputs(
      projectName,
      bundleHash,
      originalityScore,
      certificate.spdxLicense,
    );
    const payload: CertificatePayload = {
      version: 1,
      ...normalized,
      issuedBy: ISSUER,
      legalStatement: createLegalStatement(
        normalized.projectName,
        normalized.bundleHash,
        normalized.originalityScore,
        normalized.spdxLicense,
      ),
      issuedAt: certificate.issuedAt,
    };
    if (certificate.legalStatement !== payload.legalStatement) {
      return false;
    }
    const expected = Buffer.from(calculateCertificateId(payload), 'utf8');
    const actual = Buffer.from(certificate.certificateId, 'utf8');
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}