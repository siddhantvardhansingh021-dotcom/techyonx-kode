export interface PrivacyEnforcementResult {
  readonly compliantText: string;
  readonly piiRedactedCount: number;
  readonly regulationsMet: string[];
}

const MAX_TEXT_CHARS = 4_000_000;

const PII_PATTERNS: readonly { readonly kind: string; readonly expression: RegExp }[] = [
  {
    kind: 'AADHAAR',
    expression: /(?<!\d)(?:\d{4}[ -]?){2}\d{4}(?!\d)/g,
  },
  {
    kind: 'PAN',
    expression: /\b[A-Z]{5}\d{4}[A-Z]\b/gi,
  },
  {
    kind: 'SSN',
    expression: /(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)/g,
  },
  {
    kind: 'EMAIL',
    expression: /\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+\b/gi,
  },
  {
    kind: 'PHONE',
    expression: /(?<!\d)(?:\+?91[ .-]?)?[6-9]\d{4}[ .-]?\d{5}(?!\d)/g,
  },
  {
    kind: 'PHONE',
    expression: /(?<!\d)\+\d{1,3}(?:[ .()-]?\d){7,14}(?!\d)/g,
  },
  {
    kind: 'PHONE',
    expression: /(?<!\d)\d{3}[ .-]\d{3}[ .-]\d{4}(?!\d)/g,
  },
];

const REGULATIONS_MET = [
  'India Digital Personal Data Protection Act, 2023: PII redaction control applied; overall legal compliance is not certified.',
  'India Information Technology Act, 2000: sensitive-data handling control applied; overall legal compliance is not certified.',
  'EU General Data Protection Regulation: data-minimization redaction control applied; overall legal compliance is not certified.',
];

/** Redacts common PII patterns in prompts and generated text; this does not certify regulatory compliance. */
export function enforcePrivacyComplianceInCode(textOrCode: string): {
  compliantText: string;
  piiRedactedCount: number;
  regulationsMet: string[];
} {
  if (typeof textOrCode !== 'string') {
    throw new TypeError('Privacy input must be a string.');
  }
  if (textOrCode.length > MAX_TEXT_CHARS) {
    throw new RangeError(`Privacy input exceeds the ${MAX_TEXT_CHARS}-character limit.`);
  }

  let compliantText = textOrCode;
  let piiRedactedCount = 0;
  for (const { kind, expression } of PII_PATTERNS) {
    const matcher = new RegExp(expression.source, expression.flags);
    compliantText = compliantText.replace(matcher, () => {
      piiRedactedCount += 1;
      return `[REDACTED:${kind}]`;
    });
  }

  return {
    compliantText,
    piiRedactedCount,
    regulationsMet: [...REGULATIONS_MET],
  };
}