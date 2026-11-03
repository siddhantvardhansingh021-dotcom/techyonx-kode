export interface CleanRoomInputFile {
  readonly path: string;
  readonly content: string;
}

export interface CleanRoomOutputFile {
  readonly path: string;
  readonly content: string;
}

const MAX_FILE_COUNT = 20_000;
const MAX_TOTAL_SOURCE_CHARS = 16_000_000;
const TOOL_WATERMARK_COMMENT = /^\s*(?:\/\/|#|\/\*+|\*|<!--)\s*(?:generated|created|written)\s+(?:by|with)\s+(?:github\s+copilot|copilot|cursor|chatgpt|openai|claude|codeium|tabnine|replit)(?:\b|\s*[:.-])[^\r\n]*(?:\*\/|-->)?\s*$/i;
const LEGAL_ATTRIBUTION = /\b(?:copyright(?:\s*\(c\))?|all rights reserved|spdx-license-identifier|licensed under|license agreement|proprietary|confidential|third[- ]party source)\b/i;
const THIRD_PARTY_SOURCE_MARKER = /\b(?:all rights reserved|proprietary|confidential|third[- ]party source|licensed under the (?:gnu|mozilla|eclipse|common development and distribution))\b/i;

interface CleanedContent {
  readonly content: string;
  readonly removedWatermarks: number;
  readonly legalLines: number[];
  readonly thirdPartySignals: number;
}

function cleanWatermarks(content: string): CleanedContent {
  const lines = content.split(/\r\n|\r|\n/);
  const output: string[] = [];
  const legalLines: number[] = [];
  let removedWatermarks = 0;
  let thirdPartySignals = 0;

  lines.forEach((line, index) => {
    if (TOOL_WATERMARK_COMMENT.test(line)) {
      removedWatermarks += 1;
      return;
    }
    if (LEGAL_ATTRIBUTION.test(line)) {
      legalLines.push(index + 1);
    }
    if (THIRD_PARTY_SOURCE_MARKER.test(line)) {
      thirdPartySignals += 1;
    }
    output.push(line);
  });

  return {
    content: output.join('\n'),
    removedWatermarks,
    legalLines,
    thirdPartySignals,
  };
}

function normalizedFingerprint(content: string): string {
  return content
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0)
    .join('\n');
}

/** Checks provenance signals only; source inspection cannot prove clean-room authorship. */
export function verifyCleanRoomOriginality(files: Array<{ path: string; content: string }>): {
  passed: boolean;
  originalityScore: number;
  cleanedFiles: Array<{ path: string; content: string }>;
  auditNotes: string[];
} {
  if (!Array.isArray(files) || files.length > MAX_FILE_COUNT) {
    throw new RangeError(`Clean-room verification accepts at most ${MAX_FILE_COUNT} files.`);
  }

  let totalSourceChars = 0;
  for (const file of files) {
    if (typeof file?.path !== 'string' || typeof file.content !== 'string') {
      throw new TypeError('Every clean-room input must have a string path and content.');
    }
    totalSourceChars += file.content.length;
    if (totalSourceChars > MAX_TOTAL_SOURCE_CHARS) {
      throw new RangeError(`Clean-room verification exceeds the ${MAX_TOTAL_SOURCE_CHARS}-character source limit.`);
    }
  }

  const notes = [
    'This score is a source-only heuristic. It cannot prove first-principles authorship or establish that code is not copied from an unprovided source corpus.',
    'Copyright, SPDX, license, proprietary, and confidentiality notices are preserved as provenance evidence; review them before redistribution rather than deleting legal attribution.',
  ];
  const cleanedFiles: CleanRoomOutputFile[] = [];
  const fingerprints = new Map<string, string[]>();
  let score = 100;
  let legalBlockers = 0;
  let removedWatermarkCount = 0;

  for (const file of files) {
    const cleaned = cleanWatermarks(file.content);
    cleanedFiles.push({ path: file.path, content: cleaned.content });
    removedWatermarkCount += cleaned.removedWatermarks;

    if (cleaned.legalLines.length > 0) {
      notes.push(`${file.path}: preserved legal/provenance notices on line${cleaned.legalLines.length === 1 ? '' : 's'} ${cleaned.legalLines.join(', ')}.`);
    }
    if (cleaned.thirdPartySignals > 0) {
      legalBlockers += cleaned.thirdPartySignals;
      score -= Math.min(45, cleaned.thirdPartySignals * 25);
      notes.push(`${file.path}: third-party, proprietary, or confidentiality provenance requires legal review; no notice was removed.`);
    }
    if (cleaned.removedWatermarks > 0) {
      notes.push(`${file.path}: removed ${cleaned.removedWatermarks} non-legal AI/tool watermark comment${cleaned.removedWatermarks === 1 ? '' : 's'}.`);
    }

    const fingerprint = normalizedFingerprint(cleaned.content);
    if (fingerprint.length >= 240) {
      const paths = fingerprints.get(fingerprint) ?? [];
      paths.push(file.path);
      fingerprints.set(fingerprint, paths);
    }
  }

  let duplicateGroups = 0;
  for (const paths of fingerprints.values()) {
    if (paths.length > 1) {
      duplicateGroups += 1;
      score -= 15;
      notes.push(`Identical substantial content appears in multiple files (${paths.join(', ')}); confirm it is intentional and independently authored.`);
    }
  }

  if (removedWatermarkCount === 0 && legalBlockers === 0 && duplicateGroups === 0) {
    notes.push('No recognized third-party provenance markers, tool watermarks, or substantial duplicate files were found.');
  }

  const originalityScore = Math.max(0, Math.min(100, Math.round(score)));
  return {
    passed: legalBlockers === 0 && duplicateGroups === 0 && originalityScore >= 80,
    originalityScore,
    cleanedFiles,
    auditNotes: notes,
  };
}