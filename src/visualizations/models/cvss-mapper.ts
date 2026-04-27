import type { CheckResult, Severity } from '../../core/types.js';

export type CvssSource = 'real' | 'severity-mapped';

export interface CvssMapping {
  score: number;
  source: CvssSource;
}

const SEVERITY_TO_CVSS: Record<Severity, number> = {
  critical: 9.0,
  warning: 5.0,
  info: 2.0,
};

// Match `cvss=9.8` or `CVSS: 7.5` but NOT a CVSS vector spec version
// like `CVSS:3.1/AV:N/...`. The lookahead also blocks engine backtracking
// from matching just the integer part (e.g., capturing `3` from `3.1/...`).
const CVSS_NUMERIC_RE = /\bcvss[=:\s]+([\d]+(?:\.\d+)?)(?![\d./])/i;

export function mapToCvss(result: CheckResult): CvssMapping {
  const real = extractRealCvss(result);
  if (real !== undefined) return { score: real, source: 'real' };
  return { score: SEVERITY_TO_CVSS[result.severity], source: 'severity-mapped' };
}

function extractRealCvss(result: CheckResult): number | undefined {
  if (!result.evidence) return undefined;
  for (const e of result.evidence) {
    const detail = e.detail ?? '';
    const m = detail.match(CVSS_NUMERIC_RE);
    if (!m) continue;
    const score = Number.parseFloat(m[1]);
    if (Number.isFinite(score) && score >= 0 && score <= 10) return score;
  }
  return undefined;
}
