export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;

  if (m === 0) return n;
  if (n === 0) return m;

  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,      // deletion
        dp[i][j - 1] + 1,      // insertion
        dp[i - 1][j - 1] + cost // substitution
      );
    }
  }

  return dp[m][n];
}

export interface TyposquatMatch {
  skillName: string;
  trustedName: string;
  distance: number;
}

/**
 * Optimal string alignment distance: Levenshtein plus adjacent transposition
 * as a single edit ("githbu" → "github" is 1), the most common real typo.
 */
export function typoDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[m][n];
}

/**
 * Edits tolerated before a name counts as a typosquat, scaled by the trusted
 * name's length. A flat 2 flagged ordinary words: "research" is 2 edits from
 * "websearch" (normalized "web-search"). Short names must match exactly.
 */
export function allowedTypoEdits(trustedLength: number): number {
  if (trustedLength <= 4) return 0;
  if (trustedLength <= 9) return 1;
  return 2;
}

/** Endings added to a whole word (`calendar` → `calendars`). */
const ADDED_ENDINGS = new Set(['s', 'es', 'ing', 'ed']);
/** Endings that replace a final `e` (`translate` → `translator`). */
const E_ENDINGS = new Set(['or', 'er', 'ors', 'ers', 'ion', 'ions', 'ing', 'ed', 'es']);

/**
 * `calendars` / `calendar`, `translate` / `translator`: another form of the
 * same word — an ordinary name, not a lookalike. A typo changes the stem
 * (`calendr`, `weahter`, `githubhelpr`, `calculater`).
 */
export function isInflection(a: string, b: string): boolean {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  if (i < 4) return false;
  const [x, y] = [a.slice(i), b.slice(i)].sort((p, q) => p.length - q.length);
  return (x === '' && ADDED_ENDINGS.has(y)) || (x === 'e' && E_ENDINGS.has(y));
}

export function detectTyposquatting(
  skillName: string,
  trustedNames: string[],
  maxDistance?: number,
): TyposquatMatch | null {
  const normalized = skillName.toLowerCase().replace(/[-_]/g, '');
  const normalizedTrusted = trustedNames.map(t => t.toLowerCase().replace(/[-_]/g, ''));

  // A name that IS a trusted name can't be a typosquat of a neighboring
  // trusted name (server-github is distance 2 from server-gitlab; both are
  // legitimate). Without this, every trusted pair within maxDistance of each
  // other flags itself.
  if (normalizedTrusted.includes(normalized)) return null;

  for (let i = 0; i < trustedNames.length; i++) {
    const trusted = trustedNames[i];
    if (isInflection(normalized, normalizedTrusted[i])) continue;
    const limit = maxDistance ?? allowedTypoEdits(normalizedTrusted[i].length);
    const distance = typoDistance(normalized, normalizedTrusted[i]);
    if (distance > 0 && distance <= limit) {
      return { skillName, trustedName: trusted, distance };
    }
  }

  return null;
}
