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

export function detectTyposquatting(
  skillName: string,
  trustedNames: string[],
  maxDistance = 2,
): TyposquatMatch | null {
  const normalized = skillName.toLowerCase().replace(/[-_]/g, '');

  for (const trusted of trustedNames) {
    const normalizedTrusted = trusted.toLowerCase().replace(/[-_]/g, '');

    // Exact match = not typosquatting
    if (normalized === normalizedTrusted) continue;

    const distance = levenshteinDistance(normalized, normalizedTrusted);
    if (distance > 0 && distance <= maxDistance) {
      return { skillName, trustedName: trusted, distance };
    }
  }

  return null;
}
