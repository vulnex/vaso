export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: string | undefined;
  raw: string;
}

const SEMVER_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.]+))?/;

export function parseSemVer(version: string): SemVer | null {
  const m = SEMVER_RE.exec(version.trim());
  if (!m) return null;
  return {
    major: parseInt(m[1], 10),
    minor: parseInt(m[2], 10),
    patch: parseInt(m[3], 10),
    prerelease: m[4] ?? undefined,
    raw: version.trim(),
  };
}

export function compareSemVer(a: SemVer, b: SemVer): -1 | 0 | 1 {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;

  // No prerelease > has prerelease (1.0.0 > 1.0.0-beta)
  if (!a.prerelease && b.prerelease) return 1;
  if (a.prerelease && !b.prerelease) return -1;
  if (a.prerelease && b.prerelease) {
    const aParts = a.prerelease.split('.');
    const bParts = b.prerelease.split('.');
    const len = Math.max(aParts.length, bParts.length);
    for (let i = 0; i < len; i++) {
      if (i >= aParts.length) return -1;
      if (i >= bParts.length) return 1;
      const aNum = parseInt(aParts[i], 10);
      const bNum = parseInt(bParts[i], 10);
      const aIsNum = !isNaN(aNum);
      const bIsNum = !isNaN(bNum);
      if (aIsNum && bIsNum) {
        if (aNum !== bNum) return aNum < bNum ? -1 : 1;
      } else if (aIsNum) {
        return -1; // numeric < string
      } else if (bIsNum) {
        return 1;
      } else {
        if (aParts[i] < bParts[i]) return -1;
        if (aParts[i] > bParts[i]) return 1;
      }
    }
  }
  return 0;
}

interface Comparator {
  op: '<' | '<=' | '>' | '>=' | '=';
  ver: SemVer;
}

function parseComparator(token: string): Comparator | null {
  const m = /^([<>]=?|=)?(.+)$/.exec(token.trim());
  if (!m) return null;
  const op = (m[1] || '=') as Comparator['op'];
  const ver = parseSemVer(m[2]);
  if (!ver) return null;
  return { op, ver };
}

function matchComparator(version: SemVer, comp: Comparator): boolean {
  const cmp = compareSemVer(version, comp.ver);
  switch (comp.op) {
    case '=': return cmp === 0;
    case '<': return cmp === -1;
    case '<=': return cmp <= 0;
    case '>': return cmp === 1;
    case '>=': return cmp >= 0;
  }
}

/**
 * Check if a version satisfies a constraint string.
 * Tokens separated by spaces are ANDed together.
 * Supports: <, <=, >, >=, = operators.
 * Example: ">=1.2.0 <1.5.0"
 */
export function satisfies(version: string, constraint: string): boolean {
  const ver = parseSemVer(version);
  if (!ver) return false;

  const tokens = constraint.trim().split(/\s+/);
  for (const token of tokens) {
    const comp = parseComparator(token);
    if (!comp) return false;
    if (!matchComparator(ver, comp)) return false;
  }
  return true;
}
