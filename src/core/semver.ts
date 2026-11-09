export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: string | undefined;
  /**
   * Correction-release number (`2026.7.1-1` → 1), set only when parsed with
   * `correctionSuffix`. A correction ships after its base release and sorts
   * between it and the next patch.
   */
  correction?: number;
  raw: string;
}

export interface VersionParseOptions {
  /**
   * Read a numeric-only suffix (`2026.7.1-1`) as a correction release rather
   * than a prerelease. OpenClaw publishes these on npm after the base calendar
   * release; under plain semver `2026.7.1-1 < 2026.7.1`, which is backwards.
   * Off by default — elsewhere `1.0.0-1` keeps its semver meaning.
   */
  correctionSuffix?: boolean;
}

const SEMVER_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.]+))?/;

export function parseSemVer(version: string, opts: VersionParseOptions = {}): SemVer | null {
  const m = SEMVER_RE.exec(version.trim());
  if (!m) return null;
  const correction = opts.correctionSuffix && m[4] && /^\d+$/.test(m[4]) ? parseInt(m[4], 10) : undefined;
  return {
    major: parseInt(m[1], 10),
    minor: parseInt(m[2], 10),
    patch: parseInt(m[3], 10),
    prerelease: correction === undefined ? m[4] ?? undefined : undefined,
    ...(correction !== undefined ? { correction } : {}),
    raw: version.trim(),
  };
}

export function compareSemVer(a: SemVer, b: SemVer): -1 | 0 | 1 {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  const ac = a.correction ?? 0;
  const bc = b.correction ?? 0;
  if (ac !== bc) return ac < bc ? -1 : 1;

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

function parseComparator(token: string, opts: VersionParseOptions): Comparator | null {
  const m = /^([<>]=?|=)?(.+)$/.exec(token.trim());
  if (!m) return null;
  const op = (m[1] || '=') as Comparator['op'];
  const ver = parseSemVer(m[2], opts);
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
 * Tokens separated by spaces are ANDed together; `||` separates alternatives.
 * Supports: <, <=, >, >=, = operators.
 * Example: ">=1.2.0 <1.5.0", ">=6.0.0 <6.2.3 || >=7.0.0 <7.5.10"
 */
/** Compare two version strings; unparseable versions sort before parseable ones. */
export function compareVersions(a: string, b: string, opts: VersionParseOptions = {}): number {
  const pa = parseSemVer(a, opts);
  const pb = parseSemVer(b, opts);
  if (!pa || !pb) return pa ? 1 : pb ? -1 : 0;
  return compareSemVer(pa, pb);
}

/**
 * A constraint's `||`-separated alternatives (`>=7.0.0 <7.5.10 || >=8.0.0
 * <8.17.1`): an advisory with one affected range per release line.
 */
export function constraintBranches(constraint: string): string[] {
  return constraint.split('||').map((b) => b.trim()).filter(Boolean);
}

export function satisfies(version: string, constraint: string, opts: VersionParseOptions = {}): boolean {
  const ver = parseSemVer(version, opts);
  if (!ver) return false;
  const branches = constraintBranches(constraint);
  if (branches.length > 1) return branches.some((b) => satisfies(version, b, opts));

  const tokens = constraint.trim().split(/\s+/);
  for (const token of tokens) {
    const comp = parseComparator(token, opts);
    if (!comp) return false;
    if (!matchComparator(ver, comp)) return false;
  }
  return true;
}
