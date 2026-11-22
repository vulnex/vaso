/**
 * Declared dependency ranges (npm `^1.2.3`, `~1.2`, `1.x`, `>=1 <2`; PyPI
 * `==1.2.3`, `~=1.2`, `>=1.0,<1.5`) reduced to the interval of versions they
 * admit. `satisfies()` takes a concrete version; a range is judged by asking
 * whether *every* version it admits is affected — only then is a manifest
 * without a lockfile evidence of a vulnerable install.
 */

import { compareSemVer, constraintBranches, parseSemVer, satisfies } from './semver.js';

export interface VersionBounds {
  /** Lowest admitted version (inclusive); '0.0.0' when unbounded below. */
  min: string;
  /** Upper bound, exclusive; undefined when unbounded above. */
  maxExclusive?: string;
  /** Upper bound, inclusive (`<=`, exact pins). */
  maxInclusive?: string;
}

/**
 * PEP 440 pre-, post- and dev-release suffixes (`1.10.0rc1`, `2.0b2`,
 * `1.4.post1`, `3.1.dev4`) as semver: pre-releases become `-a.N` / `-b.N` /
 * `-rc.N` (a < b < rc, all before the release), a dev release `-0.dev.N`
 * (before them), and a post-release is the release itself (it only fixes
 * packaging). Without this, `1.10.0rc1` read as 1.10.0, past a `<1.10.0` fix.
 */
const PEP440_SUFFIX = /^[-_.]?(?:(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?(?:[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?$/i;

function pep440Suffix(suffix: string): string | undefined {
  const m = PEP440_SUFFIX.exec(suffix);
  if (!m) return undefined;
  const pre = m[1]?.toLowerCase();
  const kind = pre === undefined ? undefined : pre.startsWith('a') ? 'a' : pre.startsWith('b') ? 'b' : 'rc';
  if (kind) return `-${kind}.${m[2] || 0}${m[5] ? `.dev.${m[6] || 0}` : ''}`;
  if (m[5]) return m[3] ? '' : `-0.dev.${m[6] || 0}`; // `1.0.post1.dev2` is after 1.0
  return '';
}

/** `1`, `1.2`, `1.2.3` → full x.y.z (missing parts are 0). */
function full(version: string): string | undefined {
  const v = version.trim();
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(-[\w.]+)?$/.exec(v);
  if (m) return `${m[1]}.${m[2] ?? 0}.${m[3] ?? 0}${m[4] ?? ''}`;
  const p = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?([-_.]?[A-Za-z][\w.]*)$/.exec(v);
  const suffix = p ? pep440Suffix(p[4]) : undefined;
  if (!p || suffix === undefined) return undefined;
  return `${p[1]}.${p[2] ?? 0}.${p[3] ?? 0}${suffix}`;
}

/**
 * A version padded to x.y.z for comparison (`5.3` → `5.3.0`): PyPI releases
 * and lockfiles often have two parts, which `satisfies()` can't parse.
 * Returned unchanged when it isn't a plain release number.
 */
export function fullVersion(version: string): string {
  return full(version) ?? version;
}

function bump(version: string, part: 'major' | 'minor' | 'patch'): string {
  const v = parseSemVer(version)!;
  if (part === 'major') return `${v.major + 1}.0.0`;
  if (part === 'minor') return `${v.major}.${v.minor + 1}.0`;
  return `${v.major}.${v.minor}.${v.patch + 1}`;
}

function npmBounds(range: string): VersionBounds | undefined {
  const r = range.trim();
  if (!r || r === '*' || r === 'latest' || r.includes('||') || /^[a-z]+:|\/|^git/i.test(r)) return undefined;

  // 1.x / 1.2.x / 1 / 1.2 (x-ranges and partials)
  const xr = /^v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?$/i.exec(r);
  if (xr && (xr[2] === undefined || /x|\*/i.test(xr[2]) || xr[3] === undefined || /x|\*/i.test(xr[3]))) {
    const major = xr[1];
    if (xr[2] === undefined || /x|\*/i.test(xr[2])) return { min: `${major}.0.0`, maxExclusive: `${Number(major) + 1}.0.0` };
    return { min: `${major}.${xr[2]}.0`, maxExclusive: `${major}.${Number(xr[2]) + 1}.0` };
  }

  // Hyphen range `1.2.3 - 2.3.4` (inclusive); a partial top (`- 2.3`) means <2.4.0
  const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(r);
  if (hyphen) {
    const min = full(hyphen[1]);
    const top = full(hyphen[2]);
    if (!min || !top) return undefined;
    const parts = hyphen[2].replace(/^v/, '').split('.').length;
    if (parts >= 3) return { min, maxInclusive: top };
    return { min, maxExclusive: parts === 1 ? bump(top, 'major') : bump(top, 'minor') };
  }
  const caret = /^\^\s*(.+)$/.exec(r);
  if (caret) {
    const min = full(caret[1]);
    if (!min) return undefined;
    const v = parseSemVer(min)!;
    const upper = v.major > 0 ? bump(min, 'major') : v.minor > 0 ? bump(min, 'minor') : bump(min, 'patch');
    return { min, maxExclusive: upper };
  }
  const tilde = /^~\s*(.+)$/.exec(r);
  if (tilde) {
    const min = full(tilde[1]);
    if (!min) return undefined;
    const parts = tilde[1].split('.').length;
    return { min, maxExclusive: parts === 1 ? bump(min, 'major') : bump(min, 'minor') };
  }
  return comparatorBounds(r.split(/\s+/));
}

function pypiBounds(spec: string): VersionBounds | undefined {
  const parts = spec.split(',').map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0) return undefined;
  const tokens: string[] = [];
  for (const part of parts) {
    const compatible = /^~=\s*(.+)$/.exec(part);
    if (compatible) {
      const min = full(compatible[1]);
      if (!min) return undefined;
      // ~=1.2 → >=1.2,<2.0 ; ~=1.2.3 → >=1.2.3,<1.3.0
      const upper = compatible[1].split('.').length <= 2 ? bump(min, 'major') : bump(min, 'minor');
      tokens.push(`>=${min}`, `<${upper}`);
      continue;
    }
    const pinned = /^===?\s*(.+)$/.exec(part);
    if (pinned) {
      tokens.push(`=${pinned[1].trim()}`);
      continue;
    }
    if (/^!=/.test(part)) continue; // an exclusion doesn't move the interval
    tokens.push(part.replace(/\s+/g, ''));
  }
  return comparatorBounds(tokens);
}

/** `>=a <b`, `>a`, `<=b`, `=v` comparator lists. */
function comparatorBounds(tokens: string[]): VersionBounds | undefined {
  const bounds: VersionBounds = { min: '0.0.0' };
  for (const token of tokens) {
    const m = /^(>=|<=|>|<|=)?\s*(.+)$/.exec(token);
    if (!m) return undefined;
    const version = full(m[2]);
    if (!version) return undefined;
    switch (m[1] ?? '=') {
      case '>=': bounds.min = version; break;
      case '>': bounds.min = bump(version, 'patch'); break;
      case '<': bounds.maxExclusive = version; break;
      case '<=': bounds.maxInclusive = version; break;
      case '=': bounds.min = version; bounds.maxInclusive = version; break;
    }
  }
  return bounds;
}

export function rangeBounds(range: string, ecosystem: 'npm' | 'pypi' = 'npm'): VersionBounds | undefined {
  return ecosystem === 'pypi' ? pypiBounds(range) : npmBounds(range);
}

/**
 * An exact version (`1.2.3`, `=1.2.3`, `==1.2.3`), or undefined when the spec
 * is a range. A partial version is exact only after PEP 440 `==` (`==5.3` is
 * 5.3.0); in npm `0.1` and `=0.1` are x-ranges (any 0.1.x — npm installs the
 * newest).
 */
export function exactVersion(spec: string): string | undefined {
  const m = /^(===?|=)?\s*v?(\d+\.\d+(\.\d+)?(?:-[\w.]+)?)$/.exec(spec.trim());
  if (!m) {
    // PEP 440 pin of a pre-release (`==1.10.0rc1`)
    const pin = /^===?\s*(\d+(?:\.\d+)*[-_.]?[A-Za-z][\w.]*)$/.exec(spec.trim());
    return pin ? full(pin[1]) : undefined;
  }
  if (!m[3] && !m[1]?.startsWith('==')) return undefined;
  return full(m[2]);
}

/**
 * Whether every version a range admits falls inside an affected constraint:
 * the lowest admitted version is affected, and the range ends at or below the
 * first fixed release (or its inclusive top is itself affected). With several
 * affected branches (`… || …`), the range must sit inside one of them, bounded
 * by that branch's own upper comparator — one fixed version can't speak for
 * every release line.
 */
export function rangeEntirelyAffected(
  range: string,
  ecosystem: 'npm' | 'pypi',
  affected: string,
  fixedVersion: string | undefined,
): boolean {
  const bounds = rangeBounds(range, ecosystem);
  if (!bounds) return false;
  const branches = constraintBranches(affected);
  if (branches.length > 1) {
    return branches.some((branch) => withinBranch(bounds, branch, branchUpperBound(branch)));
  }
  // No fixed release named: the affected range's own upper bound (`<=1.0.1`) is where it ends
  return withinBranch(bounds, affected, fixedVersion ?? branchUpperBound(affected));
}

function withinBranch(bounds: VersionBounds, affected: string, fixedVersion: string | undefined): boolean {
  if (!satisfies(bounds.min, affected)) return false;
  if (bounds.maxInclusive) return satisfies(bounds.maxInclusive, affected);
  if (!bounds.maxExclusive || !fixedVersion) return false;
  const top = parseSemVer(bounds.maxExclusive);
  const fixed = parseSemVer(fixedVersion);
  return Boolean(top && fixed && compareSemVer(top, fixed) <= 0);
}

/** `>=7.0.0 <7.5.10` → `7.5.10`; `<=2.88.2` → `2.88.3`; undefined when unbounded above. */
function branchUpperBound(branch: string): string | undefined {
  for (const token of branch.split(/\s+/)) {
    const lt = /^<(\d.*)$/.exec(token);
    if (lt) return full(lt[1]);
    const le = /^<=(\d.*)$/.exec(token);
    if (le) {
      const v = full(le[1]);
      return v ? bump(v, 'patch') : undefined;
    }
  }
  return undefined;
}
