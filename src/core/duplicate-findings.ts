import type { CheckResult, Evidence } from './types.js';

/**
 * Generic credential-permission checks walk the adapter's credential paths, so
 * one loose file was reported up to three times: by CFG-003 (credential paths
 * that are also loaded config files), by POL-003 (every credential path), and
 * by the agent's own permission check (DEV-002, GEM-002, QC-002, CUR-004, …).
 * Each copy cost score. Within an installation, a generic finding for a file
 * is dropped when a more specific check already reports that file's mode:
 * agent checks first, then CFG-003 (fixable) ahead of POL-003.
 */
const GENERIC_PERMISSION_CHECKS = ['CFG-003', 'POL-003'];

// Evidence that is about the file's mode — not, say, a plaintext key found in
// the same file, which must never hide a permission finding.
const PERMISSION_EVIDENCE = /\b(?:mode|permissions?)[:\s]+0?[0-7]{3}\b|\breadable(?: or writable)? by (?:group|other|all)\b|\bworld-(?:readable|writable)\b/i;

function isPermissionEvidence(e: Evidence): boolean {
  return PERMISSION_EVIDENCE.test(`${e.snippet ?? ''} ${e.detail ?? ''}`);
}

export function dedupePermissionFindings(results: CheckResult[]): CheckResult[] {
  const reportedBy = new Map<string, string>(); // file → check id that reports its mode
  const record = (r: CheckResult) => {
    for (const e of r.evidence ?? []) {
      if (e.file && isPermissionEvidence(e) && !reportedBy.has(e.file)) reportedBy.set(e.file, r.id);
    }
  };

  // Agent-specific checks own their files
  for (const r of results) {
    if (!r.passed && !r.errored && !GENERIC_PERMISSION_CHECKS.includes(r.id)) record(r);
  }

  const deduped = new Map<string, CheckResult>();
  for (const id of GENERIC_PERMISSION_CHECKS) {
    const r = results.find(x => x.id === id);
    if (!r || r.passed || r.errored || !r.evidence?.length) continue;
    const own = r.evidence.filter(e => !e.file || !reportedBy.has(e.file));
    if (own.length < r.evidence.length) {
      const owners = [...new Set(r.evidence.filter(e => e.file && reportedBy.has(e.file)).map(e => reportedBy.get(e.file)!))];
      deduped.set(id, own.length > 0
        ? { ...r, evidence: own, message: `${r.message} (other files reported by ${owners.join(', ')})` }
        : { ...r, passed: true, evidence: undefined, fixable: undefined, message: `Reported by ${owners.join(', ')}` });
      // Fully folded into the owners, which keep the finding — but the fix
      // (chmod) lives here: hand it over, or `vaso fix` would leave the file loose.
      if (own.length === 0 && r.fixable) {
        for (const ownerId of owners) {
          const owner = deduped.get(ownerId) ?? results.find(x => x.id === ownerId);
          if (owner && !owner.fixable) {
            deduped.set(ownerId, { ...owner, fixable: true, fixDescription: r.fixDescription, fixedBy: r.fixedBy ?? id });
          }
        }
      }
    }
    // Later generic checks yield to this one
    record(deduped.get(id) ?? r);
  }

  return deduped.size === 0 ? results : results.map(r => deduped.get(r.id) ?? r);
}
