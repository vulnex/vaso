import type { AgentScanResult, CheckResult, Evidence } from './types.js';
import { computeScore, scoreToGrade } from './scoring.js';

/**
 * Sub-installations (OpenClaw `agents/<name>` profiles) load the parent's
 * config files, shared skills dir, and run every host-wide check, so each
 * one repeated the parent's findings — reports listed them once per
 * sub-agent. Keep only what differs from the parent: evidence the parent
 * already reports for the same check is dropped, and a result left with
 * nothing of its own is marked `inherited`. The parent keeps full results
 * and the headline stays worst-case, so nothing is hidden.
 */
export function dedupeInheritedFindings(agents: AgentScanResult[]): void {
  for (const sub of agents) {
    const subInst = sub.installation;
    if (!subInst.agentName) continue;
    const parent = agents.find(p =>
      p !== sub &&
      p.agent === sub.agent &&
      !p.installation.agentName &&
      p.installation.user === subInst.user &&
      p.installation.profile === subInst.profile &&
      subInst.installDir.startsWith(`${p.installation.installDir}/`));
    if (!parent) continue;

    const parentLabel = `${parent.agent} (${parent.installation.installDir})`;
    const parentFailures = new Map(
      parent.results.filter(r => !r.passed && !r.errored).map(r => [r.id, r]));
    let changed = false;

    sub.results = sub.results.map((r): CheckResult => {
      const p = parentFailures.get(r.id);
      if (r.passed || r.errored || !p) return r;

      const subEvidence = r.evidence ?? [];
      const parentKeys = new Set((p.evidence ?? []).map(evidenceKey));
      const own = subEvidence.filter(e => !parentKeys.has(evidenceKey(e)));

      const fullyInherited = subEvidence.length > 0
        ? own.length === 0
        : (p.evidence ?? []).length === 0 && p.message === r.message;
      if (fullyInherited) {
        changed = true;
        return {
          ...r,
          passed: true,
          inherited: true,
          evidence: undefined,
          message: `Same finding as the parent installation — reported under ${parentLabel}`,
        };
      }
      if (own.length < subEvidence.length) {
        changed = true;
        const dropped = subEvidence.length - own.length;
        return { ...r, evidence: own, message: `${r.message} (${dropped} shared with ${parentLabel}, reported there)` };
      }
      return r;
    });

    if (changed) {
      sub.score = computeScore(sub.results);
      sub.grade = scoreToGrade(sub.score);
    }
  }
}

function evidenceKey(e: Evidence): string {
  return `${e.file}\u0000${e.line ?? ''}\u0000${e.detail ?? ''}\u0000${e.snippet ?? ''}`;
}
