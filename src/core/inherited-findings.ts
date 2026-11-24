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

    if (inheritFrom(sub, parent, () => true)) {
      sub.score = computeScore(sub.results);
      sub.grade = scoreToGrade(sub.score);
    }
  }
  dedupeHostWideFindings(agents);
  dedupeOwnPersistence(agents);
}

/**
 * Checks that inspect the host rather than the installation: connections,
 * services, cron, editor extensions, processes, and the ~/.nemoclaw
 * recommendation. Sibling top-level installs of one agent for one user
 * (~/.openclaw next to a legacy ~/.clawdbot, profile dirs) all ran them and
 * repeated the same findings.
 */
const HOST_WIDE_CHECKS = new Set(['NET-005', 'RUN-001', 'RUN-002', 'RUN-003', 'RUN-005', 'CFG-016']);

/** NemoClaw hardening checks: they read ~/.nemoclaw, so they belong to the NemoClaw install. */
const NEMOCLAW_CHECKS = new Set(['CFG-016', 'CFG-017', 'CFG-018', 'CFG-019', 'CFG-020', 'CFG-021', 'CFG-022', 'CFG-023', 'CFG-024']);

/**
 * Report host-wide findings once per host: the first top-level install of an
 * agent (per user) keeps them and its siblings mark matching results
 * `inherited`. When NemoClaw itself was detected for the user, OpenClaw's
 * copies of the NemoClaw hardening checks defer to it entirely.
 */
export function dedupeHostWideFindings(agents: AgentScanResult[]): void {
  const owners = new Map<string, AgentScanResult>();
  for (const a of agents) {
    let changed = false;
    if (!a.installation.agentName) {
      const key = `${a.agent}\u0000${a.installation.user ?? ''}`;
      const owner = owners.get(key);
      if (!owner) owners.set(key, a);
      else if (owner.installation.installDir !== a.installation.installDir) {
        changed = inheritFrom(a, owner, id => HOST_WIDE_CHECKS.has(id), 'Host-wide finding');
      }
    }
    if (a.agent === 'openclaw') {
      const nemo = agents.find(n => n.agent === 'nemoclaw' && n.installation.user === a.installation.user);
      if (nemo) {
        const label = `${nemo.agent} (${nemo.installation.installDir})`;
        a.results = a.results.map((r): CheckResult => {
          if (!NEMOCLAW_CHECKS.has(r.id) || r.passed || r.errored) return r;
          changed = true;
          return { ...r, passed: true, inherited: true, evidence: undefined, fixable: undefined,
            message: `NemoClaw hardening is reported under ${label}` };
        });
      }
    }
    if (changed) {
      a.score = computeScore(a.results);
      a.grade = scoreToGrade(a.score);
    }
  }
}

/** Drop from `target` the failing evidence `source` already reports, for the checks `applies` selects. */
function inheritFrom(
  target: AgentScanResult, source: AgentScanResult, applies: (id: string) => boolean,
  sameAs = 'Same finding as the parent installation',
): boolean {
  const sourceLabel = `${source.agent} (${source.installation.installDir})`;
  const sourceFailures = new Map(
    source.results.filter(r => !r.passed && !r.errored).map(r => [r.id, r]));
  let changed = false;

  target.results = target.results.map((r): CheckResult => {
    const p = sourceFailures.get(r.id);
    if (r.passed || r.errored || !p || !applies(r.id)) return r;

    const ownEvidence = r.evidence ?? [];
    const sourceKeys = new Set((p.evidence ?? []).map(evidenceKey));
    const own = ownEvidence.filter(e => !sourceKeys.has(evidenceKey(e)));

    const fullyInherited = ownEvidence.length > 0
      ? own.length === 0
      : (p.evidence ?? []).length === 0 && p.message === r.message;
    if (fullyInherited) {
      changed = true;
      return {
        ...r,
        passed: true,
        inherited: true,
        evidence: undefined,
        message: `${sameAs} — reported under ${sourceLabel}`,
      };
    }
    if (own.length < ownEvidence.length) {
      changed = true;
      const dropped = ownEvidence.length - own.length;
      return { ...r, evidence: own, message: `${r.message} (${dropped} shared with ${sourceLabel}, reported there)` };
    }
    return r;
  });
  return changed;
}

function evidenceKey(e: Evidence): string {
  return `${e.file}\u0000${e.line ?? ''}\u0000${e.detail ?? ''}\u0000${e.snippet ?? ''}`;
}

/** Service and cron checks: a unit/job is judged against the scanned installation's own paths. */
const PERSISTENCE_CHECKS = new Set(['RUN-001', 'RUN-002']);

function persistenceKey(e: Evidence): string {
  return `${e.file}\u0000${e.line ?? ''}\u0000${e.snippet ?? ''}`;
}

/**
 * A service or cron job that runs one detected agent is info under that
 * agent and, judged by its paths, a warning under every other agent on the
 * host (it is not theirs). Report it once, under the agent it runs: the
 * other agents drop that item. Items no detected agent claims stay a
 * warning everywhere — nothing is dropped by name.
 */
export function dedupeOwnPersistence(agents: AgentScanResult[]): void {
  const owners = new Map<string, AgentScanResult>();
  for (const a of agents) {
    for (const r of a.results) {
      if (!PERSISTENCE_CHECKS.has(r.id)) continue;
      for (const e of r.evidence ?? []) {
        const key = `${r.id}\u0000${persistenceKey(e)}`;
        if (e.mitigated && !owners.has(key)) owners.set(key, a);
      }
    }
  }
  if (owners.size === 0) return;

  for (const a of agents) {
    let changed = false;
    a.results = a.results.map((r): CheckResult => {
      if (!PERSISTENCE_CHECKS.has(r.id) || r.passed || r.errored || !r.evidence) return r;
      const claimedBy = new Set<AgentScanResult>();
      const kept = r.evidence.filter(e => {
        const owner = e.mitigated ? undefined : owners.get(`${r.id}\u0000${persistenceKey(e)}`);
        if (owner && owner !== a) { claimedBy.add(owner); return false; }
        return true;
      });
      if (kept.length === r.evidence.length) return r;
      changed = true;
      const labels = [...claimedBy].map(o => `${o.agent} (${o.installation.installDir})`).join(', ');
      if (kept.length === 0) {
        return { ...r, passed: true, inherited: true, evidence: undefined, fixable: undefined,
          message: `Runs another detected agent — reported under ${labels}` };
      }
      const dropped = r.evidence.length - kept.length;
      const suspicious = kept.filter(e => !e.mitigated).length;
      const what = r.id === 'RUN-002' ? 'cron entry/entries' : 'persistence mechanism(s)';
      const head = suspicious === 0
        ? `Found ${kept.length} ${r.id === 'RUN-002' ? 'cron entry/entries' : 'agent service(s)'} — all run an installed agent`
        : `Found ${suspicious} suspicious ${what}`;
      return {
        ...r,
        evidence: kept,
        severity: suspicious === 0 ? 'info' : r.severity,
        message: `${head} (${dropped} more run${dropped === 1 ? 's' : ''} another detected agent, reported under ${labels})`,
      };
    });
    if (changed) {
      a.score = computeScore(a.results);
      a.grade = scoreToGrade(a.score);
    }
  }
}
