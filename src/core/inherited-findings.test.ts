import { describe, it, expect } from 'vitest';
import type { AgentScanResult, CheckResult } from './types.js';
import { dedupeInheritedFindings } from './inherited-findings.js';

const fail = (id: string, evidence?: CheckResult['evidence'], message = `${id} failed`): CheckResult =>
  ({ id, name: id, category: 'config', severity: 'critical', passed: false, message, evidence });

function agent(installDir: string, results: CheckResult[], agentName?: string): AgentScanResult {
  return {
    agent: 'openclaw',
    installation: { agent: 'openclaw', installDir, configFiles: [], agentName },
    results,
    score: 0,
    grade: 'F',
  };
}

describe('dedupeInheritedFindings', () => {
  const shared = { file: '/h/.openclaw/openclaw.json', detail: 'gateway bound to 0.0.0.0' };

  it('marks a sub-agent finding identical to the parent as inherited and rescores', () => {
    const parent = agent('/h/.openclaw', [fail('CFG-001', [shared]), fail('CFG-005')]);
    const sub = agent('/h/.openclaw/agents/main', [fail('CFG-001', [shared]), fail('CFG-005')], 'main');
    dedupeInheritedFindings([parent, sub]);

    expect(sub.results.every(r => r.passed && r.inherited)).toBe(true);
    expect(sub.results[0].message).toContain('/h/.openclaw');
    expect(sub.score).toBe(100);
    expect(parent.results.every(r => !r.passed)).toBe(true);
  });

  it('keeps sub-agent-specific evidence and notes what was shared', () => {
    const own = { file: '/h/.openclaw/agents/main/agent.json', detail: 'sandbox disabled' };
    const parent = agent('/h/.openclaw', [fail('OC-001', [shared])]);
    const sub = agent('/h/.openclaw/agents/main', [fail('OC-001', [shared, own])], 'main');
    dedupeInheritedFindings([parent, sub]);

    expect(sub.results[0].passed).toBe(false);
    expect(sub.results[0].evidence).toEqual([own]);
    expect(sub.results[0].message).toContain('1 shared with');
  });

  it('leaves findings the parent does not have, and unrelated installations, untouched', () => {
    const parent = agent('/h/.openclaw', [fail('CFG-001', [shared])]);
    const sub = agent('/h/.openclaw/agents/main', [fail('SKL-005', [{ file: '/h/.openclaw/agents/main/skills/x.js' }])], 'main');
    const project = agent('/work/app/.openclaw', [fail('CFG-001', [shared])], 'project:app');
    dedupeInheritedFindings([parent, sub, project]);

    expect(sub.results[0].passed).toBe(false);
    expect(project.results[0].passed).toBe(false);
  });
});

describe('host-wide findings', () => {
  const svc = { file: '/h/Library/LaunchAgents/com.evil.claw.plist', detail: 'LaunchAgent references "claw"' };

  it('reports a host-wide finding once across sibling top-level installs', () => {
    const main = agent('/h/.openclaw', [fail('RUN-001', [svc]), fail('CFG-001', [{ file: '/h/.openclaw/openclaw.json' }])]);
    const legacy = agent('/h/.clawdbot', [fail('RUN-001', [svc]), fail('CFG-001', [{ file: '/h/.clawdbot/openclaw.json' }])]);
    dedupeInheritedFindings([main, legacy]);

    expect(main.results[0].passed).toBe(false);
    expect(legacy.results[0]).toMatchObject({ passed: true, inherited: true });
    expect(legacy.results[0].message).toContain('/h/.openclaw');
    // install-specific checks stay with each install
    expect(legacy.results[1].passed).toBe(false);
  });

  it('attributes NemoClaw hardening checks to the NemoClaw install only', () => {
    const oc = agent('/h/.openclaw', [fail('CFG-018', [{ file: '/h/.nemoclaw/state/nemoclaw.json' }]), fail('CFG-001')]);
    const nemo: AgentScanResult = {
      agent: 'nemoclaw',
      installation: { agent: 'nemoclaw', installDir: '/h/.nemoclaw', configFiles: [] },
      results: [fail('CFG-018', [{ file: '/h/.nemoclaw/state/nemoclaw.json' }])],
      score: 0,
      grade: 'F',
    };
    dedupeInheritedFindings([oc, nemo]);

    expect(oc.results[0]).toMatchObject({ passed: true, inherited: true });
    expect(oc.results[0].message).toContain('nemoclaw');
    expect(oc.results[1].passed).toBe(false);
    expect(nemo.results[0].passed).toBe(false);
  });

  it('keeps NemoClaw checks on OpenClaw when NemoClaw was not scanned', () => {
    const oc = agent('/h/.openclaw', [fail('CFG-018')]);
    dedupeInheritedFindings([oc]);
    expect(oc.results[0].passed).toBe(false);
  });
});

describe('another detected agent\'s own service or cron job', () => {
  const job = (mitigated: boolean, line: number, snippet: string) =>
    ({ file: 'crontab', line, snippet, detail: mitigated ? 'Cron entry runs an installed agent' : 'Cron entry references', mitigated: mitigated || undefined });
  const cron = (evidence: CheckResult['evidence']): CheckResult =>
    ({ id: 'RUN-002', name: 'RUN-002', category: 'runtime', severity: evidence!.every(e => e.mitigated) ? 'info' : 'warning', passed: false, message: 'x', evidence });
  const of = (a: AgentScanResult['agent'], dir: string, results: CheckResult[]): AgentScanResult =>
    ({ agent: a, installation: { agent: a, installDir: dir, configFiles: [] }, results, score: 0, grade: 'F' });

  it('is reported once, under the agent it runs; unclaimed jobs stay warnings everywhere', () => {
    const nb = '*/10 * * * * /h/.local/bin/nanobot heartbeat';
    const evil = '@reboot /opt/x/openclaw-update.sh';
    const openclaw = of('openclaw', '/h/.openclaw', [cron([job(false, 1, nb), job(false, 2, evil)])]);
    const nanobot = of('nanobot', '/h/.nanobot', [cron([job(true, 1, nb), job(false, 2, evil)])]);
    dedupeInheritedFindings([openclaw, nanobot]);

    expect(openclaw.results[0].evidence?.map(e => e.snippet)).toEqual([evil]);
    expect(openclaw.results[0].severity).toBe('warning');
    expect(openclaw.results[0].message).toBe('Found 1 suspicious cron entry/entries (1 more runs another detected agent, reported under nanobot (/h/.nanobot))');
    expect(nanobot.results[0].evidence).toHaveLength(2);
  });

  it('passes an agent whose only finding is another agent\'s own job', () => {
    const nb = '*/10 * * * * /h/.local/bin/nanobot heartbeat';
    const openclaw = of('openclaw', '/h/.openclaw', [cron([job(false, 1, nb)])]);
    const nanobot = of('nanobot', '/h/.nanobot', [cron([job(true, 1, nb)])]);
    dedupeInheritedFindings([openclaw, nanobot]);
    expect(openclaw.results[0]).toMatchObject({ passed: true, inherited: true });
    expect(openclaw.score).toBe(100);
    expect(nanobot.results[0]).toMatchObject({ passed: false, severity: 'info' });
  });
});
