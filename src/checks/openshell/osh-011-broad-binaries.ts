import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { describeEndpoint, networkRules, policyPassMessage, sandboxPolicies } from './shared.js';

// Patterns that authorize (nearly) every executable. Policy schema: binary
// globs use `*` for one path component and `**` recursively.
// - only wildcards and slashes: `**`, `/**`, `/*`, `/**/*`, `/*/**`
// - a recursive glob directly under a top-level directory: `/usr/**`, `/home/*/**`
// - every program in a standard bin directory: `/usr/bin/*`, `/usr/local/sbin/**`
const BROAD = [
  /^[/*]*\*[/*]*$/,
  /^\/[^/*]+\/(?:\*\*|\*\/\*)[/*]*$/,
  /^(?:\/usr(?:\/local)?)?\/s?bin\/\*[/*]*$/,
];

export const osh011 = defineCheck({
  id: 'OSH-011',
  name: 'OpenShell Network Rule Allows Any Program',
  category: 'openshell',
  severity: 'warning',
  description: 'Detect sandbox network rules whose `binaries` glob matches every executable (`/**`, `**`, `/*`, `/usr/**`, `/usr/bin/*`) — binary-scoped egress is OpenShell\'s main exfiltration control, and the gateway accepts these globs without complaint (verified on 0.1.2)',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const r of networkRules(await sandboxPolicies(ctx))) {
      const broad = r.binaries.filter(b => BROAD.some(re => re.test(b.trim())));
      if (broad.length === 0 || r.endpoints.length === 0) continue;
      evidence.push({
        file: r.ref.file,
        snippet: `network_policies.${r.rule}.binaries: ${broad.join(', ')}`,
        detail: `${r.ref.source}: any program in the sandbox can reach ${r.endpoints.map(describeEndpoint).join(', ')}`,
      });
    }
    return h.fromEvidence(evidence, {
      passed: await policyPassMessage(ctx, 'Sandbox network rules are scoped to specific programs'),
      failed: (n) => `Found ${n} OpenShell network rule(s) open to any program`,
      fixDescription: 'List the exact executables (or a narrow directory glob such as /sandbox/.venv/bin/*) that need each endpoint, then openshell policy set <sandbox> --policy <file>',
    });
  },
});
