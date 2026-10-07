import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { record, sandboxPolicies } from './shared.js';

// Writable paths that let the agent replace binaries, trust stores or other
// users' data. `/` itself is rejected by the gateway; these are accepted.
const SENSITIVE = /^\/(?:etc|usr|bin|sbin|lib|lib32|lib64|boot|opt|var|root|home|srv|sys|proc|dev|usr\/local(?:\/bin)?|usr\/bin|var\/lib)\/?$/;

export const osh014 = defineCheck({
  id: 'OSH-014',
  name: 'OpenShell Sandbox Can Write System Paths',
  category: 'openshell',
  severity: 'warning',
  description: 'Detect sandbox filesystem policies granting read-write access to system or user directories (/etc, /usr, /bin, /lib, /var, /opt, /home, /root, …) — the agent can replace binaries, alter TLS trust or DNS, or reach every user\'s files inside the sandbox image and mounts',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const ref of await sandboxPolicies(ctx)) {
      const rw = record(ref.policy.filesystem_policy)?.read_write;
      const hits = (Array.isArray(rw) ? rw : []).filter((p): p is string => typeof p === 'string' && SENSITIVE.test(p.trim()));
      if (hits.length === 0) continue;
      evidence.push({ file: ref.file, snippet: `filesystem_policy.read_write: ${hits.join(', ')}`, detail: `${ref.source}: system/user directories are writable by the agent` });
    }
    return h.fromEvidence(evidence, {
      passed: 'Sandbox filesystem policies keep system paths read-only',
      failed: (n) => `Found ${n} OpenShell sandbox polic(ies) with writable system paths`,
      fixDescription: 'Keep system paths in read_only and grant read_write only to the workdir, /tmp or a dedicated subdirectory; filesystem changes take effect when the sandbox is recreated',
    });
  },
});
