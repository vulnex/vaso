import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SANDBOXES_FILE = 'sandboxes.json';


interface SandboxEntry {
  name?: string;
  policies?: string[];
}

interface SandboxesConfig {
  sandboxes?: Record<string, SandboxEntry>;
}

export const cfg022 = defineCheck({
  id: 'CFG-022',
  name: 'NemoClaw Policy Scope',
  category: 'config',
  severity: 'warning',
  description: 'Report the NemoClaw policy presets (egress allowances) a legacy sandbox registry records; the effective sandbox policy is judged by the OpenShell checks',
  supportedAgents: ['openclaw', 'nemoclaw'],

  async run(ctx, h) {
    const sandboxesPath = join(ctx.fs.homedir(), '.nemoclaw', SANDBOXES_FILE);

    if (!(await ctx.fs.access(sandboxesPath))) {
      return h.passed('No NemoClaw sandboxes configuration found');
    }

    let config: SandboxesConfig;
    try {
      const raw = await ctx.fs.readFile(sandboxesPath);
      config = JSON.parse(raw) as SandboxesConfig;
    } catch {
      return h.result({
        passed: false,
        message: 'NemoClaw sandboxes.json exists but could not be parsed',
      });
    }

    if (!config.sandboxes || Object.keys(config.sandboxes).length === 0) {
      return h.passed('No sandboxes defined in NemoClaw configuration');
    }

    // Current releases strip `policies` from the registry on every load/save —
    // applied presets are held by the OpenShell gateway — so only entries that
    // still record them (legacy installs) can be judged from disk.
    const withPolicies = Object.entries(config.sandboxes).filter(([, s]) => Array.isArray(s.policies));
    if (withPolicies.length === 0) {
      return h.passed('NemoClaw policy presets are held by the OpenShell gateway, not on disk — evaluated by the OpenShell checks (OSH-011–OSH-014)');
    }

    // NemoClaw presets (nemoclaw-blueprint/policies/presets: npm, pypi,
    // docker, huggingface, slack, discord, telegram, jira, outlook, …) are
    // network egress allowances layered on the default-deny sandbox policy —
    // each one widens what the sandbox reaches. There are no filesystem /
    // network / syscall presets: a short (or empty) list is the narrow one.
    const evidence: Evidence[] = withPolicies.map(([name, sandbox]) => ({
      file: sandboxesPath,
      detail: `Sandbox "${name}": egress presets [${(sandbox.policies ?? []).join(', ') || 'none'}]`,
    }));
    return h.result({
      passed: true,
      message: 'NemoClaw policy presets only add egress to the default-deny sandbox policy — the effective policy is judged by the OpenShell checks (OSH-011–OSH-014)',
      evidence,
    });
  },
});
