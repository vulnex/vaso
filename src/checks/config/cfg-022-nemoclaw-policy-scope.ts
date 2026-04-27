import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SANDBOXES_FILE = 'sandboxes.json';

const RECOMMENDED_POLICIES = ['filesystem', 'network', 'syscall', 'pypi', 'npm'] as const;

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
  description: 'Check if NemoClaw sandbox policies cover filesystem, network, and syscall restrictions beyond package management',
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

    const evidence: Evidence[] = [];
    let narrowCount = 0;

    for (const [name, sandbox] of Object.entries(config.sandboxes)) {
      const policies = sandbox.policies ?? [];
      const missing = RECOMMENDED_POLICIES.filter(p => !policies.includes(p));

      if (missing.length > 0) {
        narrowCount++;
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": active policies [${policies.join(', ') || 'none'}] — missing: [${missing.join(', ')}]`,
        });
      } else {
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": full policy coverage [${policies.join(', ')}]`,
        });
      }
    }

    return h.result({
      passed: narrowCount === 0,
      message: narrowCount === 0
        ? 'All sandboxes have comprehensive policy coverage'
        : `${narrowCount} sandbox(es) have narrow policy scope — missing filesystem, network, or syscall restrictions`,
      evidence,
    });
  },
});
