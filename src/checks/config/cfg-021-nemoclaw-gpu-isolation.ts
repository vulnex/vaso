import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SANDBOXES_FILE = 'sandboxes.json';

interface SandboxEntry {
  name?: string;
  gpuEnabled?: boolean;
  nimContainer?: string | null;
  provider?: string;
  model?: string;
  policies?: string[];
}

interface SandboxesConfig {
  sandboxes?: Record<string, SandboxEntry>;
  defaultSandbox?: string;
}

export const cfg021 = defineCheck({
  id: 'CFG-021',
  name: 'NemoClaw GPU Isolation',
  category: 'config',
  severity: 'warning',
  description: 'Check if GPU-enabled NemoClaw sandboxes use NIM container isolation',
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
    let unsafeCount = 0;

    for (const [name, sandbox] of Object.entries(config.sandboxes)) {
      if (sandbox.gpuEnabled && !sandbox.nimContainer) {
        unsafeCount++;
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": GPU enabled but nimContainer is ${sandbox.nimContainer === null ? 'null' : 'not set'} — GPU passthrough without NIM container isolation`,
        });
      } else if (sandbox.gpuEnabled && sandbox.nimContainer) {
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": GPU isolated via NIM container "${sandbox.nimContainer}"`,
        });
      }
    }

    return h.result({
      passed: unsafeCount === 0,
      message: unsafeCount === 0
        ? 'All GPU-enabled sandboxes use NIM container isolation'
        : `${unsafeCount} sandbox(es) have GPU passthrough without NIM container isolation`,
      evidence,
    });
  },
});
