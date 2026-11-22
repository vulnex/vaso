import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SANDBOXES_FILE = 'sandboxes.json';

interface SandboxEntry {
  name?: string;
  gpuEnabled?: boolean;
  sandboxGpuEnabled?: boolean;
  sandboxGpuMode?: string | null;
  sandboxGpuDevice?: string | null;
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
  description: 'Check whether NemoClaw sandboxes get the host GPU passed through (sandboxGpuEnabled), exposing the host GPU driver to agent code',
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

    // NemoClaw records whether the sandbox gets the host GPU as
    // sandboxGpuEnabled (onboard's effective choice; sandboxGpuMode is the
    // requested auto/1/0), mirrored into gpuEnabled — `nemoclaw status` reads
    // sandboxGpuEnabled ?? gpuEnabled. nimContainer is the local NIM inference
    // server the sandbox talks to, not an isolation layer around the GPU.
    for (const [name, sandbox] of Object.entries(config.sandboxes)) {
      const gpu = typeof sandbox.sandboxGpuEnabled === 'boolean' ? sandbox.sandboxGpuEnabled : sandbox.gpuEnabled === true;
      if (!gpu) continue;
      unsafeCount++;
      const device = typeof sandbox.sandboxGpuDevice === 'string' && sandbox.sandboxGpuDevice ? ` (device ${sandbox.sandboxGpuDevice})` : '';
      evidence.push({
        file: sandboxesPath,
        detail: `Sandbox "${name}": host GPU passed into the sandbox${device}${sandbox.sandboxGpuMode ? `, sandboxGpuMode ${JSON.stringify(sandbox.sandboxGpuMode)}` : ''}`,
      });
    }

    // GPU passthrough is how NemoClaw runs local GPU workloads (sandboxGpuMode
    // "auto" enables it on a GPU host) — reported, not failed: a missing
    // nimContainer never meant missing isolation
    return h.result({
      passed: true,
      message: unsafeCount === 0
        ? 'No sandbox has the host GPU passed through'
        : `${unsafeCount} sandbox(es) have the host GPU passed through (sandboxGpuMode) — the host GPU driver is reachable from agent code; turn it off when the agent runs no local GPU workloads`,
      evidence,
    });
  },
});
