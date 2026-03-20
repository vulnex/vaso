import { join } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const SANDBOXES_FILE = 'sandboxes.json';

interface SandboxEntry {
  name?: string;
  model?: string;
}

interface SandboxesConfig {
  sandboxes?: Record<string, SandboxEntry>;
}

export const cfg023: CheckModule = {
  id: 'CFG-023',
  name: 'NemoClaw Model Pinning',
  category: 'config',
  severity: 'info',
  description: 'Check if NemoClaw sandboxes pin models to specific versions to prevent model swap attacks',
  supportedAgents: ['openclaw', 'nemoclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const sandboxesPath = join(ctx.fs.homedir(), '.nemoclaw', SANDBOXES_FILE);

    if (!(await ctx.fs.access(sandboxesPath))) {
      return {
        id: 'CFG-023',
        name: 'NemoClaw Model Pinning',
        category: 'config',
        severity: 'info',
        passed: true,
        message: 'No NemoClaw sandboxes configuration found',
      };
    }

    let config: SandboxesConfig;
    try {
      const raw = await ctx.fs.readFile(sandboxesPath);
      config = JSON.parse(raw) as SandboxesConfig;
    } catch {
      return {
        id: 'CFG-023',
        name: 'NemoClaw Model Pinning',
        category: 'config',
        severity: 'info',
        passed: false,
        message: 'NemoClaw sandboxes.json exists but could not be parsed',
      };
    }

    if (!config.sandboxes || Object.keys(config.sandboxes).length === 0) {
      return {
        id: 'CFG-023',
        name: 'NemoClaw Model Pinning',
        category: 'config',
        severity: 'info',
        passed: true,
        message: 'No sandboxes defined in NemoClaw configuration',
      };
    }

    const evidence: Evidence[] = [];
    let unpinnedCount = 0;

    // Mutable tags that don't pin to a specific model version
    const mutableTags = ['latest', 'stable', 'nightly', 'dev', 'canary'];

    for (const [name, sandbox] of Object.entries(config.sandboxes)) {
      const model = sandbox.model;

      if (!model) {
        unpinnedCount++;
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": no model specified — will use provider default (unpinned)`,
        });
        continue;
      }

      // Check for mutable tags in model string (e.g., "org/model:latest")
      const parts = model.split(':');
      const tag = parts.length > 1 ? parts[parts.length - 1] : undefined;
      const isMutable = tag !== undefined && mutableTags.includes(tag.toLowerCase());

      // Check if model lacks any version/variant specifier
      const hasVersion = /[-:][\dv]/.test(model) || /\d+[bB]/.test(model);

      if (isMutable) {
        unpinnedCount++;
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": model "${model}" uses mutable tag "${tag}" — vulnerable to server-side model swap`,
        });
      } else if (hasVersion) {
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": model "${model}" appears version-pinned`,
        });
      } else {
        unpinnedCount++;
        evidence.push({
          file: sandboxesPath,
          detail: `Sandbox "${name}": model "${model}" has no version specifier — consider pinning to a specific version`,
        });
      }
    }

    return {
      id: 'CFG-023',
      name: 'NemoClaw Model Pinning',
      category: 'config',
      severity: 'info',
      passed: unpinnedCount === 0,
      message: unpinnedCount === 0
        ? 'All sandbox models are pinned to specific versions'
        : `${unpinnedCount} sandbox(es) use unpinned or mutable model references`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
