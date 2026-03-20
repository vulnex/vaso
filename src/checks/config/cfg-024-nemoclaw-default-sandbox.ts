import { join } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const SANDBOXES_FILE = 'sandboxes.json';

interface SandboxEntry {
  name?: string;
}

interface SandboxesConfig {
  sandboxes?: Record<string, SandboxEntry>;
  defaultSandbox?: string;
}

export const cfg024: CheckModule = {
  id: 'CFG-024',
  name: 'NemoClaw Default Sandbox',
  category: 'config',
  severity: 'warning',
  description: 'Check if NemoClaw defaultSandbox references an existing sandbox to prevent fallback to unprotected execution',
  supportedAgents: ['openclaw', 'nemoclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const sandboxesPath = join(ctx.fs.homedir(), '.nemoclaw', SANDBOXES_FILE);

    if (!(await ctx.fs.access(sandboxesPath))) {
      return {
        id: 'CFG-024',
        name: 'NemoClaw Default Sandbox',
        category: 'config',
        severity: 'warning',
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
        id: 'CFG-024',
        name: 'NemoClaw Default Sandbox',
        category: 'config',
        severity: 'warning',
        passed: false,
        message: 'NemoClaw sandboxes.json exists but could not be parsed',
      };
    }

    const evidence: Evidence[] = [];

    if (!config.defaultSandbox) {
      return {
        id: 'CFG-024',
        name: 'NemoClaw Default Sandbox',
        category: 'config',
        severity: 'warning',
        passed: false,
        message: 'No defaultSandbox set — NemoClaw may not apply sandbox policies automatically',
        evidence: [{ file: sandboxesPath, detail: 'defaultSandbox field is missing or empty' }],
      };
    }

    const sandboxNames = Object.keys(config.sandboxes ?? {});

    if (sandboxNames.length === 0) {
      return {
        id: 'CFG-024',
        name: 'NemoClaw Default Sandbox',
        category: 'config',
        severity: 'warning',
        passed: false,
        message: `defaultSandbox "${config.defaultSandbox}" is set but no sandboxes are defined`,
        evidence: [{ file: sandboxesPath, detail: `Dangling reference: "${config.defaultSandbox}" → no sandboxes exist` }],
      };
    }

    if (!sandboxNames.includes(config.defaultSandbox)) {
      return {
        id: 'CFG-024',
        name: 'NemoClaw Default Sandbox',
        category: 'config',
        severity: 'warning',
        passed: false,
        message: `defaultSandbox "${config.defaultSandbox}" does not match any defined sandbox`,
        evidence: [{
          file: sandboxesPath,
          detail: `Dangling reference: "${config.defaultSandbox}" not in [${sandboxNames.join(', ')}]`,
        }],
      };
    }

    evidence.push({
      file: sandboxesPath,
      detail: `defaultSandbox "${config.defaultSandbox}" resolves to a valid sandbox`,
    });

    return {
      id: 'CFG-024',
      name: 'NemoClaw Default Sandbox',
      category: 'config',
      severity: 'warning',
      passed: true,
      message: `Default sandbox "${config.defaultSandbox}" is correctly configured`,
      evidence,
    };
  },
};
