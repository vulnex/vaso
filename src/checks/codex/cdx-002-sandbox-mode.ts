import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const DANGEROUS_SANDBOX_MODES = new Set([
  'danger-full-access',
  'danger_full_access',
  'dangerously-bypass-sandbox',
  'none',
  'disabled',
]);

export const cdx002: CheckModule = {
  id: 'CDX-002',
  name: 'Codex Sandbox Disabled',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when Codex sandbox_mode grants unrestricted host access',
  supportedAgents: ['codex'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mode = config.data.sandbox_mode ?? config.data.sandboxMode;
      if (typeof mode === 'string' && DANGEROUS_SANDBOX_MODES.has(mode.toLowerCase())) {
        evidence.push({
          file: config.filePath,
          detail: `sandbox_mode = "${mode}" — Codex commands run with full host access`,
        });
      }
    }

    return {
      id: 'CDX-002',
      name: 'Codex Sandbox Disabled',
      category: 'coding-agent',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Codex sandbox is restricting command execution'
        : 'Codex sandbox is disabled — commands have full host access',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Set sandbox_mode to "read-only" or "workspace-write" in ~/.codex/config.toml',
    };
  },
};
