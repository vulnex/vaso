import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const DANGEROUS_APPROVAL = new Set(['never', 'none', 'auto']);
const DANGEROUS_SANDBOX = new Set([
  'danger-full-access',
  'danger_full_access',
  'dangerously-bypass-sandbox',
  'none',
  'disabled',
]);

function isDangerousApproval(v: unknown): boolean {
  return typeof v === 'string' && DANGEROUS_APPROVAL.has(v.toLowerCase());
}

function isDangerousSandbox(v: unknown): boolean {
  return typeof v === 'string' && DANGEROUS_SANDBOX.has(v.toLowerCase());
}

export const cdx008: CheckModule = {
  id: 'CDX-008',
  name: 'Codex Profile Security Downgrade',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Codex profiles that override approval_policy or sandbox_mode to a more permissive value than the root config',
  supportedAgents: ['codex'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const profiles = config.data.profiles as Record<string, unknown> | undefined;
      if (!profiles || typeof profiles !== 'object') continue;

      const rootApproval = config.data.approval_policy ?? config.data.approvalPolicy;
      const rootSandbox = config.data.sandbox_mode ?? config.data.sandboxMode;

      for (const [name, profile] of Object.entries(profiles)) {
        if (!profile || typeof profile !== 'object') continue;
        const p = profile as Record<string, unknown>;

        const approval = p.approval_policy ?? p.approvalPolicy;
        if (isDangerousApproval(approval) && !isDangerousApproval(rootApproval)) {
          evidence.push({
            file: config.filePath,
            snippet: `[profiles.${name}] approval_policy = "${approval as string}"`,
            detail: 'Profile sets approval_policy to a value that skips user confirmation (root config does not)',
          });
        }

        const sandbox = p.sandbox_mode ?? p.sandboxMode;
        if (isDangerousSandbox(sandbox) && !isDangerousSandbox(rootSandbox)) {
          evidence.push({
            file: config.filePath,
            snippet: `[profiles.${name}] sandbox_mode = "${sandbox as string}"`,
            detail: 'Profile disables the sandbox (root config does not) — `codex --profile ' + name + '` runs unrestricted',
          });
        }
      }
    }

    return {
      id: 'CDX-008',
      name: 'Codex Profile Security Downgrade',
      category: 'coding-agent',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No Codex profile downgrades the root security posture'
        : `Found ${evidence.length} Codex profile(s) that weaken approval/sandbox vs. root config`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Remove the override from the profile, or remove the profile entirely — the root config is the floor',
    };
  },
};
