import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { codexProfileName } from '../../adapters/codex.js';

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

function checkProfile(
  name: string,
  p: Record<string, unknown>,
  root: Record<string, unknown>,
  file: string,
  label: string,
  evidence: Evidence[],
): void {
  const approval = p.approval_policy ?? p.approvalPolicy;
  if (isDangerousApproval(approval) && !isDangerousApproval(root.approval_policy ?? root.approvalPolicy)) {
    evidence.push({
      file,
      snippet: `${label} approval_policy = "${approval as string}"`,
      detail: 'Profile sets approval_policy to a value that skips user confirmation (root config does not)',
    });
  }

  const sandbox = p.sandbox_mode ?? p.sandboxMode;
  if (isDangerousSandbox(sandbox) && !isDangerousSandbox(root.sandbox_mode ?? root.sandboxMode)) {
    evidence.push({
      file,
      snippet: `${label} sandbox_mode = "${sandbox as string}"`,
      detail: 'Profile disables the sandbox (root config does not) — `codex --profile ' + name + '` runs unrestricted',
    });
  }
}

export const cdx008 = defineCheck({
  id: 'CDX-008',
  name: 'Codex Profile Security Downgrade',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Codex profiles that override approval_policy or sandbox_mode to a more permissive value than the root config',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    // Project config can't select or define profiles (Codex ignores
    // profile/profiles there)
    if (ctx.installation.profile === 'project') return h.passed('Project config cannot define Codex profiles');

    // Codex 0.134+ profile files: $CODEX_HOME/<name>.config.toml layered on
    // config.toml by `codex -p <name>`
    const root = ctx.configs.find(c => !codexProfileName(c.filePath));
    for (const config of ctx.configs) {
      const name = codexProfileName(config.filePath);
      if (!name) continue;
      checkProfile(name, config.data, root?.data ?? {}, config.filePath, `${name}.config.toml:`, evidence);
    }

    // Legacy [profiles.<name>] tables (read by Codex < 0.134)
    for (const config of ctx.configs) {
      if (codexProfileName(config.filePath)) continue;
      const profiles = config.data.profiles as Record<string, unknown> | undefined;
      if (!profiles || typeof profiles !== 'object') continue;

      for (const [name, profile] of Object.entries(profiles)) {
        if (!profile || typeof profile !== 'object') continue;
        checkProfile(name, profile as Record<string, unknown>, config.data, config.filePath, `[profiles.${name}]`, evidence);
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No Codex profile downgrades the root security posture',
      failed: (n) => `Found ${n} Codex profile(s) that weaken approval/sandbox vs. root config`,
      fixDescription: 'Remove the override from the profile, or remove the profile entirely — the root config is the floor',
    });
  },
});
