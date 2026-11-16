import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { codexProfileName } from '../../adapters/codex.js';
import { judgeDefaultPermissions } from './permission-profiles.js';
import { deepMerge } from '../../core/utils.js';
import { envMitigation, inheritOf } from './cdx-005-shell-env-policy.js';

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

function shellPolicy(data: Record<string, unknown>): Record<string, unknown> | undefined {
  const p = data.shell_environment_policy ?? data.shellEnvironmentPolicy;
  return p && typeof p === 'object' && !Array.isArray(p) ? p as Record<string, unknown> : undefined;
}

function checkProfile(
  name: string,
  p: Record<string, unknown>,
  root: Record<string, unknown>,
  file: string,
  label: string,
  evidence: Evidence[],
  home: string,
): void {
  // default_permissions: the profile may select a [permissions.<name>] table
  // from config.toml or its own file, or change the inherited selection's
  // tables or [features] (network_proxy) — it layers over config.toml
  if (typeof p.default_permissions === 'string' || 'permissions' in p || 'features' in p) {
    // the profile layers over config.toml: tables merge key by key
    const table = (v: unknown) => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});
    const merged = {
      ...p,
      default_permissions: p.default_permissions ?? root.default_permissions,
      permissions: deepMerge(table(root.permissions), table(p.permissions)),
      features: deepMerge(table(root.features), table(p.features)),
    };
    // report what the profile adds over the root config's own findings
    // the detail names the normalized path: a root grant the profile restates
    // with another spelling (`"~"` vs `"~/"`) is the same finding
    const key = (f: { level: string; detail: string }) => `${f.level}\0${f.detail}`;
    const rootFindings = new Set(judgeDefaultPermissions(root, home).map(key));
    for (const f of judgeDefaultPermissions(merged, home)) {
      // an entry Codex rejects grants nothing: no downgrade
      if (f.level === 'info' || rootFindings.has(key(f))) continue;
      evidence.push({
        file,
        snippet: `${label} ${f.snippet}`,
        detail: `${f.detail} under \`codex --profile ${name}\` (root config does not)`,
      });
    }
  }

  // shell_environment_policy: inherit = "all" where the root config narrows
  // it (unset, the root already inherits everything — no downgrade)
  const policy = shellPolicy(p);
  if (inheritOf(policy) === 'all' && !envMitigation(policy)) {
    const rootPolicy = shellPolicy(root);
    const rootInherit = inheritOf(rootPolicy);
    if ((rootInherit !== undefined && rootInherit !== 'all') || envMitigation(rootPolicy)) {
      evidence.push({
        file,
        snippet: `${label} shell_environment_policy.inherit = "all"`,
        detail: 'Profile passes the full process environment (secrets included) to tool subprocesses (root config restricts it)',
      });
    }
  }

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
  description: 'Detect Codex profiles that override approval_policy, sandbox_mode, default_permissions or shell_environment_policy.inherit to a more permissive value than the root config',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();
    // Project config can't select or define profiles (Codex ignores
    // profile/profiles there)
    if (ctx.installation.profile === 'project') return h.passed('Project config cannot define Codex profiles');

    // Codex 0.134+ profile files: $CODEX_HOME/<name>.config.toml layered on
    // config.toml by `codex -p <name>`
    const root = ctx.configs.find(c => !codexProfileName(c.filePath));
    for (const config of ctx.configs) {
      const name = codexProfileName(config.filePath);
      if (!name) continue;
      checkProfile(name, config.data, root?.data ?? {}, config.filePath, `${name}.config.toml:`, evidence, home);
    }

    // Legacy [profiles.<name>] tables (read by Codex < 0.134)
    for (const config of ctx.configs) {
      if (codexProfileName(config.filePath)) continue;
      const profiles = config.data.profiles as Record<string, unknown> | undefined;
      if (!profiles || typeof profiles !== 'object') continue;

      for (const [name, profile] of Object.entries(profiles)) {
        if (!profile || typeof profile !== 'object') continue;
        checkProfile(name, profile as Record<string, unknown>, config.data, config.filePath, `[profiles.${name}]`, evidence, home);
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No Codex profile downgrades the root security posture',
      failed: (n) => `Found ${n} Codex profile(s) that weaken approval/sandbox vs. root config`,
      fixDescription: 'Remove the override from the profile, or remove the profile entirely — the root config is the floor',
    });
  },
});
