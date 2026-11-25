import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { defaultProfile, isProjectInstall } from './shared.js';

export const msc002 = defineCheck({
  id: 'MSC-002',
  name: 'Muse Code Sandbox Disabled by Default',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect a Meta Muse Code default permission profile that turns off the shell sandbox: filesystem "unrestricted" (commands can write anywhere the user can) or network.mode "enabled" (commands reach any host instead of going through the egress proxy)',
  supportedAgents: ['muse-code'],

  async run(ctx, h) {
    if (isProjectInstall(ctx)) return h.passed('Permission profiles are user-level — evaluated on the user installation');
    const evidence: Evidence[] = [];
    const view = defaultProfile(ctx.configs);
    if (view?.configured) {
      if (view.profile.filesystem === 'unrestricted') {
        evidence.push({
          file: view.config.filePath,
          snippet: `permissions.default_profile: "${view.id}" (filesystem unrestricted)`,
          detail: 'Shell commands run outside the filesystem sandbox — they can modify shell profiles, SSH keys and other projects',
        });
      }
      if (view.profile.network === 'enabled') {
        evidence.push({
          file: view.config.filePath,
          snippet: `permissions.default_profile: "${view.id}" (network enabled)`,
          detail: 'Shell commands have direct network access instead of the default egress proxy — a prompt-injected command can send workspace data anywhere',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Muse Code sessions keep the shell sandbox',
      failed: (n) => `Found ${n} sandbox setting(s) disabled in the default Muse Code permission profile`,
      fixDescription: 'Keep filesystem sandboxing (omit filesystem or use path rules) and network.mode "proxy_only" (default) or "restricted" in the default profile; allow specific hosts with network.targets',
    });
  },
});
