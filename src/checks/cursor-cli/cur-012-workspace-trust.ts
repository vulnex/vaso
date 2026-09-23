import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

// Cursor disables VS Code's workspace-trust model by default. With trust off,
// opening a malicious repo can auto-execute tasks (`runOptions.runOn:
// "folderOpen"`) with no prompt — the exact vector of CVE-2025-59944 /
// CVE-2025-61590…61593. Only the IDE User settings.json can turn it back on.
export const cur012 = defineCheck({
  id: 'CUR-012',
  name: 'Cursor Workspace Trust Disabled',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect that VS Code workspace trust is not enabled in the Cursor IDE user settings (Cursor ships with it off — folder-open task auto-run has no gate)',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    // Only meaningful when the IDE settings file was found — CLI-only
    // installs have no workspace-trust surface.
    const ideSettings = ctx.configs.filter(c =>
      c.filePath.endsWith('settings.json') && /User[\\/]settings\.json$/.test(c.filePath)
    );
    if (ideSettings.length === 0) {
      return h.passed('No Cursor IDE user settings found — workspace trust not applicable');
    }

    const evidence: Evidence[] = [];
    for (const config of ideSettings) {
      const enabled = config.data['security.workspace.trust.enabled'];
      if (enabled !== true) {
        evidence.push({
          file: config.filePath,
          snippet: enabled === false
            ? '"security.workspace.trust.enabled": false'
            : '(security.workspace.trust.enabled not set — Cursor default is off)',
          detail: 'Workspace trust is disabled: opening an untrusted repository can auto-run tasks on folder open with no prompt (CVE-2025-59944 class)',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Workspace trust is enabled in Cursor IDE settings',
      failed: (n) => `Workspace trust is not enabled in ${n} Cursor IDE settings file(s)`,
      fixDescription: 'Set "security.workspace.trust.enabled": true in the Cursor IDE User settings.json and review folders before trusting them',
    });
  },
});
