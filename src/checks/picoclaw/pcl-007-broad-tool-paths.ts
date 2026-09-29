import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { asRecord, compileGoRegex, picoMainConfigs, stringList } from './shared.js';

/** Sensitive files a path allowance must not reach. */
function sensitiveTargets(home: string, picoHome: string): string[] {
  return [
    join(home, '.ssh', 'id_ed25519'),
    join(home, '.aws', 'credentials'),
    join(picoHome, '.security.yml'),
    join(home, '.bashrc'),
    '/etc/shadow',
  ];
}

export const pcl007 = defineCheck({
  id: 'PCL-007',
  name: 'PicoClaw Tool Path Allowance Too Broad',
  category: 'picoclaw',
  severity: 'warning',
  description: 'tools.allow_read_paths / allow_write_paths are regexes that let file tools reach paths outside the workspace. A pattern matching SSH keys, cloud credentials, shell profiles or /etc undoes the workspace restriction (writes: critical).',
  supportedAgents: ['picoclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let writes = false;
    const targets = sensitiveTargets(ctx.fs.homedir(), ctx.installation.installDir);
    for (const config of picoMainConfigs(ctx.configs)) {
      const tools = asRecord(config.data.tools) ?? {};
      for (const [key, write] of [['allow_read_paths', false], ['allow_write_paths', true]] as const) {
        for (const pattern of stringList(tools[key])) {
          const re = compileGoRegex(pattern);
          if (!re) continue;
          const hits = targets.filter(t => re.test(t));
          if (hits.length === 0) continue;
          if (write) writes = true;
          evidence.push({
            file: config.filePath,
            snippet: `tools.${key}: ${JSON.stringify(pattern)}`,
            detail: `Lets the agent ${write ? 'write' : 'read'} ${hits.join(', ')}`,
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'PicoClaw tool path allowances stay clear of credentials and system files',
      failed: (n) => `${n} PicoClaw path allowance(s) reach credentials or system files`,
      severity: writes ? 'critical' : 'warning',
      fixDescription: 'Narrow tools.allow_read_paths / allow_write_paths to specific project directories',
    });
  },
});
