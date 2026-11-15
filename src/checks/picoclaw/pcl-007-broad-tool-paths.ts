import { dirname, join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { testSamples } from '../../analyzers/bounded-regex.js';
import { asRecord, compileGoRegex, picoMainConfigs, stringList } from './shared.js';
import { riskyWhitelistEntry } from '../nanobot/nb-005-ssrf-webfetch.js';

/** Sensitive files a path allowance must not reach. `.security.yml` lives
 *  next to config.json, which PICOCLAW_CONFIG may relocate out of the home. */
function sensitiveTargets(home: string, configDir: string): string[] {
  return [
    join(home, '.ssh', 'id_ed25519'),
    join(home, '.aws', 'credentials'),
    join(configDir, '.security.yml'),
    join(home, '.bashrc'),
    '/etc/shadow',
  ];
}

/** Why a tools.web.private_host_whitelist entry re-opens SSRF, if it does. */
function riskyPrivateHost(entry: string): string | undefined {
  const e = entry.trim().toLowerCase();
  if (e === '*') return 'exempts every private host — the web_fetch SSRF guard is off';
  if (e === 'localhost' || e.endsWith('.localhost')) return 'exempts loopback — local services become reachable';
  if (e === 'metadata.google.internal') return 'exempts the cloud metadata service — instance credentials become fetchable';
  return riskyWhitelistEntry(e);
}

export const pcl007 = defineCheck({
  id: 'PCL-007',
  name: 'PicoClaw Tool Allowance Too Broad',
  category: 'picoclaw',
  severity: 'warning',
  description: 'tools.allow_read_paths / allow_write_paths are regexes that let file tools reach paths outside the workspace. A pattern matching SSH keys, cloud credentials, shell profiles or /etc undoes the workspace restriction (writes: critical). tools.web.private_host_whitelist exempts hosts from the web_fetch SSRF guard; wildcard, loopback, metadata-service or /8-wide entries re-open SSRF.',
  supportedAgents: ['picoclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let writes = false;
    for (const config of picoMainConfigs(ctx.configs)) {
      const targets = sensitiveTargets(ctx.fs.homedir(), dirname(config.filePath));
      const tools = asRecord(config.data.tools) ?? {};
      for (const entry of stringList(asRecord(tools.web)?.private_host_whitelist)) {
        const why = riskyPrivateHost(entry);
        if (!why) continue;
        evidence.push({
          file: config.filePath,
          snippet: `tools.web.private_host_whitelist: ${JSON.stringify(entry)}`,
          detail: `web_fetch SSRF allowance ${why}`,
        });
      }
      for (const [key, write] of [['allow_read_paths', false], ['allow_write_paths', true]] as const) {
        for (const pattern of stringList(tools[key])) {
          const re = compileGoRegex(pattern);
          if (!re) continue;
          const matched = testSamples(re, targets);
          if (!matched) {
            evidence.push({
              file: config.filePath,
              snippet: `tools.${key}: ${JSON.stringify(pattern)}`,
              detail: `Pattern not evaluated: it backtracks exponentially on sample paths, so whether it lets the agent ${write ? 'write' : 'read'} credentials or system files is unknown — review it`,
            });
            continue;
          }
          const hits = targets.filter((_, i) => matched[i]);
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
      passed: 'PicoClaw tool allowances stay clear of credentials, system files and private networks',
      failed: (n) => `${n} PicoClaw tool allowance(s) reach credentials, system files or private networks`,
      severity: writes ? 'critical' : 'warning',
      fixDescription: 'Narrow tools.allow_read_paths / allow_write_paths to specific project directories and tools.web.private_host_whitelist to the specific internal hosts web_fetch needs',
    });
  },
});
