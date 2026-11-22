import { dirname, join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { regexBudget, runSampleBatch, type SampleRun } from '../../analyzers/bounded-regex.js';
import { compileForeignRegex, notEvaluatedDetail, unjudgedEvidence } from '../../analyzers/foreign-regex.js';
import { asRecord, picoMainConfigs, stringList } from './shared.js';
import { envNote } from '../../adapters/env-overrides.js';
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
    // read and write allowances are judged with separate budgets: slow read
    // patterns must not leave a write catch-all unjudged
    const budgets = { allow_read_paths: regexBudget(), allow_write_paths: regexBudget() };
    for (const config of picoMainConfigs(ctx.configs)) {
      const targets = sensitiveTargets(ctx.fs.homedir(), dirname(config.filePath));
      const tools = asRecord(config.data.tools) ?? {};
      for (const entry of stringList(asRecord(tools.web)?.private_host_whitelist)) {
        const why = riskyPrivateHost(entry);
        if (!why) continue;
        evidence.push({
          file: config.filePath,
          snippet: `tools.web.private_host_whitelist: ${JSON.stringify(entry)}${envNote(config.data, 'tools.web.private_host_whitelist')}`,
          detail: `web_fetch SSRF allowance ${why}`,
        });
      }
      for (const [key, write] of [['allow_read_paths', false], ['allow_write_paths', true]] as const) {
        const what = `lets the agent ${write ? 'write' : 'read'} credentials or system files`;
        const unjudged: string[] = [];
        const patterns = stringList(tools[key]);
        const compiled = patterns.map(p => compileForeignRegex(p, 'go'));
        const runs: Array<SampleRun | undefined> = compiled.map(() => undefined);
        const ok = compiled.flatMap((c, k) => (c.kind === 'ok' ? [{ k, re: c.re }] : []));
        runSampleBatch(ok.map(({ re }) => ({ re, samples: targets })), { budget: budgets[key] })
          .forEach((run, j) => { runs[ok[j].k] = run; });
        for (const [k, pattern] of patterns.entries()) {
          const snippet = `tools.${key}: ${JSON.stringify(pattern)}${envNote(config.data, `tools.${key}`)}`;
          // PicoClaw rejects a pattern Go can't compile: it allows nothing
          if (compiled[k].kind === 'invalid') continue;
          const run = runs[k];
          if (!run) {
            evidence.push({ file: config.filePath, snippet, detail: notEvaluatedDetail('unsupported', what) });
            continue;
          }
          // a target matched before the time ran out is a finding all the same
          const hits = targets.filter((_, i) => run.hits[i]);
          if (hits.length === 0) {
            if (run.reason === 'budget') unjudged.push(pattern);
            else if (run.reason) evidence.push({ file: config.filePath, snippet, detail: notEvaluatedDetail(run.reason, what) });
            continue;
          }
          if (write) writes = true;
          evidence.push({
            file: config.filePath,
            snippet,
            detail: `Lets the agent ${write ? 'write' : 'read'} ${hits.join(', ')}${run.complete ? '' : ' (the other sensitive paths were not evaluated)'}`,
          });
        }
        if (unjudged.length > 0) evidence.push(unjudgedEvidence(config.filePath, `tools.${key}`, unjudged, what));
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
