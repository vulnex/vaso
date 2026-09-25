import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, readableByOthers } from '../../core/permissions.js';

// Session-credential files inside the Chromium profile. Values are encrypted
// with the OS keychain/DPAPI, but loose file modes still expose them to
// offline attack and same-host credential theft tooling.
const SENSITIVE_PROFILE_FILES = ['Cookies', 'Login Data', 'Web Data', 'Preferences'];

export const pc001 = defineCheck({
  id: 'PC-001',
  name: 'Comet Profile Data Readable by Others',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Check that Comet’s browser profile (Cookies, Login Data, Preferences — the agent’s session credentials and connector config) is not readable by other local users',
  supportedAgents: ['comet'],

  async run(ctx, h) {
    const defaultProfile = join(ctx.installation.installDir, 'Default');
    if (!(await ctx.fs.access(defaultProfile))) {
      return h.passed('Comet profile directory not present');
    }

    const evidence: Evidence[] = [];
    for (const name of SENSITIVE_PROFILE_FILES) {
      const target = join(defaultProfile, name);
      let facts;
      try {
        facts = await queryPermissions(ctx.fs, target);
      } catch {
        continue; // absent
      }
      if (facts === 'unsupported') continue;
      if (readableByOthers(facts)) {
        evidence.push({
          file: target,
          snippet: facts.octal,
          detail: 'Readable by other local users — Comet is an agentic browser, so this profile carries the agent’s logged-in sessions and connector configuration',
        });
      }
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Comet profile data is not readable by other users',
      failed: (n) => `Found ${n} Comet profile file(s) readable by other users`,
      fixDescription: 'chmod go-rwx the flagged files under the Comet profile directory',
    });
  },
});
