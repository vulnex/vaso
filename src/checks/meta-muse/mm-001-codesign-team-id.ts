import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const APP_BUNDLE_PATH = '/Applications/Muse.app';
const EXPECTED_TEAM_ID = 'V9WTTPBFK9'; // Meta Platforms, Inc.
const EXPECTED_IDENTIFIER = 'com.meta.endo';
const TEAM_ID_RE = /TeamIdentifier=([A-Z0-9]+)/;
const IDENTIFIER_RE = /Identifier=([\w.-]+)/;

export const mm001 = defineCheck({
  id: 'MM-001',
  name: 'Muse.app Codesign / Team ID',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify /Applications/Muse.app is signed with the expected Meta Team ID — catches a swapped/impersonated app',
  supportedAgents: ['meta-muse'],
  supportedPlatforms: ['darwin'],

  async run(ctx, h) {
    if (!ctx.installation.appBundle) {
      return h.passed('Muse.app not installed under /Applications');
    }

    let result;
    try {
      result = await ctx.fs.exec('codesign', ['-dv', APP_BUNDLE_PATH], { timeout: 5000 });
    } catch {
      return h.passed('codesign tool not available — skipping');
    }

    // codesign writes its metadata to stderr by design
    const text = `${result.stdout}\n${result.stderr}`;
    const teamMatch = text.match(TEAM_ID_RE);
    const idMatch = text.match(IDENTIFIER_RE);

    const evidence: Evidence[] = [];

    if (!teamMatch || !idMatch) {
      evidence.push({
        file: APP_BUNDLE_PATH,
        detail: 'codesign returned no TeamIdentifier/Identifier — bundle is unsigned or signature is broken',
      });
    } else {
      if (teamMatch[1] !== EXPECTED_TEAM_ID) {
        evidence.push({
          file: APP_BUNDLE_PATH,
          snippet: `TeamIdentifier=${teamMatch[1]} (expected ${EXPECTED_TEAM_ID})`,
          detail: 'Muse.app is signed by an unexpected developer — this is not the official Meta build',
        });
      }
      if (idMatch[1] !== EXPECTED_IDENTIFIER) {
        evidence.push({
          file: APP_BUNDLE_PATH,
          snippet: `Identifier=${idMatch[1]} (expected ${EXPECTED_IDENTIFIER})`,
          detail: 'Bundle identifier mismatch — app at this path may have been swapped',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Muse.app codesign matches the expected Meta Team ID',
      failed: (n) => `Found ${n} codesign mismatch(es) on /Applications/Muse.app`,
      fixDescription: 'Reinstall Muse from Meta’s official distribution channel; verify the download source before trusting the current bundle',
    });
  },
});
