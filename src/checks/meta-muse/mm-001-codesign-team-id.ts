import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { readCodesign } from '../../analyzers/codesign.js';

const APP_BUNDLE_PATH = '/Applications/Muse.app';
const EXPECTED_TEAM_ID = 'V9WTTPBFK9'; // Meta Platforms, Inc.
const EXPECTED_IDENTIFIER = 'com.meta.endo';

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

    // Only codesign's own verdict says unsigned; a run that failed says nothing
    const sig = readCodesign(result);
    if (sig.state === 'unknown') {
      return h.passed(`Muse.app signature not verified — ${sig.reason}`);
    }

    const evidence: Evidence[] = [];
    if (sig.state === 'unsigned') {
      evidence.push({ file: APP_BUNDLE_PATH, detail: 'codesign reports the bundle is not signed at all — this is not the official Meta build' });
    } else if (sig.state === 'broken') {
      evidence.push({ file: APP_BUNDLE_PATH, snippet: sig.detail, detail: 'codesign reports an invalid signature — the bundle was modified after signing' });
    } else if (sig.state === 'adhoc') {
      evidence.push({ file: APP_BUNDLE_PATH, snippet: 'Signature=adhoc', detail: 'Muse.app is signed ad hoc, without a developer identity — this is not the official Meta build' });
    } else {
      if (sig.team !== EXPECTED_TEAM_ID) {
        evidence.push({
          file: APP_BUNDLE_PATH,
          snippet: `TeamIdentifier=${sig.team} (expected ${EXPECTED_TEAM_ID})`,
          detail: 'Muse.app is signed by an unexpected developer — this is not the official Meta build',
        });
      }
      if (sig.identifier !== EXPECTED_IDENTIFIER) {
        evidence.push({
          file: APP_BUNDLE_PATH,
          snippet: `Identifier=${sig.identifier} (expected ${EXPECTED_IDENTIFIER})`,
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
