import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CLASSIC_APP_BUNDLE_PATH } from '../../adapters/chatgpt-desktop.js';
import { readCodesign } from '../../analyzers/codesign.js';

const EXPECTED_TEAM_ID = '2DC432GLL2';

// OpenAI ships two apps under /Applications: the current ChatGPT.app (bundle
// com.openai.codex since the Codex-based rewrite; com.openai.chat before it)
// and, after that update, the original app as "ChatGPT (Classic).app".
const BUNDLES: { path: string; identifiers: string[] }[] = [
  { path: '/Applications/ChatGPT.app', identifiers: ['com.openai.codex', 'com.openai.chat'] },
  { path: CLASSIC_APP_BUNDLE_PATH, identifiers: ['com.openai.chat'] },
];

export const cg005 = defineCheck({
  id: 'CG-005',
  name: 'ChatGPT.app Codesign / Team ID',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify the ChatGPT apps under /Applications (ChatGPT.app and ChatGPT (Classic).app) are signed with the expected OpenAI Team ID and bundle identifier — catches a swapped/impersonated app',
  supportedAgents: ['chatgpt-desktop'],
  supportedPlatforms: ['darwin'],

  async run(ctx, h) {
    if (!ctx.installation.appBundle) {
      return h.passed('No ChatGPT app installed under /Applications');
    }

    const evidence: Evidence[] = [];
    let verified = 0;
    // Bundles codesign didn't give a verdict on (failed run, not collected)
    const unverified: string[] = [];

    for (const bundle of BUNDLES) {
      if (!(await ctx.fs.access(bundle.path))) continue;
      let result;
      try {
        result = await ctx.fs.exec('codesign', ['-dv', bundle.path], { timeout: 5000 });
      } catch {
        continue; // codesign unavailable
      }
      const name = bundle.path.split('/').pop();

      // Only codesign's own verdict says unsigned; a run that failed says nothing
      const sig = readCodesign(result);
      if (sig.state === 'unknown') {
        unverified.push(`${name} (${sig.reason})`);
        continue;
      }
      verified++;
      if (sig.state === 'unsigned') {
        evidence.push({ file: bundle.path, detail: `codesign reports ${name} is not signed at all — this is not the official OpenAI build` });
        continue;
      }
      if (sig.state === 'broken') {
        evidence.push({ file: bundle.path, snippet: sig.detail, detail: `codesign reports an invalid signature on ${name} — the bundle was modified after signing` });
        continue;
      }
      if (sig.state === 'adhoc') {
        evidence.push({ file: bundle.path, snippet: 'Signature=adhoc', detail: `${name} is signed ad hoc, without a developer identity — this is not the official OpenAI build` });
        continue;
      }
      const { team, identifier: id } = sig;
      if (team !== EXPECTED_TEAM_ID) {
        evidence.push({
          file: bundle.path,
          snippet: `TeamIdentifier=${team} (expected ${EXPECTED_TEAM_ID})`,
          detail: `${name} is signed by an unexpected developer — this is not the official OpenAI build`,
        });
      }
      if (!bundle.identifiers.includes(id)) {
        evidence.push({
          file: bundle.path,
          snippet: `Identifier=${id} (expected ${bundle.identifiers.join(' or ')})`,
          detail: 'Bundle identifier mismatch — the app at this path may have been swapped',
        });
      }
    }

    const notVerified = unverified.length > 0 ? `; not verified: ${unverified.join(', ')}` : '';
    if (verified === 0) {
      return h.passed(unverified.length > 0 ? `ChatGPT app signature not verified — ${unverified.join(', ')}` : 'codesign tool not available — skipping');
    }
    return h.fromEvidence(evidence, {
      passed: `ChatGPT app codesign matches the expected OpenAI Team ID (${verified} bundle${verified === 1 ? '' : 's'})${notVerified}`,
      failed: (n) => `Found ${n} codesign mismatch(es) on the ChatGPT apps`,
      fixDescription: 'Reinstall ChatGPT from chatgpt.com/desktop or the App Store; verify the download host before trusting any prompts shown by the current bundle',
    });
  },
});
