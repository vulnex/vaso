import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CLASSIC_APP_BUNDLE_PATH } from '../../adapters/chatgpt-desktop.js';

const EXPECTED_TEAM_ID = '2DC432GLL2';
const TEAM_ID_RE = /TeamIdentifier=([A-Z0-9]+)/;
const IDENTIFIER_RE = /^Identifier=([\w.-]+)/m;

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

    for (const bundle of BUNDLES) {
      if (!(await ctx.fs.access(bundle.path))) continue;
      let result;
      try {
        result = await ctx.fs.exec('codesign', ['-dv', bundle.path], { timeout: 5000 });
      } catch {
        continue; // codesign unavailable
      }
      verified++;
      const name = bundle.path.split('/').pop();

      // codesign writes its metadata to stderr by design
      const text = `${result.stdout}\n${result.stderr}`;
      const team = text.match(TEAM_ID_RE)?.[1];
      const id = text.match(IDENTIFIER_RE)?.[1];

      if (!team || !id) {
        evidence.push({
          file: bundle.path,
          detail: `codesign returned no TeamIdentifier/Identifier for ${name} — bundle is unsigned or its signature is broken`,
        });
        continue;
      }
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

    if (verified === 0) return h.passed('codesign tool not available — skipping');
    return h.fromEvidence(evidence, {
      passed: `ChatGPT app codesign matches the expected OpenAI Team ID (${verified} bundle${verified === 1 ? '' : 's'})`,
      failed: (n) => `Found ${n} codesign mismatch(es) on the ChatGPT apps`,
      fixDescription: 'Reinstall ChatGPT from chatgpt.com/desktop or the App Store; verify the download host before trusting any prompts shown by the current bundle',
    });
  },
});
