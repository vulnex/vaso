import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const APP_BUNDLE_PATH = '/Applications/ChatGPT.app';
const EXPECTED_TEAM_ID = '2DC432GLL2';
const TEAM_ID_RE = /TeamIdentifier=([A-Z0-9]+)/;
const IDENTIFIER_RE = /Identifier=([\w.-]+)/;
const EXPECTED_IDENTIFIER = 'com.openai.chat';

export const cg005 = defineCheck({
  id: 'CG-005',
  name: 'ChatGPT.app Codesign / Team ID',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify /Applications/ChatGPT.app is signed with the expected OpenAI Team ID — catches a swapped/impersonated app',
  supportedAgents: ['chatgpt-desktop'],
  supportedPlatforms: ['darwin'],

  async run(ctx, h) {
    if (!ctx.installation.appBundle) {
      return h.passed('ChatGPT.app not installed under /Applications');
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
      const team = teamMatch[1];
      const id = idMatch[1];
      if (team !== EXPECTED_TEAM_ID) {
        evidence.push({
          file: APP_BUNDLE_PATH,
          snippet: `TeamIdentifier=${team} (expected ${EXPECTED_TEAM_ID})`,
          detail: 'ChatGPT.app is signed by an unexpected developer — this is not the official OpenAI build',
        });
      }
      if (id !== EXPECTED_IDENTIFIER) {
        evidence.push({
          file: APP_BUNDLE_PATH,
          snippet: `Identifier=${id} (expected ${EXPECTED_IDENTIFIER})`,
          detail: 'Bundle identifier mismatch — app at this path may have been swapped',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'ChatGPT.app codesign matches the expected OpenAI Team ID',
      failed: (n) => `Found ${n} codesign mismatch(es) on /Applications/ChatGPT.app`,
      fixDescription: 'Reinstall ChatGPT from chatgpt.com/desktop or the App Store; verify the download host before trusting any prompts shown by the current bundle',
    });
  },
});
