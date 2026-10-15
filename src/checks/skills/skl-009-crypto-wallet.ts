import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { readSkillText, skillFilesOf, skillsDirsOf } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';

const CRYPTO_RULES = SECURITY_PATTERNS.filter(r => r.category === 'crypto-wallet');
const ADDRESS_RULES = new Set(['CW-001', 'CW-002']);

/**
 * What turns a wallet address into wallet targeting: a clipper swaps copied
 * addresses, a drainer reads wallet files, extension storage or seed phrases,
 * or sends funds to an address it carries. A skill that just lists token
 * contracts (USDC, WETH…) or a donation address does none of these.
 */
const TARGETING = [
  /\b(?:clipboard|pbpaste|pbcopy|xclip|xsel|wl-paste|GetClipboardData|clipboardy)\b/i,
  /\bwallet\.dat\b|\bkeystore\b|\b(?:metamask|phantom|exodus|electrum|atomic\s*wallet|trust\s*wallet)\b|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa/i,
  /\b(?:seed\s*phrase|mnemonic|private[\s_-]*key|secret[\s_-]*recovery)\b/i,
];
/** A transfer whose destination is written into the code. */
const TRANSFER_TO_LITERAL = /\b(?:transfer|sendTransaction|send_transaction|sendTransfer|transferFrom|safeTransfer)\s*\([^)]{0,200}?(?:0x[0-9a-fA-F]{40}|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b)/;

export const skl009 = defineCheck({
  id: 'SKL-009',
  name: 'Crypto Wallet Targeting',
  category: 'skills',
  severity: 'warning',
  description: 'Detect crypto wallet targeting: wallet addresses alongside clipboard swapping, wallet-file or seed-phrase access, or transfers to a hardcoded address',

  async run(ctx, h) {
    if (skillsDirsOf(ctx).length === 0) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'patterns');
        if (code === undefined) continue;
        const matches = scanWithPatterns(code, CRYPTO_RULES);
        const addresses = matches.filter(m => ADDRESS_RULES.has(m.pattern));
        const targeting = TARGETING.some(re => re.test(code)) || TRANSFER_TO_LITERAL.test(code);

        for (const match of matches) {
          if (ADDRESS_RULES.has(match.pattern) && !targeting) continue;
          evidence.push({ file, line: match.line, snippet: match.snippet, detail: match.description });
        }
        if (addresses.length > 0 && !targeting) {
          // Token contracts, donation addresses: listed once per file, informational
          evidence.push({
            file,
            line: addresses[0].line,
            snippet: addresses[0].snippet,
            detail: `${addresses.length} wallet/contract address(es) — no wallet-targeting behaviour (clipboard, wallet files, seed phrases, transfers to a hardcoded address) in this file`,
            mitigated: true,
          });
        }
      } catch {}
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No crypto wallet targeting patterns detected',
      failed: (n) => `Found ${n} crypto wallet targeting pattern(s)`,
    });
  },
});
