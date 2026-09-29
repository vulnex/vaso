import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isLyrieCheckout, lyrieShieldBinaryPaths } from '../../adapters/lyrie.js';

/**
 * Lyrie's AgenticThreatBridge (used by the MCP Shield middleware, the MCP
 * registry and the daemon) looks for the Rust Shield only at
 * <checkout>/packages/shield/target/{release,debug}/lyrie-shield — never on
 * PATH. Without it the TypeScript ShieldManager still runs, but the Rust
 * agentic-threat detection is silently unavailable.
 */
export const ly002 = defineCheck({
  id: 'LY-002',
  name: 'Lyrie Rust Shield Binary Not Built',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect a Lyrie checkout without the Rust Shield binary at packages/shield/target/{release,debug}/lyrie-shield — the only locations Lyrie searches (PATH is not consulted). The TypeScript Shield still runs, but agentic-threat detection (attack-chain compression, self-propagation, AI-sink writes) for MCP traffic and the daemon is silently disabled.',
  supportedAgents: ['lyrie'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const checkout = ctx.installation.installDir;
    if (!(await isLyrieCheckout(checkout, ctx.fs))) {
      return h.passed('No Lyrie agent checkout found — Shield binary check not applicable');
    }

    const candidates = lyrieShieldBinaryPaths(checkout);
    for (const path of candidates) {
      if (await ctx.fs.access(path)) return h.passed(`Rust Shield binary present at ${path}`);
    }

    const evidence: Evidence[] = [{
      file: candidates[0],
      detail: 'lyrie-shield has not been built in this checkout — the agentic-threat bridge reports itself unavailable and Rust-side detection is skipped',
    }];
    return h.fromEvidence(evidence, {
      passed: 'Rust Shield binary present',
      failed: () => 'Rust Shield binary not built — agentic-threat detection is disabled',
      fixDescription: 'In the Lyrie checkout run `bun run shield:build` (cargo build --release in packages/shield)',
    });
  },
});
