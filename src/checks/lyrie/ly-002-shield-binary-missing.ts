import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const ly002 = defineCheck({
  id: 'LY-002',
  name: 'Lyrie Shield Binary Missing',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect when the Rust lyrie-shield binary is not on PATH — Lyrie\'s TS engine still runs but Layer-1 enforcement is silently absent.',
  supportedAgents: ['lyrie'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    let resolved: string | undefined;
    try {
      resolved = ctx.fs.execSync('which', ['lyrie-shield'], { timeout: 3000 }).trim();
    } catch {
      resolved = undefined;
    }

    if (!resolved) {
      evidence.push({
        file: ctx.installation.installDir,
        detail: 'lyrie-shield is not on PATH — Layer-1 (Shield) is unavailable; build it via `cargo build --release` in packages/shield/',
      });
    } else {
      try {
        const out = ctx.fs.execSync(resolved, ['--version'], { timeout: 3000 }).trim();
        if (!out) {
          evidence.push({
            file: resolved,
            detail: 'lyrie-shield --version returned no output — binary may be broken',
          });
        }
      } catch {
        evidence.push({
          file: resolved,
          detail: 'lyrie-shield exists on PATH but failed to execute — binary may be broken',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'lyrie-shield binary is present and runnable',
      failed: () => 'lyrie-shield is missing or broken — Layer-1 enforcement is silently disabled',
      fixDescription: 'Build the Rust Shield: `bun run shield:build` (or `cd packages/shield && cargo build --release`)',
    });
  },
});
