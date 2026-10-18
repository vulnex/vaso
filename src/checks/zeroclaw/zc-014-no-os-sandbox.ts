import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { asRecord, effectiveProfiles, isFalse, mainConfig, profileLabel, writeMainConfig, type EffectiveProfile } from './zc-config.js';
import type { KeyPath } from '../../core/utils.js';

function backendNone(p: EffectiveProfile): boolean {
  return typeof p.profile.sandbox_backend === 'string' && p.profile.sandbox_backend.trim().toLowerCase() === 'none';
}

function sandboxOff(p: EffectiveProfile): boolean {
  return !p.legacy && (isFalse(p.profile.sandbox_enabled) || backendNone(p));
}

function nativeRuntime(data: Record<string, unknown>): boolean {
  const kind = asRecord(data.runtime)?.kind;
  return kind === undefined || (typeof kind === 'string' && kind.trim().toLowerCase() === 'native');
}

export const zc014 = defineCheck({
  id: 'ZC-014',
  name: 'Sandbox Disabled',
  category: 'zeroclaw',
  severity: 'warning',
  description:
    'Detect a risk profile with sandbox_enabled=false or sandbox_backend="none" while [runtime] kind is native — shell and tool subprocesses run with no OS-level isolation (Landlock/Firejail/Bubblewrap/Docker/Seatbelt)',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    if (!nativeRuntime(config.data)) return h.passed('Runtime is not native (container/remote isolation)');
    const evidence: Evidence[] = [];
    for (const p of effectiveProfiles(config.data)) {
      if (!sandboxOff(p)) continue;
      evidence.push({
        file: config.filePath,
        detail: `${profileLabel(p)}: ${backendNone(p) ? 'sandbox_backend = "none"' : 'sandbox_enabled = false'} with the native runtime — no OS-level isolation`,
      });
    }
    // "auto" (the default) picks the first backend that works on the host and
    // falls back to none — ZeroClaw 0.8.5 on Ubuntu 24.04 with bwrap and
    // Landlock present still reported active_backend "none". The config can't
    // tell; `zeroclaw security status` can.
    return h.fromEvidence(evidence, {
      passed: 'No agent risk profile disables the sandbox (with backend "auto", confirm the active backend: `zeroclaw security status --agent <alias>`)',
      failed: (n) => `${n} risk profile(s) run tools without an OS sandbox`,
      fixable: true,
      fixDescription:
        'Set sandbox_enabled = true (and sandbox_backend = "auto" or a specific backend) on the risk profile, or run with [runtime] kind = "docker"; then check `zeroclaw security status --agent <alias>` — "auto" falls back to no sandbox when no backend works on the host',
    });
  },

  async fix(ctx) {
    const config = mainConfig(ctx.configs);
    const updates: Array<[KeyPath, unknown]> = [];
    if (config && nativeRuntime(config.data)) {
      for (const p of effectiveProfiles(config.data)) {
        if (!sandboxOff(p)) continue;
        updates.push([[...p.path, 'sandbox_enabled'], true]);
        if (backendNone(p)) updates.push([[...p.path, 'sandbox_backend'], 'auto']);
      }
    }
    return writeMainConfig(ctx, 'ZC-014', updates,
      'Enabled the sandbox on risk profiles (sandbox_enabled=true) — verify the active backend with `zeroclaw security status --agent <alias>`: "auto" runs unsandboxed when no backend works on this host');
  },
});
