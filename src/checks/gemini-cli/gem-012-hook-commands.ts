import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { truncateSnippet } from '../../core/patterns.js';
import { markUntrustedWorkspace } from '../../adapters/folder-trust.js';
import { geminiHome, geminiSystemDefaultsPath, geminiSystemSettingsPath, geminiWorkspaceTrusted } from '../../adapters/gemini.js';
import { parseJsonLenient } from '../../core/jsonc.js';
import { join } from 'node:path';
import type { ScanContext } from '../../core/types.js';
import { hookExpansion, hookItemRisks, hookItems, topTier, hookSnippet } from '../../analyzers/hook-commands.js';

// Hooks in settings.json (`{Event: [{matcher, hooks: [{type: "command",
// command}]}]}`) run with the user's privileges on every matching event,
// the event JSON on stdin; a project .gemini/settings.json brings its own
// (geminicli.com/docs/hooks). Gemini sets these for every hook — paths and
// IDs it chooses itself, never tool or prompt input.
const GEMINI_HOOK_VARIABLES = ['GEMINI_PROJECT_DIR', 'GEMINI_PLANS_DIR', 'GEMINI_SESSION_ID', 'GEMINI_CWD', 'CLAUDE_PROJECT_DIR'];
const EXPANSION = hookExpansion(GEMINI_HOOK_VARIABLES);

function hooksConfig(data: unknown): Record<string, unknown> | undefined {
  const hc = (data as Record<string, unknown> | undefined)?.hooksConfig;
  return hc && typeof hc === 'object' && !Array.isArray(hc) ? hc as Record<string, unknown> : undefined;
}

/**
 * The effective `hooksConfig` switches (cli config.ts: `enableHooks:
 * hooksConfig.enabled`, `disabledHooks: hooksConfig.disabled`). Settings merge
 * system defaults < user < workspace < system; `enabled` (default true) comes
 * from the highest layer that sets it, `disabled` is a union of every layer
 * (mergeStrategy UNION). A user-level scan cannot see a workspace that turns
 * hooks back on, so an off switch only mitigates — it never hides a hook.
 */
async function hookSwitches(ctx: ScanContext): Promise<{ enabled: boolean; disabled: Set<string> }> {
  const fs = ctx.fs;
  const read = async (file: string): Promise<unknown> => {
    const loaded = ctx.configs.find(c => c.filePath === file);
    if (loaded) return loaded.data;
    try { return parseJsonLenient(await fs.readFile(file)); } catch { return undefined; }
  };
  const system = geminiSystemSettingsPath(fs);
  const defaults = geminiSystemDefaultsPath(fs);
  const user = join(geminiHome(fs.homedir(), fs), 'settings.json');
  const workspace = ctx.installation.profile === 'project'
    ? ctx.configs.filter(c => c.filePath.endsWith('settings.json') && ![system, defaults, user].includes(c.filePath)).map(c => c.data)
    : [];
  const layers = [await read(defaults), await read(user), ...workspace, await read(system)];
  let enabled = true;
  const disabled = new Set<string>();
  for (const layer of layers) {
    const hc = hooksConfig(layer);
    if (!hc) continue;
    if (typeof hc.enabled === 'boolean') enabled = hc.enabled;
    if (Array.isArray(hc.disabled)) for (const d of hc.disabled) if (typeof d === 'string') disabled.add(d);
  }
  return { enabled, disabled };
}

export const gem012 = defineCheck({
  id: 'GEM-012',
  name: 'Gemini Hook Command Fetches Code or Exfiltrates',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Gemini CLI settings.json hooks that download and execute code, send credentials or hook input over the network, or re-evaluate input as code',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let critical = false;
    const switches = await hookSwitches(ctx);

    for (const config of ctx.configs) {
      for (const item of hookItems(config.data.hooks)) {
        const risks = hookItemRisks(item, { expansion: EXPANSION });
        const tier = topTier(risks);
        if (!tier) continue;
        // hookRegistry getHookName: the hook's name, else its command
        const off = !switches.enabled ? 'hooksConfig.enabled is false — Gemini runs no hooks'
          : switches.disabled.has(item.name ?? item.scripts[0] ?? '') ? 'listed in hooksConfig.disabled — Gemini skips it'
          : undefined;
        if (tier === 'critical' && !off) critical = true;
        evidence.push({
          file: config.filePath,
          snippet: hookSnippet(item.event, truncateSnippet(item.url ?? item.scripts[0], 120), item.matcher ? `(${item.matcher})` : ''),
          detail: `Hook command ${risks.map(r => r.reason).join('; ')}${off ? ` (mitigated: ${off})` : ''}`,
          ...(tier === 'info' || off ? { mitigated: true } : {}),
        });
      }
    }

    // A project's hooks run only in a trusted workspace
    await markUntrustedWorkspace(ctx, evidence, geminiWorkspaceTrusted);

    return h.fromEvidence(evidence, {
      passed: 'No Gemini hook command downloads code, sends data out or runs input as code',
      failed: (n) => `Found ${n} Gemini hook command(s) that download code, send data over the network or run hook input as code`,
      severity: critical ? 'critical' : 'warning',
      fixDescription: 'Remove hooks you did not add yourself (a project .gemini/settings.json arrives with the repo); run reviewed scripts instead of downloads, send audit data only to https endpoints you control, and never eval or pipe hook input into a shell',
    });
  },
});
