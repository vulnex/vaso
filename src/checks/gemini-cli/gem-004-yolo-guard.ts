import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { parseJsonLenient } from '../../core/jsonc.js';
import { markUntrustedWorkspace } from '../../adapters/folder-trust.js';
import { geminiHome, geminiSystemSettingsPath, geminiWorkspaceTrusted } from '../../adapters/gemini.js';

function disableYoloMode(data: unknown): unknown {
  return ((data as Record<string, unknown> | undefined)?.security as Record<string, unknown> | undefined)?.disableYoloMode;
}

export const gem004 = defineCheck({
  id: 'GEM-004',
  name: 'Gemini YOLO Mode Guard Removed',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect a workspace setting security.disableYoloMode: false that overrides the user\'s guard (re-enabling `--yolo`); an explicit false elsewhere is the default and reported as info',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    // disableYoloMode defaults to false (settingsSchema.ts), so `false` only
    // weakens anything when workspace settings override a user-level `true`
    // (merge order: system defaults < user < workspace < system)
    const guardIn = async (file: string): Promise<boolean> => {
      try {
        return disableYoloMode(parseJsonLenient(await ctx.fs.readFile(file))) === true;
      } catch {
        return false; // no readable settings — no guard to override
      }
    };
    let userGuard = false;
    if (ctx.installation.profile === 'project') {
      // system settings win over the workspace, so a system-level guard holds
      if (await guardIn(geminiSystemSettingsPath(ctx.fs))) return h.passed('System settings keep Gemini\'s YOLO guard on');
      userGuard = await guardIn(join(geminiHome(ctx.fs.homedir(), ctx.fs), 'settings.json'));
    }

    let overrides = false;
    for (const config of ctx.configs) {
      if (disableYoloMode(config.data) !== false) continue;
      if (userGuard) {
        overrides = true;
        evidence.push({
          file: config.filePath,
          snippet: 'security.disableYoloMode = false',
          detail: 'Overrides the user-level disableYoloMode: true — `gemini --yolo` auto-approves every tool call in this workspace again',
        });
      } else {
        evidence.push({
          file: config.filePath,
          snippet: 'security.disableYoloMode = false',
          detail: 'Same as the default — `gemini --yolo` stays available; set true to block it',
        });
      }
    }

    await markUntrustedWorkspace(ctx, evidence, geminiWorkspaceTrusted);

    return h.fromEvidence(evidence, {
      severity: overrides ? 'critical' : 'info',
      passed: 'Gemini YOLO mode guard is not explicitly disabled',
      failed: () => overrides
        ? 'Workspace settings turn off the user\'s YOLO guard — `gemini --yolo` works in this workspace'
        : 'Gemini security.disableYoloMode is false (the default) — `--yolo` sessions remain possible',
      fixDescription: 'Set security.disableYoloMode: true in ~/.gemini/settings.json to block --yolo at the CLI layer, and remove the workspace override',
    });
  },
});
