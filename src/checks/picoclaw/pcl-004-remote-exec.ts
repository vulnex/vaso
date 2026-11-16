import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envNote, envOverrideFor } from '../../adapters/env-overrides.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { enabledChannels, execConfig, isChatChannel, picoMainConfigs } from './shared.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

export const pcl004 = defineCheck({
  id: 'PCL-004',
  name: 'PicoClaw Chat Channels Can Run Commands',
  category: 'picoclaw',
  severity: 'warning',
  description: 'tools.exec.allow_remote (default true) lets messages from chat channels trigger the exec tool (GHSA-pv8c-p6jf-3fpp). With a chat channel enabled, anyone allowed to message the bot can run shell commands on this host.',
  supportedAgents: ['picoclaw'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    // A value set by an env var survives any config edit: no fix to offer then
    let envSet = false;
    for (const config of picoMainConfigs(ctx.configs)) {
      const { enabled, cfg } = execConfig(config.data);
      if (!enabled || cfg.allow_remote === false) continue;
      const chats = enabledChannels(config.data).filter(isChatChannel);
      if (chats.length === 0) continue;
      envSet ||= envOverrideFor(config.data, 'tools.exec.allow_remote') !== undefined;
      evidence.push({
        file: config.filePath,
        snippet: `tools.exec.allow_remote: ${cfg.allow_remote === true ? 'true' : '(default true)'}${envNote(config.data, 'tools.exec.allow_remote')}`,
        detail: `Exec is reachable from ${chats.map(c => c.name).join(', ')}`,
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'PicoClaw exec is limited to internal channels',
      failed: () => 'PicoClaw chat channels can run shell commands',
      fixable: !envSet,
      fixDescription: envSet
        ? 'Unset PICOCLAW_TOOLS_EXEC_ALLOW_REMOTE (it overrides the config file), then set tools.exec.allow_remote to false'
        : 'Set tools.exec.allow_remote to false (exec stays available to the local CLI and launcher)',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(picoMainConfigs(ctx.configs), {
      checkId: 'PCL-004',
      path: 'tools.exec.allow_remote',
      value: false,
      message: 'Set tools.exec.allow_remote to false',
    });
  },
});
