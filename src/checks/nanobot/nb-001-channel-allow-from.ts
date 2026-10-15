import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { asRecord, asStringArray, channelSections, isChannelEnabled, nanobotConfigs, pick, pyBool } from './shared.js';

// Channels whose DM gate is `dm.policy` ("open" | "allowlist") instead of the
// base allowFrom list (nanobot/channels/{slack,mattermost,signal}/runtime.py).
// Slack and Mattermost default to "open": any member of the workspace/team.
const DM_POLICY_DEFAULT: Record<string, string> = {
  slack: 'open',
  mattermost: 'open',
  signal: 'allowlist',
};

// Workspace-scoped chat systems: "open" admits every member of the org, not
// the internet at large.
const WORKSPACE_SCOPED = new Set(['slack', 'mattermost']);

export const nb001 = defineCheck({
  id: 'NB-001',
  name: 'Channel Open to Any Sender',
  category: 'nanobot',
  severity: 'critical',
  description: 'Detect enabled chat channels that accept messages from anyone: allowFrom containing "*" (nanobot checks star > allowlist > pairing store > deny, so "*" skips DM pairing), or a Slack/Mattermost/Signal dm.policy of "open". Every accepted sender drives the agent and its tools (shell exec, files, web). An empty allowFrom is safe — unknown senders get a pairing code the owner must approve.',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let critical = false;

    for (const config of nanobotConfigs(ctx.configs)) {
      for (const [name, section] of channelSections(config.data)) {
        // The websocket (WebUI) channel defaults to allowFrom ["*"] and is
        // gated by its connection token instead — see NB-008.
        if (name === 'websocket') continue;
        if (!isChannelEnabled(section)) continue;

        const allowFrom = asStringArray(pick(section, 'allowFrom'));
        if (allowFrom.includes('*')) {
          const scoped = WORKSPACE_SCOPED.has(name);
          if (!scoped) critical = true;
          evidence.push({
            file: config.filePath,
            snippet: `channels.${name}.allowFrom: ["*"]`,
            detail: `Channel "${name}" accepts messages from ${scoped ? 'every workspace member' : 'anyone'} — "*" bypasses the allowlist and DM pairing`,
          });
        }

        if (name in DM_POLICY_DEFAULT) {
          const dm = asRecord(section.dm);
          if (pyBool(dm?.enabled) === false) continue;
          const policy = typeof dm?.policy === 'string' ? dm.policy : DM_POLICY_DEFAULT[name];
          if (policy === 'open') {
            if (!WORKSPACE_SCOPED.has(name)) critical = true;
            evidence.push({
              file: config.filePath,
              snippet: `channels.${name}.dm.policy: "open"${dm?.policy === undefined ? ' (default)' : ''}`,
              detail: WORKSPACE_SCOPED.has(name)
                ? `Channel "${name}" answers direct messages from any workspace member — set dm.policy to "allowlist" with dm.allowFrom`
                : `Channel "${name}" answers direct messages from anyone — set dm.policy to "allowlist"`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Every enabled channel restricts senders (allowlist or DM pairing)',
      failed: (n) => `${n} channel access rule(s) let any sender drive the agent`,
      severity: evidence.length > 0 && !critical ? 'warning' : undefined,
      fixDescription: 'Replace "*" in channels.<name>.allowFrom with explicit sender IDs (or leave it empty to require DM pairing — approve senders with `/pairing approve <code>`); set channels.slack/mattermost.dm.policy to "allowlist" with dm.allowFrom',
    });
  },
});
