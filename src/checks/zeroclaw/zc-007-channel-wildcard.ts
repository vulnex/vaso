import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { asRecord, hasWildcard, isTrue, mainConfig, type Rec } from './zc-config.js';

/**
 * Per-channel sender allowlists where "*" admits everyone, by channel type
 * as ZeroClaw 0.8.5's schema (`zeroclaw config schema`) declares them. A key
 * a channel type doesn't have (telegram `allowed_users`) is rejected as an
 * unknown property and never applied, so it is not judged.
 */
const CHANNEL_ALLOW_KEYS: Record<string, string[]> = {
  wecom_ws: ['allowed_users', 'allowed_groups'],
  whatsapp: ['allowed_groups'],
  matrix: ['allowed_rooms'],
};
const ALL_ALLOW_KEYS = [...new Set(Object.values(CHANNEL_ALLOW_KEYS).flat())];

/** Chat policies that admit every sender: whatsapp `dm_policy`/`group_policy`
 *  = "all" (default allowlist), line `dm_policy` = "open" (default pairing) and
 *  `group_policy` = "open" (answers every group message; default mention). */
const OPEN_POLICIES: Record<string, Record<string, string>> = {
  whatsapp: { dm_policy: 'all', group_policy: 'all' },
  line: { dm_policy: 'open', group_policy: 'open' },
};

/** `[channels.<type>.<alias>]` instances. Scalars among the channel types
 *  (cli, message_timeout_secs, …) are skipped; a pre-V3 single-instance
 *  table is treated as one instance. */
function channelInstances(data: Rec): Array<{ type: string; alias?: string; cfg: Rec }> {
  const channels = asRecord(data.channels);
  if (!channels) return [];
  const out: Array<{ type: string; alias?: string; cfg: Rec }> = [];
  for (const [type, raw] of Object.entries(channels)) {
    const table = asRecord(raw);
    if (!table) continue;
    const legacy = typeof table.enabled === 'boolean' || ALL_ALLOW_KEYS.some(k => Array.isArray(table[k]))
      || Object.keys(OPEN_POLICIES[type] ?? {}).some(k => typeof table[k] === 'string');
    if (legacy) {
      out.push({ type, cfg: table });
      continue;
    }
    for (const [alias, inst] of Object.entries(table)) {
      const cfg = asRecord(inst);
      if (cfg) out.push({ type, alias, cfg });
    }
  }
  return out;
}

export const zc007 = defineCheck({
  id: 'ZC-007',
  name: 'Open-to-Anyone Channel Access',
  category: 'zeroclaw',
  severity: 'critical',
  description:
    'Detect channels that admit any sender: [peer_groups.<name>] external_peers = ["*"], a channel instance allowlist containing "*" (wecom_ws allowed_users/allowed_groups, whatsapp allowed_groups, matrix allowed_rooms), or an open chat policy (whatsapp dm_policy/group_policy = "all", line dm_policy/group_policy = "open")',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const instances = channelInstances(config.data);
    const evidence: Evidence[] = [];

    // Channels default to enabled=false; a wildcard on a disabled channel is
    // latent (reported at info via `mitigated`).
    const channelLive = (ref: string): boolean => {
      const [type, alias] = ref.split('.', 2);
      return instances.some(i => i.type === type && (alias === undefined || i.alias === alias) && isTrue(i.cfg.enabled));
    };

    const groups = asRecord(config.data.peer_groups) ?? {};
    for (const [name, raw] of Object.entries(groups)) {
      const g = asRecord(raw);
      if (!g || !hasWildcard(g.external_peers) || hasWildcard(g.ignore)) continue;
      const channel = typeof g.channel === 'string' ? g.channel.trim() : '';
      const live = channel !== '' && channelLive(channel);
      const agents = Array.isArray(g.agents) ? (g.agents as unknown[]).filter(a => typeof a === 'string').join(', ') : '';
      evidence.push({
        file: config.filePath,
        detail:
          `peer_groups.${name}: external_peers = ["*"] on channel "${channel || '?'}"` +
          (agents ? ` (agents: ${agents})` : '') +
          (live ? ' — any account on that channel can message the agent' : ' — channel not enabled'),
        ...(live ? {} : { mitigated: true }),
      });
    }

    for (const inst of instances) {
      const live = isTrue(inst.cfg.enabled);
      const path = `channels.${inst.type}${inst.alias ? `.${inst.alias}` : ''}`;
      for (const key of CHANNEL_ALLOW_KEYS[inst.type] ?? []) {
        if (!hasWildcard(inst.cfg[key])) continue;
        evidence.push({
          file: config.filePath,
          detail: `${path}: ${key} = ["*"]` + (live ? ' — any sender is admitted' : ' — channel not enabled'),
          ...(live ? {} : { mitigated: true }),
        });
      }
      for (const [key, open] of Object.entries(OPEN_POLICIES[inst.type] ?? {})) {
        if (inst.cfg[key] !== open) continue;
        evidence.push({
          file: config.filePath,
          snippet: `${key} = "${open}"`,
          detail: `${path}: ${key} = "${open}"` + (live ? ` — the agent answers every ${key.startsWith('dm') ? 'direct message' : 'group message'}` : ' — channel not enabled'),
          ...(live ? {} : { mitigated: true }),
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No channel admits arbitrary senders',
      failed: (n) => `${n} channel allowlist(s) or chat policies admit any sender`,
      fixDescription:
        'Replace "*" with explicit usernames in [peer_groups.<name>] external_peers (or the channel allowlist); use ignore for blocklists; set whatsapp dm_policy/group_policy = "allowlist" and line dm_policy = "pairing" / group_policy = "mention"',
    });
  },
});
