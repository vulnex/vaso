import type { Evidence, ParsedConfig, Severity } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { containerEnvironment, openclawEffectiveBind } from '../../adapters/openclaw-bind.js';

/**
 * Overrides OpenClaw's own `openclaw security audit` flags (2026.9.4,
 * verified against its audit source and `openclaw config validate`), with
 * VASO's severities: critical only where they hand remote or unauthenticated
 * callers code execution or bypass auth on a reachable gateway.
 *
 *  - tools.elevated.allowFrom.<channel> = ["*"]: everyone on that channel may
 *    run elevated (host, outside the sandbox) exec. An agent's own allowFrom
 *    can only narrow the global list, so the global wildcard is what counts.
 *  - gateway.tools.allow re-enabling a tool from the default HTTP deny list
 *    (exec, shell, fs_write, sessions_spawn, gateway, …) on /tools/invoke.
 *  - gateway.allowRealIpFallback: X-Real-IP trusted when X-Forwarded-For is
 *    missing — a forwarded client header can spoof the local-client checks.
 *  - gateway.nodes.commands.allow with camera/screen/contacts/calendar/
 *    reminders/SMS/health commands.
 *  - hooks.allowRequestSessionKey: hook callers choose the session key.
 *  - hooks.path = "/": the hooks endpoint shadows the gateway's other routes.
 *  - browser.ssrfPolicy.dangerouslyAllowPrivateNetwork: browser tooling may
 *    reach private-network addresses (SSRF from a prompt-injected page).
 *
 * `gateway.controlUi.allowInsecureAuth` is not here: 2026.9.4 rejects it as
 * an unrecognized key, so a config containing it doesn't run.
 */

/** Tools OpenClaw denies on HTTP /tools/invoke unless gateway.tools.allow re-enables them. */
const HTTP_DENIED_TOOLS = new Set([
  'exec', 'spawn', 'shell', 'fs_write', 'fs_delete', 'fs_move', 'apply_patch', 'terminal', 'portal',
  'sessions_spawn', 'sessions_send', 'conversations_list', 'conversations_send', 'conversations_turn', 'gateway',
]);

/** OpenClaw's DEFAULT_DANGEROUS_NODE_COMMANDS. */
const DANGEROUS_NODE_COMMANDS = new Set([
  'camera.snap', 'camera.clip', 'camera.ptz.control', 'screen.record', 'desktop.stream',
  'contacts.add', 'calendar.add', 'reminders.add', 'sms.send', 'sms.search', 'health.summary',
]);

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

/**
 * Reachable beyond this host: a non-loopback bind (unset = loopback, "auto"
 * in a container) or Tailscale serve/funnel. "auto" is 0.0.0.0 only inside a
 * container (`inContainer` from containerEnvironment(); unknown counts as
 * loopback).
 */
export function openclawGatewayExposed(data: Record<string, unknown>, inContainer?: boolean): boolean {
  const bind = openclawEffectiveBind(data, inContainer);
  const mode = typeof bind === 'string' ? bind.trim().toLowerCase() : 'loopback';
  if (mode === 'auto' && !inContainer) return tailscaleExposed(data);
  if (mode === 'custom') {
    const host = getNestedValue(data, 'gateway.customBindHost');
    if (typeof host === 'string' && LOOPBACK_HOSTS.has(host.trim())) return tailscaleExposed(data);
    return true;
  }
  return mode !== 'loopback' || tailscaleExposed(data);
}

function tailscaleExposed(data: Record<string, unknown>): boolean {
  const ts = getNestedValue(data, 'gateway.tailscale.mode');
  return ts === 'serve' || ts === 'funnel';
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').map(s => s.trim().toLowerCase()) : [];
}

const RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

export const oc008 = defineCheck({
  id: 'OC-008',
  name: 'Dangerous Gateway Overrides',
  category: 'openclaw',
  severity: 'critical',
  description: 'Detect OpenClaw overrides its own security audit flags: elevated exec open to everyone on a channel, HTTP /tools/invoke re-enabling exec/control tools, X-Real-IP fallback, dangerous node commands, caller-chosen hook session keys, hooks on "/", and browser access to private networks',
  supportedAgents: ['openclaw'],

  async run(ctx, h) {
    // Gateway and tool settings are host-wide; a sub-agent's own file is OC-001's
    if (ctx.installation.agentName) {
      return h.passed('Sub-agent installation; OC-008 only runs at top-level');
    }

    const evidence: Evidence[] = [];
    let worst: Severity = 'info';
    const add = (config: ParsedConfig, severity: Severity, detail: string) => {
      evidence.push({ file: config.filePath, detail: `[${severity}] ${detail}` });
      if (RANK[severity] > RANK[worst]) worst = severity;
    };

    const inContainer = await containerEnvironment(ctx.fs);
    for (const config of ctx.configs) {
      const data = config.data;
      // Remote mode: this host runs no gateway; these keys belong to the remote one
      if (getNestedValue(data, 'gateway.mode') === 'remote') continue;
      const exposed = openclawGatewayExposed(data, inContainer);
      const where = exposed ? 'on a gateway reachable beyond this host' : 'on a loopback-only gateway';

      if (getNestedValue(data, 'tools.elevated.enabled') !== false) {
        const allowFrom = getNestedValue(data, 'tools.elevated.allowFrom');
        if (allowFrom && typeof allowFrom === 'object' && !Array.isArray(allowFrom)) {
          for (const [channel, list] of Object.entries(allowFrom as Record<string, unknown>)) {
            if (strings(list).includes('*')) {
              add(config, 'critical', `tools.elevated.allowFrom.${channel} includes "*" — anyone on ${channel} can run elevated (host) exec`);
            }
          }
        }
      }

      const reenabled = strings(getNestedValue(data, 'gateway.tools.allow')).filter(t => HTTP_DENIED_TOOLS.has(t));
      if (reenabled.length > 0) {
        add(config, exposed ? 'critical' : 'warning',
          `gateway.tools.allow re-enables ${reenabled.join(', ')} on HTTP /tools/invoke ${where}`);
      }

      if (getNestedValue(data, 'gateway.allowRealIpFallback') === true) {
        add(config, exposed ? 'critical' : 'info',
          `gateway.allowRealIpFallback = true — a client-supplied X-Real-IP can spoof the local-client checks ${where}`);
      }

      const nodeCommands = strings(getNestedValue(data, 'gateway.nodes.commands.allow'));
      const denied = new Set(strings(getNestedValue(data, 'gateway.nodes.commands.deny')));
      const dangerous = nodeCommands.filter(c => DANGEROUS_NODE_COMMANDS.has(c) && !denied.has(c));
      if (dangerous.length > 0) {
        add(config, exposed ? 'warning' : 'info',
          `gateway.nodes.commands.allow enables ${dangerous.join(', ')} (device camera/screen/SMS/personal data) ${where}`);
      }

      // Hook settings only matter while the hooks endpoint is on (as OpenClaw audits them)
      if (getNestedValue(data, 'hooks.enabled') === true) {
        if (getNestedValue(data, 'hooks.allowRequestSessionKey') === true) {
          const prefixes = strings(getNestedValue(data, 'hooks.allowedSessionKeyPrefixes'));
          add(config, exposed && prefixes.length === 0 ? 'warning' : 'info',
            `hooks.allowRequestSessionKey = true — hook callers choose the session they write into${prefixes.length > 0 ? ' (limited by allowedSessionKeyPrefixes)' : ''}`);
        }
        const path = getNestedValue(data, 'hooks.path');
        if (typeof path === 'string' && path.trim() === '/') {
          add(config, 'warning', 'hooks.path = "/" — the hooks endpoint shadows the gateway\'s other HTTP routes');
        }
      }

      if (getNestedValue(data, 'browser.ssrfPolicy.dangerouslyAllowPrivateNetwork') === true) {
        add(config, 'warning', 'browser.ssrfPolicy.dangerouslyAllowPrivateNetwork = true — browser tooling can reach private-network hosts (SSRF from untrusted pages)');
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No dangerous OpenClaw gateway, hook, tool or browser overrides',
      failed: (n) => `${n} dangerous OpenClaw override(s) that \`openclaw security audit\` also flags`,
      severity: worst,
      fixDescription: 'Remove "*" from tools.elevated.allowFrom, drop exec/control tools from gateway.tools.allow and dangerous commands from gateway.nodes.commands.allow, set gateway.allowRealIpFallback and hooks.allowRequestSessionKey to false, use a dedicated hooks.path (e.g. "/hooks"), and leave browser.ssrfPolicy.dangerouslyAllowPrivateNetwork unset; run `openclaw security audit` to confirm',
    });
  },
});
