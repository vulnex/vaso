import type { Evidence } from '../../core/types.js';
import { resolve } from 'node:path';
import type { MCPConfig, MCPServerEntry } from '../../mcp/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { defaultMcpStateStore } from '../../mcp/mcp-state-store.js';
import { isPinnedOrLocal, runnerPackage } from '../../mcp/package-pin.js';

/**
 * MCP-028 — MCP Configuration Drift.
 *
 * Configuration drift (Hou et al. arXiv 2503.23278 §5.3.3): the MCP config
 * accumulates changes over time that quietly weaken its posture. On each scan we
 * fingerprint the security-relevant shape of every server and compare it to the
 * stored baseline, flagging only *regressions* (a new server, a lost version
 * pin, an https→http downgrade, removed auth). Improvements and removals don't
 * warn. The first scan establishes the baseline. A regression stays reported
 * until it is undone: the baseline keeps the stronger setting.
 */

/**
 * Baseline keyed by config file + server (`baselineKey`). The earlier
 * baseline (`config-drift`, keyed `<source label>::<server>`) is read as a
 * fallback: the label depends on how the file was found (`mcp scan -p` calls
 * every file "Custom"), so it made servers look new.
 */
const DRIFT_KEY = 'config-drift-v2';
const LEGACY_DRIFT_KEY = 'config-drift';
const AUTH_ENV_RE =
  /(authorization|auth[_-]?token|access[_-]?token|api[_-]?key|apikey|bearer|oauth|client[_-]?secret|secret|token|password|credential)/i;

interface ServerFingerprint {
  transport: string;
  pinned: boolean;
  scheme: 'http' | 'https' | 'none';
  hasAuth: boolean;
}

type DriftSnapshot = Record<string, ServerFingerprint>;

function isPinned(server: MCPServerEntry): boolean {
  const pkg = runnerPackage(server.command, server.args);
  return !pkg || isPinnedOrLocal(pkg); // no package runner: pinning not applicable
}

function schemeOf(url?: string): 'http' | 'https' | 'none' {
  if (!url) return 'none';
  if (/^https:\/\//i.test(url)) return 'https';
  if (/^http:\/\//i.test(url)) return 'http';
  return 'none';
}

function hasAuth(server: MCPServerEntry): boolean {
  for (const [key, value] of Object.entries(server.env ?? {})) {
    if (AUTH_ENV_RE.test(key) && String(value).trim().length > 0) return true;
  }
  for (const [key, value] of Object.entries(server.headers ?? {})) {
    if ((AUTH_ENV_RE.test(key) || /bearer\s+\S/i.test(String(value))) && String(value).trim().length > 0) return true;
  }
  if (server.url && /\/\/[^/@]+:[^/@]+@/.test(server.url)) return true; // user:pass@
  if (server.url && /[?&](access_token|token|api_key|apikey|auth)=/i.test(server.url)) return true;
  return false;
}

function fingerprint(server: MCPServerEntry): ServerFingerprint {
  return {
    transport: server.transport,
    pinned: isPinned(server),
    scheme: schemeOf(server.url),
    hasAuth: hasAuth(server),
  };
}

/**
 * Stable per-server key: the config file, plus the project for the
 * per-project servers `~/.claude.json` holds, plus the server name.
 */
function baselineKey(config: MCPConfig, server: MCPServerEntry): string {
  const project = /^Claude Code \(project (.+)\)$/.exec(config.source)?.[1];
  return `${resolve(config.filePath)}${project ? `#${project}` : ''}::${server.name}`;
}

/** What to remember for a server: its current shape, minus any regression from `before`. */
function persisted(before: ServerFingerprint | undefined, now: ServerFingerprint): ServerFingerprint {
  if (!before) return now;
  return {
    ...now,
    pinned: now.pinned || before.pinned,
    scheme: before.scheme === 'https' && now.scheme === 'http' ? 'https' : now.scheme,
    hasAuth: now.hasAuth || before.hasAuth,
  };
}

export const mcp028 = defineCheck({
  id: 'MCP-028',
  name: 'MCP Configuration Drift',
  category: 'mcp',
  severity: 'warning',
  description:
    'Detect security regressions in MCP config since the last scan (new server, lost version pin, https→http, removed auth)',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const configs = ctx.mcpConfigs ?? [];
    const store = ctx.mcpStateStore ?? defaultMcpStateStore();

    const baseline = await store.load<DriftSnapshot>(DRIFT_KEY);
    const legacy = await store.load<DriftSnapshot>(LEGACY_DRIFT_KEY);

    const evidence: Evidence[] = [];
    const next: DriftSnapshot = {};
    for (const config of configs) {
      for (const server of config.servers) {
        const key = baselineKey(config, server);
        const now = fingerprint(server);
        const before = baseline?.[key] ?? legacy?.[`${config.source}::${server.name}`];
        next[key] = persisted(before, now);
        if (!baseline && !legacy) continue;

        // Evidence names the config file and server; the baseline key is internal.
        const at = { file: config.filePath, snippet: `Server "${server.name}" (${config.source})` };
        const name = `"${server.name}" (${config.source})`;
        if (!before) {
          evidence.push({ ...at, detail: `New MCP server ${name} appeared since the last scan` });
          continue;
        }
        if (before.pinned && !now.pinned) {
          evidence.push({ ...at, detail: `MCP server ${name} lost its version pin since the last scan` });
        }
        if (before.scheme === 'https' && now.scheme === 'http') {
          evidence.push({ ...at, detail: `MCP server ${name} was downgraded from https to http since the last scan` });
        }
        if (before.hasAuth && !now.hasAuth) {
          evidence.push({ ...at, detail: `MCP server ${name} had its authentication removed since the last scan` });
        }
      }
    }

    // Merge, don't replace: one baseline serves every scan, and a scan of a
    // single config (`mcp scan -p other.json`, `--source` only) must not
    // erase the entries of configs it didn't look at — the next full scan
    // would report all of them as new.
    await store.save(DRIFT_KEY, { ...(baseline ?? {}), ...next });

    if (!baseline && !legacy) {
      return h.result({
        passed: true,
        severity: 'info',
        message: 'MCP configuration baseline established — drift will be detected on subsequent scans',
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'No security regressions in MCP configuration since the last scan',
      failed: (n) => `Found ${n} security regression(s) in MCP configuration since the last scan`,
    });
  },
});
