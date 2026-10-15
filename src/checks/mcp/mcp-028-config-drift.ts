import type { Evidence } from '../../core/types.js';
import type { MCPServerEntry } from '../../mcp/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { defaultMcpStateStore } from '../../mcp/mcp-state-store.js';

/**
 * MCP-028 — MCP Configuration Drift.
 *
 * Configuration drift (Hou et al. arXiv 2503.23278 §5.3.3): the MCP config
 * accumulates changes over time that quietly weaken its posture. On each scan we
 * fingerprint the security-relevant shape of every server and compare it to the
 * stored baseline, flagging only *regressions* (a new server, a lost version
 * pin, an https→http downgrade, removed auth). Improvements and removals don't
 * warn. The first scan establishes the baseline.
 */

const DRIFT_KEY = 'config-drift';
const PACKAGE_RUNNERS = new Set(['npx', 'npx.cmd', 'pnpm', 'bunx', 'uvx', 'uv', 'pipx']);
const AUTH_ENV_RE =
  /(authorization|auth[_-]?token|access[_-]?token|api[_-]?key|apikey|bearer|oauth|client[_-]?secret|secret|token|password|credential)/i;

interface ServerFingerprint {
  transport: string;
  pinned: boolean;
  scheme: 'http' | 'https' | 'none';
  hasAuth: boolean;
}

type DriftSnapshot = Record<string, ServerFingerprint>;

function basename(p: string): string {
  const idx = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return idx >= 0 ? p.slice(idx + 1) : p;
}

function isPinned(server: MCPServerEntry): boolean {
  const cmd = server.command ? basename(server.command) : undefined;
  if (!cmd || !PACKAGE_RUNNERS.has(cmd)) return true; // pinning not applicable
  for (const arg of server.args ?? []) {
    if (arg.startsWith('-') || arg === 'run' || arg === 'tool') continue;
    return arg.lastIndexOf('@') > 0; // name@version
  }
  return true;
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

function buildSnapshot(ctxConfigs: { source: string; servers: MCPServerEntry[] }[]): DriftSnapshot {
  const snap: DriftSnapshot = {};
  for (const config of ctxConfigs) {
    for (const server of config.servers) {
      snap[`${config.source}::${server.name}`] = fingerprint(server);
    }
  }
  return snap;
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

    const current = buildSnapshot(configs);
    const baseline = await store.load<DriftSnapshot>(DRIFT_KEY);
    // Merge, don't replace: one baseline serves every scan, and a scan of a
    // single config (`mcp scan -p other.json`, `--source` only) must not
    // erase the entries of configs it didn't look at — the next full scan
    // would report all of them as new.
    await store.save(DRIFT_KEY, { ...(baseline ?? {}), ...current });

    if (!baseline) {
      return h.result({
        passed: true,
        severity: 'info',
        message: 'MCP configuration baseline established — drift will be detected on subsequent scans',
      });
    }

    // Evidence names the config file and server; the baseline key
    // (`<source>::<server>`) is internal.
    const where = new Map<string, { file: string; snippet: string }>();
    for (const config of configs) {
      for (const server of config.servers) {
        where.set(`${config.source}::${server.name}`, { file: config.filePath, snippet: `Server "${server.name}" (${config.source})` });
      }
    }
    const evidence: Evidence[] = [];
    for (const [key, now] of Object.entries(current)) {
      const before = baseline[key];
      const at = where.get(key) ?? { file: key, snippet: key };
      const name = at.snippet;
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

    return h.fromEvidence(evidence, {
      passed: 'No security regressions in MCP configuration since the last scan',
      failed: (n) => `Found ${n} security regression(s) in MCP configuration since the last scan`,
    });
  },
});
