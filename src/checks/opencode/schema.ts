import { wildcardMatch } from '../../analyzers/wildcard.js';

/**
 * OpenCode config keys in both schema generations (opencode.ai/docs/config):
 *
 *   V1                          V2
 *   permission (object/string)  permissions: [{ action, resource, effect }]
 *     bash / task                 shell / subagent
 *   agent.<id>.permission       agents.<id>.permissions (appended to global)
 *   mcp.<name>                  mcp.servers.<name>
 *   plugin: [spec | [spec, o]]  plugins: [spec | { package, options }]
 *   snapshot: false             snapshots: false
 *   autoupdate: false           update: "disable" | "notify" | "auto"
 *
 * Checks read both, so a config on either side is judged.
 */

type Obj = Record<string, unknown>;

function obj(v: unknown): Obj | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Obj : undefined;
}

export interface OpencodeMcpServer {
  name: string;
  server: Obj;
  /** Dot path for evidence: `mcp.<name>` or `mcp.servers.<name>`. */
  path: string;
}

/** MCP server entries: V2 `mcp.servers.<name>`, else V1 `mcp.<name>`. */
export function opencodeMcpServers(data: Obj): OpencodeMcpServer[] {
  const mcp = obj(data.mcp);
  if (!mcp) return [];
  const servers = obj(mcp.servers);
  // A V1 server literally named "servers" has its own `type`
  const v2 = servers !== undefined && typeof servers.type !== 'string';
  const map = v2 ? servers : mcp;
  const prefix = v2 ? 'mcp.servers' : 'mcp';
  const out: OpencodeMcpServer[] = [];
  for (const [name, raw] of Object.entries(map)) {
    const server = obj(raw);
    if (server) out.push({ name, server, path: `${prefix}.${name}` });
  }
  return out;
}

/** Plugin specs from V1 `plugin` and V2 `plugins`, with the key they came from. */
export function opencodePluginSpecs(data: Obj): Array<{ spec: string; key: 'plugin' | 'plugins' }> {
  const out: Array<{ spec: string; key: 'plugin' | 'plugins' }> = [];
  for (const key of ['plugin', 'plugins'] as const) {
    const list = data[key];
    if (!Array.isArray(list)) continue;
    for (const entry of list) {
      const spec = typeof entry === 'string' ? entry
        : Array.isArray(entry) && typeof entry[0] === 'string' ? entry[0]
          : typeof obj(entry)?.package === 'string' ? obj(entry)!.package as string
            : undefined;
      if (spec) out.push({ spec, key });
    }
  }
  return out;
}

export interface PermissionRule {
  action: string;
  resource: string;
  effect: string;
}

/** V2 `permissions` rules (in order — the last match wins), or undefined when absent. */
export function v2PermissionRules(list: unknown): PermissionRule[] | undefined {
  if (!Array.isArray(list)) return undefined;
  const rules: PermissionRule[] = [];
  for (const raw of list) {
    const r = obj(raw);
    if (!r || typeof r.action !== 'string' || typeof r.effect !== 'string') continue;
    rules.push({
      action: r.action,
      resource: typeof r.resource === 'string' ? r.resource : '*',
      effect: r.effect.toLowerCase(),
    });
  }
  return rules;
}

const V1_TO_V2: Record<string, string> = { bash: 'shell', task: 'subagent' };

/** The V2 action name for a V1 permission key (bash → shell, task → subagent). */
export function v2Action(v1Key: string): string {
  return V1_TO_V2[v1Key] ?? v1Key;
}

const CATCH_ALL = /^\*+$/;

/** Whether a rule's action pattern covers `action`: OpenCode wildcards are
 *  `*` (any run, `/` included) and `?` (exactly one character). */
export function actionMatches(pattern: string, action: string): boolean {
  if (CATCH_ALL.test(pattern) || pattern === action) return true;
  if (!/[*?]/.test(pattern)) return false;
  return wildcardMatch(pattern, action, { question: true });
}

export function isCatchAllResource(resource: string): boolean {
  return CATCH_ALL.test(resource.trim());
}

/**
 * The effect a V2 rule list gives every call of `action` (its last
 * catch-all-resource rule), the index of that rule, or the documented default
 * (allow — the base policy starts with `* * allow`) when none sets it.
 */
export function v2CatchAll(rules: PermissionRule[], action: string): { effect: string; index: number } {
  for (let i = rules.length - 1; i >= 0; i--) {
    const r = rules[i];
    if (isCatchAllResource(r.resource) && actionMatches(r.action, action)) return { effect: r.effect, index: i };
  }
  return { effect: 'allow', index: -1 };
}

/** `snapshot = false` / `snapshots = false`, as an evidence snippet. */
export function snapshotsOff(data: Obj): string | undefined {
  if (data.snapshots === false) return 'snapshots = false';
  if (data.snapshot === false) return 'snapshot = false';
  return undefined;
}

/** `autoupdate = false` / `update = "disable"`, as an evidence snippet. */
export function updatesOff(data: Obj): string | undefined {
  if (typeof data.update === 'string' && data.update.toLowerCase() === 'disable') return 'update = "disable"';
  if (data.autoupdate === false) return 'autoupdate = false';
  return undefined;
}
