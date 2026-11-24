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
 *  `*` (any run, `/` included) and `?` (exactly one UTF-16 code unit — a
 *  RegExp `.` without the `u` flag). */
export function actionMatches(pattern: string, action: string): boolean {
  if (CATCH_ALL.test(pattern) || pattern === action) return true;
  if (!/[*?]/.test(pattern)) return false;
  return wildcardMatch(pattern, action, { question: true, unit: 'utf16' });
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

/** One V1 permission rule: `permission.<key>` (string → pattern `*`) or `permission.<key>.<pattern>`. */
export interface V1PermissionRule {
  key: string;
  pattern: string;
  action: string;
  /** The config layer that set it. */
  file: string;
  /** From a whole-config string (`permission: "allow"`). */
  fromString?: boolean;
}

type V1Entry = { action: string; file: string; fromString?: boolean } | Map<string, { action: string; file: string }>;

/**
 * V1 `permission` as OpenCode builds it: every layer (config files,
 * $OPENCODE_CONFIG_CONTENT, then $OPENCODE_PERMISSION over the result) is
 * deep-merged in load order (remeda `mergeDeep`: a key already present keeps
 * its place, new keys are appended, objects merge, anything else replaces),
 * a string is `{ "*": s }`, and the result is flattened into rules in key
 * order (`Permission.fromConfig`) — the last matching rule wins. Undefined
 * when no layer sets `permission`.
 */
export function v1PermissionRules(configs: Array<{ filePath: string; data: Obj }>): V1PermissionRule[] | undefined {
  const merged = new Map<string, V1Entry>();
  let seen = false;
  for (const config of configs) {
    const raw = config.data.permission;
    const fromString = typeof raw === 'string';
    const perm = fromString ? { '*': raw } : obj(raw);
    if (!perm) continue;
    seen = true;
    for (const [key, value] of Object.entries(perm)) {
      if (typeof value === 'string') {
        merged.set(key, { action: value.toLowerCase(), file: config.filePath, ...(fromString ? { fromString } : {}) });
        continue;
      }
      const rules = obj(value);
      if (!rules) continue;
      const prev = merged.get(key);
      const target = prev instanceof Map ? prev : new Map<string, { action: string; file: string }>();
      for (const [pattern, action] of Object.entries(rules)) {
        if (typeof action === 'string') target.set(pattern, { action: action.toLowerCase(), file: config.filePath });
      }
      merged.set(key, target);
    }
  }
  if (!seen) return undefined;
  const out: V1PermissionRule[] = [];
  for (const [key, entry] of merged) {
    if (entry instanceof Map) {
      for (const [pattern, r] of entry) out.push({ key, pattern, action: r.action, file: r.file });
    } else {
      out.push({ key, pattern: '*', ...entry });
    }
  }
  return out;
}

/** The last V1 rule that gives every call of `tool` its action (catch-all pattern), and its index. */
export function v1CatchAll(rules: V1PermissionRule[], tool: string): { rule: V1PermissionRule; index: number } | undefined {
  for (let i = rules.length - 1; i >= 0; i--) {
    const r = rules[i];
    if (isCatchAllResource(r.pattern) && actionMatches(r.key, tool)) return { rule: r, index: i };
  }
  return undefined;
}

/**
 * Scoped `pattern → "allow"` rules of `tool` that still apply: no later rule
 * for the tool takes the same pattern or every call back to ask/deny.
 */
export function v1ScopedAllows(rules: V1PermissionRule[], tool: string): V1PermissionRule[] {
  return rules.filter((r, i) => r.key === tool && r.action === 'allow' && !isCatchAllResource(r.pattern)
    && !rules.slice(i + 1).some(l => actionMatches(l.key, tool) && l.action !== 'allow'
      && (isCatchAllResource(l.pattern) || l.pattern === r.pattern)));
}
