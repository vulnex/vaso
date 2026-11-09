import { join } from 'node:path';
import { parseYamlSafe } from '../../core/yaml-safe.js';
import { parseIfPresent, pathPresent } from '../../adapters/load-if-present.js';
import type { Evidence, ParsedConfig, ScanContext } from '../../core/types.js';
import type { PermissionFacts } from '../../core/fs-provider.js';
import { queryPermissions } from '../../core/permissions.js';
import {
  BREW_VAR_DIRS,
  GLOBAL_POLICY_ARGS,
  DEFAULT_WORKSPACE,
  SANDBOX_LIST_ARGS,
  SNAP_COMMON_DIR,
  SNAP_USER_REL,
  envTruthy,
  expandHome,
  gatewayTable,
  openShellPaths,
  sandboxPolicyArgs,
  snapUserDir,
  type OpenShellPaths,
} from '../../adapters/openshell.js';

/**
 * Shared helpers for the OpenShell checks. Semantics verified against the
 * 0.1.2 gateway (`openshell-gateway config preflight`, live `policy set` /
 * `sandbox create`) and the 0.0.116 gateway NemoClaw sets up.
 */

export { envTruthy };

export function record(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined;
}

/** Home of the user this installation belongs to (`--all-users` scans other homes). */
export function installHome(ctx: ScanContext): string {
  const dir = ctx.installation.installDir;
  for (const suffix of ['/.config/openshell', '/.local/state/openshell', `/${SNAP_USER_REL}`]) {
    if (dir.endsWith(suffix)) return dir.slice(0, -suffix.length);
  }
  // $XDG_* overrides and package-managed gateways only apply to the scanning user
  return ctx.fs.homedir();
}

/** Whether this installation is the scanning user's own (live CLI queries answer for that user only). */
export function ownInstall(ctx: ScanContext): boolean {
  return installHome(ctx) === ctx.fs.homedir();
}

export function paths(ctx: ScanContext): OpenShellPaths {
  return openShellPaths(installHome(ctx), ctx.fs);
}

/** The gateway TOML the service loads (at most one per installation). */
export function gatewayToml(ctx: ScanContext): ParsedConfig | undefined {
  return ctx.configs.find(c => c.format === 'toml' && gatewayTable(c));
}

/** The gateway env file (systemd EnvironmentFile / Homebrew wrapper). */
export function gatewayEnv(ctx: ScanContext): ParsedConfig | undefined {
  return ctx.configs.find(c => c.format === 'env');
}

export function gateway(ctx: ScanContext): Record<string, unknown> {
  const toml = gatewayToml(ctx);
  return (toml && gatewayTable(toml)) ?? {};
}

/** Root `[openshell]` table (holds `version`, `drivers`, `supervisor`, …). */
export function root(ctx: ScanContext): Record<string, unknown> {
  return record(gatewayToml(ctx)?.data.openshell) ?? {};
}

const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|::1)$/i;

/** The gateway listens beyond loopback (other hosts can reach it). */
export function exposed(ctx: ScanContext): boolean {
  const host = ctx.installation.gateway?.host?.trim();
  return !!host && !LOOPBACK.test(host.replace(/^\[|\]$/g, ''));
}

/** Evidence for a setting, pointing at the file it was read from. */
export function settingEvidence(config: ParsedConfig | undefined, snippet: string, detail: string): Evidence {
  return { file: config?.filePath ?? '', snippet, detail };
}

// ── Permissions ──────────────────────────────────────────────────────────────

export async function facts(ctx: ScanContext, path: string): Promise<PermissionFacts | undefined> {
  if (!(await ctx.fs.access(path))) return undefined;
  try {
    const q = await queryPermissions(ctx.fs, path);
    return q === 'unsupported' ? undefined : q;
  } catch {
    return undefined;
  }
}

export async function listDir(ctx: ScanContext, dir: string): Promise<{ name: string; path: string; isDirectory: boolean }[]> {
  try {
    return (await ctx.fs.readdirEntries(dir)).map(e => ({ name: e.name, path: join(dir, e.name), isDirectory: e.isDirectory }));
  } catch {
    return [];
  }
}

/**
 * The TLS directory gateway.env redirects to (OPENSHELL_LOCAL_TLS_DIR). The
 * probe manifest lists fixed locations only, so a remote snapshot never holds it.
 */
export function redirectedTlsDir(ctx: ScanContext): string | undefined {
  const env = gatewayEnv(ctx)?.data.OPENSHELL_LOCAL_TLS_DIR;
  return typeof env === 'string' && env.trim() ? expandHome(env.trim(), paths(ctx).home) : undefined;
}

/** The sqlite database gateway.env redirects to (`OPENSHELL_DB_URL=sqlite:<path>`); not in a remote snapshot either. */
export function redirectedDatabase(ctx: ScanContext): string | undefined {
  const url = gatewayEnv(ctx)?.data.OPENSHELL_DB_URL;
  if (typeof url !== 'string') return undefined;
  const m = /^sqlite:(?:\/\/)?(.+?)(?:\?.*)?$/.exec(url.trim());
  return m ? expandHome(m[1], paths(ctx).home) : undefined;
}

/** TLS directories the gateway may use: env override, deb/systemd, Homebrew (prefix + mirror), snap. */
export function tlsDirs(ctx: ScanContext): string[] {
  const env = redirectedTlsDir(ctx);
  return [...new Set([...(env ? [env] : []), ...fixedTlsDirs(ctx)])];
}

/** The TLS directories at fixed locations (the ones the probe manifest collects). */
export function fixedTlsDirs(ctx: ScanContext): string[] {
  const p = paths(ctx);
  const dirs = [
    join(p.stateDir, 'tls'),
    join(p.stateDir, 'homebrew', 'tls'),
    ...(ctx.fs.platform === 'darwin' ? BREW_VAR_DIRS.map(d => join(d, 'tls')) : []),
    join(SNAP_COMMON_DIR, 'tls'),
    join(snapUserDir(p.home), '.local', 'state', 'openshell', 'tls'),
  ];
  return [...new Set(dirs)];
}

/** sqlite path of the gateway database (env `OPENSHELL_DB_URL=sqlite:<path>` or the default). */
export function databasePaths(ctx: ScanContext): string[] {
  const redirected = redirectedDatabase(ctx);
  return [...new Set([...(redirected ? [redirected] : []), ...fixedDatabasePaths(ctx)])];
}

/** The database at its fixed locations (the ones the probe manifest collects). */
export function fixedDatabasePaths(ctx: ScanContext): string[] {
  const p = paths(ctx);
  return [
    join(p.stateDir, 'gateway', 'openshell.db'),
    join(snapUserDir(p.home), '.local', 'state', 'openshell', 'gateway', 'openshell.db'),
  ];
}

// ── Sandbox policies ─────────────────────────────────────────────────────────

export interface PolicyRef {
  /** Where it came from — a file path, or `sandbox <workspace>/<name>` / `global policy`. */
  source: string;
  /** Evidence `file`: the policy file, or a label for a live policy. */
  file: string;
  policy: Record<string, unknown>;
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_SANDBOXES = 100;

/** The policies OSH-011–014 judge, and the sources that could not be read. */
export interface PolicyScan {
  refs: PolicyRef[];
  /** Why a source was skipped (`sandbox list` failed, an unreadable policy file…) */
  unread: string[];
}

const cache = new WeakMap<object, Promise<PolicyScan>>();

function parseJson(stdout: string): Record<string, unknown> | undefined {
  try {
    return record(JSON.parse(stdout));
  } catch {
    return undefined;
  }
}

/** `sandbox list -o json`: `{"sandboxes": [...]}` on 0.1.x, a bare array on 0.0.x. */
function sandboxItems(stdout: string): unknown[] | undefined {
  try {
    const parsed = JSON.parse(stdout) as unknown;
    if (Array.isArray(parsed)) return parsed;
    const items = record(parsed)?.sandboxes;
    return Array.isArray(items) ? items : undefined;
  } catch {
    return undefined;
  }
}

async function livePolicies(ctx: ScanContext, unread: string[]): Promise<PolicyRef[]> {
  const cli = ctx.installation.cliBinary;
  if (!ownInstall(ctx)) return [];
  if (!cli) {
    // nothing was queried: say so rather than "no sandbox policies found"
    unread.push('live sandbox policies (no `openshell` CLI found to query them)');
    return [];
  }
  const run = (args: readonly string[]) => ctx.fs.exec(cli, [...args], { timeout: 15000 });
  const out: PolicyRef[] = [];

  const list = await run(SANDBOX_LIST_ARGS);
  const sandboxes = list.exitCode === 0 ? sandboxItems(list.stdout) : undefined;
  if (!sandboxes) {
    unread.push(list.exitCode === 0 ? '`openshell sandbox list` output was not understood' : `\`openshell sandbox list\` failed (exit ${list.exitCode})`);
  } else {
    if (sandboxes.length > MAX_SANDBOXES) unread.push(`${sandboxes.length - MAX_SANDBOXES} sandbox(es) beyond the first ${MAX_SANDBOXES}`);
    for (const item of sandboxes.slice(0, MAX_SANDBOXES)) {
      const sb = record(item);
      const name = sb?.name;
      const ws = sb?.workspace;
      const workspace = ws === undefined || ws === null || ws === '' ? DEFAULT_WORKSPACE : ws;
      if (typeof workspace !== 'string') continue;
      if (typeof name !== 'string' || !NAME.test(name) || !NAME.test(workspace)) continue;
      const res = await run(sandboxPolicyArgs(name, workspace));
      const policy = res.exitCode === 0 ? record(parseJson(res.stdout)?.policy) : undefined;
      // A sandbox without an active policy answers non-zero ("no active
      // policy configured for sandbox"): nothing to judge, not a failure
      if (policy) out.push({ source: `sandbox ${workspace}/${name}`, file: `openshell sandbox ${workspace}/${name}`, policy });
    }
  }

  // No global policy is the normal case: a failed query is not reported
  const global = await run(GLOBAL_POLICY_ARGS);
  const gp = global.exitCode === 0 ? record(parseJson(global.stdout)?.policy) : undefined;
  if (gp) out.push({ source: 'global policy', file: 'openshell global policy', policy: gp });
  return out;
}

/**
 * The policy file `openshell sandbox create` uses by default
 * ($OPENSHELL_SANDBOX_POLICY). One that is there but can't be read or parsed
 * is a CONFIG-LOAD finding (parseIfPresent), not an empty policy set.
 */
async function filePolicies(ctx: ScanContext, unread: string[]): Promise<PolicyRef[]> {
  const path = ownInstall(ctx) ? ctx.fs.getEnv('OPENSHELL_SANDBOX_POLICY')?.trim() : undefined;
  if (!path) return [];
  if (!(await pathPresent(path, ctx.fs))) {
    unread.push(`$OPENSHELL_SANDBOX_POLICY file ${path} not found`);
    return [];
  }
  const policy = await parseIfPresent(path, ctx.fs, raw => {
    const parsed = record(path.endsWith('.json') ? JSON.parse(raw) : parseYamlSafe(raw));
    if (!parsed) throw new Error('not a sandbox policy (expected a mapping)');
    return parsed;
  });
  if (!policy) {
    unread.push(`$OPENSHELL_SANDBOX_POLICY file ${path} could not be read`);
    return [];
  }
  return [{ source: path, file: path, policy }];
}

/** Every sandbox policy in reach and the sources that could not be read. */
export function policyScan(ctx: ScanContext): Promise<PolicyScan> {
  let p = cache.get(ctx.installation);
  if (!p) {
    p = (async () => {
      const unread: string[] = [];
      const refs = [
        ...await filePolicies(ctx, unread),
        ...await livePolicies(ctx, unread).catch(() => { unread.push('live sandbox policies (query failed)'); return []; }),
      ];
      return { refs, unread };
    })();
    cache.set(ctx.installation, p);
  }
  return p;
}

/** Every sandbox policy in reach: each sandbox's effective policy, the global policy, and $OPENSHELL_SANDBOX_POLICY. */
export async function sandboxPolicies(ctx: ScanContext): Promise<PolicyRef[]> {
  return (await policyScan(ctx)).refs;
}

/**
 * Pass message for OSH-011–014: the affirmative `verdict` only when it covers
 * every policy; never when none was read.
 */
export async function policyPassMessage(ctx: ScanContext, verdict: string): Promise<string> {
  const { refs, unread } = await policyScan(ctx);
  const skipped = unread.length > 0 ? `not checked: ${unread.join('; ')}` : '';
  if (refs.length === 0) return skipped ? `No sandbox policy could be checked — ${skipped}` : 'No sandbox policies found — nothing to check';
  return skipped ? `${verdict} (${refs.length} polic${refs.length === 1 ? 'y' : 'ies'} read; ${skipped})` : verdict;
}

export interface EndpointRef {
  ref: PolicyRef;
  rule: string;
  endpoint: Record<string, unknown>;
  binaries: string[];
}

export interface RuleRef {
  ref: PolicyRef;
  rule: string;
  endpoints: Record<string, unknown>[];
  binaries: string[];
}

export function networkRules(refs: PolicyRef[]): RuleRef[] {
  const out: RuleRef[] = [];
  for (const ref of refs) {
    for (const [rule, value] of Object.entries(record(ref.policy.network_policies) ?? {})) {
      const r = record(value);
      if (!r) continue;
      const endpoints = Array.isArray(r.endpoints) ? r.endpoints.map(record).filter((e): e is Record<string, unknown> => !!e) : [];
      const binaries = Array.isArray(r.binaries)
        ? r.binaries.map(b => record(b)?.path).filter((p): p is string => typeof p === 'string')
        : [];
      out.push({ ref, rule, endpoints, binaries });
    }
  }
  return out;
}

export function endpoints(refs: PolicyRef[]): EndpointRef[] {
  return networkRules(refs).flatMap(r => r.endpoints.map(endpoint => ({ ref: r.ref, rule: r.rule, endpoint, binaries: r.binaries })));
}

export function describeEndpoint(e: Record<string, unknown>): string {
  const host = typeof e.host === 'string' ? e.host : Array.isArray(e.allowed_ips) ? `[${e.allowed_ips.join(', ')}]` : '*';
  const ports = Array.isArray(e.ports) ? e.ports.join(',') : e.port;
  return ports !== undefined ? `${host}:${ports}` : host;
}
