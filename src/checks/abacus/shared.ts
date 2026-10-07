import { basename, dirname, join } from 'node:path';
import type { Evidence, ParsedConfig, ScanContext } from '../../core/types.js';

/**
 * Shared helpers for the Abacus.AI checks. Layout and semantics come from the
 * 2.10.2 CLI binary and the 2.2.4 desktop app:
 * - config.json (user ~/.abacusai, project <workspace>/.abacusai) and the
 *   desktop's agent-config-<mode>.json are settings files; `mcpServers` there
 *   is an array of { name, command, args, env }.
 * - mcp.json and the desktop's mcp-<mode>.json hold an `mcpServers` map of
 *   stdio ({ command, args, env }) or remote ({ type, url, headers, oauth })
 *   servers, each optionally `disabled` / `autoApprove`.
 * - A project file is only partly honoured until the workspace is trusted:
 *   baseUrl, permissionMode, mcpServers, additionalDirectories,
 *   additionalMcpConfigPaths, loadExternalMcpConfigs and permissions.allow /
 *   permissions.strictness are dropped, and project MCP servers and skills are
 *   not loaded.
 */

export function abacusDir(ctx: ScanContext): string {
  return join(ctx.fs.homedir(), '.abacusai');
}

export function isProjectInstall(ctx: ScanContext): boolean {
  return ctx.installation.profile === 'project';
}

const MCP_FILE = /(?:^|[\\/])mcp(?:-[a-z]+)?\.json$/;

/** Settings files (config.json, agent-config-<mode>.json) — not the MCP-only files. */
export function settingsConfigs(configs: ParsedConfig[]): ParsedConfig[] {
  return configs.filter(c => !MCP_FILE.test(c.filePath));
}

export interface McpServerRef {
  config: ParsedConfig;
  name: string;
  server: Record<string, unknown>;
  /** Dot path of the server inside its file, for evidence snippets. */
  path: string;
}

/** Every enabled MCP server definition across both config shapes. */
export function mcpServers(configs: ParsedConfig[]): McpServerRef[] {
  const refs: McpServerRef[] = [];
  for (const config of configs) {
    const raw = config.data.mcpServers;
    if (Array.isArray(raw)) {
      raw.forEach((entry, i) => {
        if (!entry || typeof entry !== 'object') return;
        const server = entry as Record<string, unknown>;
        const name = typeof server.name === 'string' ? server.name : `#${i}`;
        refs.push({ config, name, server, path: `mcpServers[${i}]` });
      });
    } else if (raw && typeof raw === 'object') {
      for (const [name, entry] of Object.entries(raw as Record<string, unknown>)) {
        if (!entry || typeof entry !== 'object') continue;
        const server = entry as Record<string, unknown>;
        if (server.disabled === true) continue;
        refs.push({ config, name, server, path: `mcpServers.${name}` });
      }
    }
  }
  return refs;
}

const TRUTHY = new Set(['1', 'true', 'yes', 'on']);

export function envFlag(ctx: ScanContext, name: string): boolean {
  return TRUTHY.has((ctx.fs.getEnv(name) ?? '').trim().toLowerCase());
}

/** Workspaces recorded in ~/.abacusai/trusted-workspaces.json ({ workspaces: { <path>: { trustedAt } } }). */
export async function trustedWorkspaces(ctx: ScanContext): Promise<{ file: string; paths: string[] }> {
  const file = join(abacusDir(ctx), 'trusted-workspaces.json');
  try {
    const data = JSON.parse(await ctx.fs.readFile(file)) as { workspaces?: unknown };
    const ws = data.workspaces;
    return { file, paths: ws && typeof ws === 'object' && !Array.isArray(ws) ? Object.keys(ws) : [] };
  } catch {
    return { file, paths: [] };
  }
}

/** Whether the CLI honours this project installation's escalating settings. */
export async function projectTrusted(ctx: ScanContext): Promise<boolean> {
  if (envFlag(ctx, 'ABACUS_TRUST_WORKSPACE')) return true;
  // Trust is inherited: a trusted directory covers every workspace beneath it
  // (verified against the 2.10.2 CLI).
  const workspace = dirname(ctx.installation.installDir);
  const { paths } = await trustedWorkspaces(ctx);
  return paths.some(p => {
    const t = p.replace(/[\\/]+$/, '') || '/';
    return workspace === t || workspace.startsWith(t === '/' ? '/' : `${t}/`);
  });
}

/**
 * Mark evidence from project files as inactive when the workspace is not
 * trusted: the CLI ignores those keys until the user trusts the workspace, so
 * the finding is downgraded (never dropped — trusting the repo activates it).
 */
export async function markUntrustedProject(ctx: ScanContext, evidence: Evidence[]): Promise<void> {
  if (!isProjectInstall(ctx) || evidence.length === 0) return;
  if (await projectTrusted(ctx)) return;
  const workspace = basename(dirname(ctx.installation.installDir));
  for (const e of evidence) {
    e.mitigated = true;
    e.detail = `${e.detail ?? ''} — inactive until workspace "${workspace}" is trusted`.replace(/^ — /, '');
  }
}

const LOOPBACK = /^https?:\/\/(?:localhost|127(?:\.\d+){3}|\[::1\])(?:[:/]|$)/i;

/** Plaintext http:// to a non-loopback host. */
export function isInsecureUrl(url: unknown): url is string {
  return typeof url === 'string' && /^http:\/\//i.test(url.trim()) && !LOOPBACK.test(url.trim());
}

/** A value that references the environment instead of holding a literal secret. */
export function isEnvReference(value: string): boolean {
  return /^\s*\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\s*$/.test(value) || /^\s*\$\{(?:env|file):[^}]+\}\s*$/.test(value);
}

export function mask(value: string): string {
  return `${value.slice(0, 4)}…(${value.length} chars)`;
}
