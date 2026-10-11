import { basename } from 'node:path';
import type { MCPServerEntry } from './types.js';

/**
 * The remote endpoint an MCP server entry connects to, whether the config
 * names it directly (`url`) or launches a local stdio bridge that dials it
 * (`npx -y mcp-remote https://…`, `npx -y supergateway --sse https://…`).
 * Claude Desktop only speaks stdio, so the bridge form is how most desktop
 * configs reach remote servers; transport/auth checks that only read `url`
 * never saw them.
 */
export interface RemoteEndpoint {
  url: string;
  transport: MCPServerEntry['transport'];
  /** The stdio bridge carrying the connection; absent for a direct `url` entry. */
  via?: 'mcp-remote' | 'supergateway';
  /**
   * mcp-remote refuses plaintext http:// to a non-localhost host unless
   * `--allow-http` is passed (verified against mcp-remote 0.14.3).
   */
  allowHttp?: boolean;
  /**
   * The bridge runs an OAuth client and authenticates on demand when the server
   * asks (mcp-remote does; supergateway only sends static headers), so a config
   * without static credentials is not evidence of an unauthenticated session.
   */
  negotiatesOAuth?: boolean;
}

const PACKAGE_RUNNERS = new Set(['npx', 'npx.cmd', 'bunx', 'bunx.cmd']);
const HTTP_URL = /^https?:\/\//i;

/** Strip a version/tag suffix: `mcp-remote@0.1.15` → `mcp-remote`. */
function packageBase(spec: string): string {
  const at = spec.lastIndexOf('@');
  return at > 0 ? spec.slice(0, at) : spec;
}

/**
 * The bridge name and its own arguments, or undefined when the entry doesn't
 * launch a known bridge. Accepts `npx [flags] <bridge>[@ver] …`, `bunx …`, and
 * a globally installed `mcp-remote` / `supergateway` binary.
 */
function bridgeInvocation(server: MCPServerEntry): { bridge: string; args: string[] } | undefined {
  if (!server.command) return undefined;
  const cmd = basename(server.command).replace(/\.cmd$/i, '');
  const args = server.args ?? [];

  if (cmd === 'mcp-remote' || cmd === 'supergateway') return { bridge: cmd, args };

  if (!PACKAGE_RUNNERS.has(basename(server.command))) return undefined;
  const pkgIndex = args.findIndex((a) => !a.startsWith('-'));
  if (pkgIndex === -1) return undefined;
  const bridge = packageBase(args[pkgIndex]);
  if (bridge !== 'mcp-remote' && bridge !== 'supergateway') return undefined;
  return { bridge, args: args.slice(pkgIndex + 1) };
}

/** Value of `--flag value` or `--flag=value`. */
function flagValue(args: string[], flag: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === flag && i + 1 < args.length) return args[i + 1];
    if (args[i].startsWith(`${flag}=`)) return args[i].slice(flag.length + 1);
  }
  return undefined;
}

export function remoteEndpoint(server: MCPServerEntry): RemoteEndpoint | undefined {
  if (server.url) return { url: server.url, transport: server.transport };

  const invocation = bridgeInvocation(server);
  if (!invocation) return undefined;
  const { bridge, args } = invocation;

  if (bridge === 'mcp-remote') {
    // `mcp-remote <url> [callback-port] [flags]` — the URL is the first positional.
    const url = args.find((a) => HTTP_URL.test(a));
    if (!url) return undefined;
    const strategy = flagValue(args, '--transport');
    return {
      url,
      transport: strategy === 'sse-only' || strategy === 'sse-first' ? 'sse' : 'streamable-http',
      via: 'mcp-remote',
      allowHttp: args.includes('--allow-http'),
      negotiatesOAuth: true,
    };
  }

  // supergateway: `--sse <url>` or `--streamableHttp <url>` dial a remote server
  // (`--stdio <cmd>` serves a local one and is not a remote endpoint).
  const sse = flagValue(args, '--sse');
  if (sse && HTTP_URL.test(sse)) return { url: sse, transport: 'sse', via: 'supergateway' };
  const http = flagValue(args, '--streamableHttp');
  if (http && HTTP_URL.test(http)) return { url: http, transport: 'streamable-http', via: 'supergateway' };
  return undefined;
}
