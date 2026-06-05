import type { Evidence } from '../../core/types.js';
import type { MCPServerEntry } from '../../mcp/types.js';
import { defineCheck } from '../../core/check-builder.js';

/**
 * MCP-030 — Untrusted Installer Source.
 *
 * Installer-spoofing (Hou et al. arXiv 2503.23278 §5.1.2; OWASP MCP04): an MCP
 * server launched via a package runner (npx/uvx/pipx/…) whose install target is
 * a git URL, a remote tarball, or a local path — not a registry package — runs
 * whatever code lives at that source, bypassing the registry's provenance and
 * any version/advisory checks. MCP-010 covers *unpinned registry* packages;
 * this covers *non-registry sources*.
 */

const PACKAGE_RUNNERS = new Set([
  'npx', 'npx.cmd', 'pnpm', 'pnpm.cmd', 'bunx', 'yarn',
  'uvx', 'uv', 'pipx', 'pip', 'pip3', 'deno',
]);

// Args that are sub-commands / flags, not the install spec.
const SKIP_ARGS = new Set(['-y', '--yes', 'run', 'tool', 'dlx', 'add', 'install', 'exec', '--']);

interface SourceClassification {
  label: string;
}

function classifyUntrustedSource(spec: string): SourceClassification | null {
  if (/^git(\+|:)/i.test(spec) || /\.git(#.*)?$/i.test(spec)) {
    return { label: 'git source' };
  }
  if (/^(github|gitlab|bitbucket|gist):/i.test(spec)) {
    return { label: 'VCS shorthand source' };
  }
  if (/^https?:\/\//i.test(spec)) {
    return { label: 'remote URL / tarball source' };
  }
  if (/^file:/i.test(spec) || /^(\/|\.\/|\.\.\/|~\/)/.test(spec)) {
    return { label: 'local path source' };
  }
  return null;
}

function firstInstallSpec(server: MCPServerEntry): string | undefined {
  for (const arg of server.args ?? []) {
    if (arg.startsWith('-')) continue;
    if (SKIP_ARGS.has(arg)) continue;
    return arg;
  }
  return undefined;
}

export const mcp030 = defineCheck({
  id: 'MCP-030',
  name: 'Untrusted Installer Source',
  category: 'mcp',
  severity: 'warning',
  description:
    'Detect MCP servers installed via a package runner from a non-registry source (git URL, remote tarball, or local path)',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        const cmd = server.command ? basename(server.command) : undefined;
        if (!cmd || !PACKAGE_RUNNERS.has(cmd)) continue;

        const spec = firstInstallSpec(server);
        if (!spec) continue;

        const classified = classifyUntrustedSource(spec);
        if (!classified) continue;

        evidence.push({
          file: config.filePath,
          snippet: `Server "${server.name}": ${cmd} … ${spec}`,
          detail: `MCP server "${server.name}" is installed from a ${classified.label} (${spec}) rather than a registry package — the code is fetched outside registry provenance and escapes version/advisory checks`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All package-runner MCP servers install from registry packages',
      failed: (n) => `Found ${n} MCP server(s) installed from an untrusted (non-registry) source`,
      fixDescription:
        'Install MCP servers from a pinned registry package (e.g. npx pkg@1.2.3); avoid git URLs, remote tarballs, and local paths as the install source',
    });
  },
});

function basename(p: string): string {
  const idx = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return idx >= 0 ? p.slice(idx + 1) : p;
}
