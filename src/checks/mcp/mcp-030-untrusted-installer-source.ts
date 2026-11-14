import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { denoRunTarget, inferPackageName, runnerName, uvRunScript } from '../../mcp/source-resolver.js';

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
  'npx', 'pnpx', 'pnpm', 'bunx', 'bun', 'yarn',
  'uvx', 'uv', 'pipx', 'pip', 'pip3', 'deno',
]);

/** Options whose value a runner installs (`uv --with git+…`, `pipx run --spec ./x`). */
const INSTALL_VALUE_FLAGS = new Set(['--from', '--with', '--with-editable', '--spec']);
/** pnpm/yarn/bun subcommands that fetch and run a package. */
const FETCH_SUBCOMMANDS = new Set(['dlx', 'x']);
/** pnpm/yarn/bun options that take a value (a directory, a filter), not a package. */
const PM_VALUE_FLAGS = new Set(['--dir', '-C', '--cwd', '--prefix', '--filter', '-F', '--workspace', '-w']);

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

function isLocalSpec(spec: string): boolean {
  return classifyUntrustedSource(spec)?.label === 'local path source';
}

/**
 * What a runner installs and runs: the package spec (`npx -y x@1`,
 * `uvx --from x y`), the values of `--from`/`--with`/`--spec`, the package of
 * a `pnpm dlx` / `yarn dlx`, the module of `deno run`. A runner given a local
 * directory to work in (`pnpm --dir d start`, `npx --prefix d pkg`) or running
 * a local script (`uv run server.py`, `deno run ./server.ts`) installs nothing
 * from that directory or script.
 */
export function installSpecs(cmd: string, args: string[]): string[] {
  const flagged: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const inline = /^(--[\w-]+)=(.+)$/.exec(args[i]);
    if (inline && INSTALL_VALUE_FLAGS.has(inline[1])) flagged.push(inline[2]);
    else if (INSTALL_VALUE_FLAGS.has(args[i]) && args[i + 1] !== undefined) flagged.push(args[++i]);
  }
  switch (cmd) {
    case 'uv':
      // `uv [--directory d] run server.py` runs a local script; only what
      // `--with` adds from elsewhere is installed
      if (uvRunScript(args)) return flagged.filter((s) => !isLocalSpec(s));
    // falls through
    case 'npx':
    case 'pnpx':
    case 'bunx':
    case 'uvx': {
      const spec = inferPackageName({ name: '', command: cmd, args, transport: 'stdio' });
      return spec ? [...flagged, spec] : flagged;
    }
    case 'deno': {
      const target = denoRunTarget(args);
      // a local module is the server's own code, like `node ./server.js`
      return target && !isLocalSpec(target) ? [...flagged, target] : flagged;
    }
    case 'pnpm':
    case 'yarn':
    case 'bun': {
      for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (PM_VALUE_FLAGS.has(arg)) { i++; continue; }
        if (arg.startsWith('-')) continue;
        // `pnpm --dir d start`: a script of a local package, nothing fetched
        if (!FETCH_SUBCOMMANDS.has(arg)) return flagged;
        for (let j = i + 1; j < args.length; j++) {
          if (args[j] === '-p' || args[j] === '--package') {
            if (args[j + 1] !== undefined) flagged.push(args[++j]);
            continue;
          }
          if (args[j].startsWith('-')) continue;
          return [...flagged, args[j]];
        }
        return flagged;
      }
      return flagged;
    }
    default: {
      // pipx run <spec>, pip install <spec>
      const sub = new Set(['run', 'install', 'tool', 'exec', '--']);
      for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (INSTALL_VALUE_FLAGS.has(arg)) { i++; continue; }
        if (arg.startsWith('-') || sub.has(arg)) continue;
        return [...flagged, arg];
      }
      return flagged;
    }
  }
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
        const cmd = server.command ? runnerName(server.command).toLowerCase() : undefined;
        if (!cmd || !PACKAGE_RUNNERS.has(cmd)) continue;

        let spec: string | undefined;
        let classified: SourceClassification | null = null;
        for (const candidate of installSpecs(cmd, server.args ?? [])) {
          classified = classifyUntrustedSource(candidate);
          if (classified) {
            spec = candidate;
            break;
          }
        }
        if (!classified || !spec) continue;

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
