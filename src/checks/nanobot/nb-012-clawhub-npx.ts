import { basename } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { asRecord, asStringArray, getPath, nanobotConfigs, pick } from './shared.js';

// Launchers that download and run a package at spawn time.
const RUNNERS: Record<string, { skip: Set<string>; subcommand?: string }> = {
  npx: { skip: new Set(['-y', '--yes', '-q', '--quiet', '--no-install', '--prefer-online', '--prefer-offline']) },
  bunx: { skip: new Set(['--bun', '-b']) },
  uvx: { skip: new Set(['-q', '--quiet', '--isolated', '--no-cache', '--refresh']) },
  pnpm: { skip: new Set(['-s', '--silent']), subcommand: 'dlx' },
  pipx: { skip: new Set(['-q', '--quiet']), subcommand: 'run' },
};
// Flags whose next argument is a value, not the package.
const VALUE_FLAGS = new Set(['-p', '--package', '--from', '--with', '--python', '--registry', '--index-url', '-c', '--call']);

/** The package spec a runner invocation fetches, or undefined when not a runner. */
function packageSpec(command: string, args: string[]): { runner: string; spec: string } | undefined {
  const runner = basename(command.trim());
  const rule = RUNNERS[runner];
  if (!rule) return undefined;
  let rest = args;
  if (rule.subcommand) {
    const idx = rest.indexOf(rule.subcommand);
    if (idx === -1) return undefined;
    rest = rest.slice(idx + 1);
  }
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (rule.skip.has(a)) continue;
    if (VALUE_FLAGS.has(a)) {
      // `npx -p <pkg> cmd` / `uvx --from <pkg> cmd`: the value is the package
      if (a === '-p' || a === '--package' || a === '--from') return { runner, spec: rest[i + 1] ?? '' };
      i++;
      continue;
    }
    if (a.startsWith('-')) continue;
    return { runner, spec: a };
  }
  return undefined;
}

/** True when the spec pins an exact version (npm `pkg@1.2.3`, PyPI `pkg==1.2.3`). */
function isPinned(spec: string): boolean {
  if (/==\d/.test(spec)) return true;
  const at = spec.lastIndexOf('@');
  if (at <= 0) return false; // no version, or only a scope prefix
  const version = spec.slice(at + 1);
  return /^\d+\.\d+\.\d+/.test(version);
}

export const nb012 = defineCheck({
  id: 'NB-012',
  name: 'Unpinned MCP Server Package',
  category: 'nanobot',
  severity: 'warning',
  description: 'Detect stdio MCP servers in tools.mcpServers launched through npx / bunx / uvx / pnpm dlx / pipx run without an exact version. The package is resolved from the registry on every start, so a compromised or typosquatted release runs with the agent\'s privileges and every env secret passed to it.',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of nanobotConfigs(ctx.configs)) {
      const servers = asRecord(getPath(config.data, 'tools.mcpServers'));
      if (!servers) continue;
      for (const [name, raw] of Object.entries(servers)) {
        const server = asRecord(raw);
        if (!server) continue;
        const command = pick(server, 'command');
        if (typeof command !== 'string' || !command.trim()) continue;
        const args = asStringArray(pick(server, 'args'));
        const found = packageSpec(command, args);
        if (!found || !found.spec || isPinned(found.spec)) continue;
        evidence.push({
          file: config.filePath,
          snippet: `tools.mcpServers.${name}: ${[command, ...args].join(' ').slice(0, 120)}`,
          detail: `MCP server "${name}" runs ${found.runner} ${found.spec} without a pinned version — fetched fresh from the registry on each start`,
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'No unpinned package-runner MCP servers in tools.mcpServers',
      failed: (n) => `${n} MCP server(s) run unpinned registry packages`,
      fixDescription: 'Pin an exact version in the args (e.g. "@modelcontextprotocol/server-filesystem@2025.8.21", "mcp-server-fetch==2025.4.7") or install the server locally and point command at it',
    });
  },
});
