import { basename, join, normalize } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { agentsNamedIn } from './agent-names.js';

export const SUSPICIOUS_KEYWORDS = [
  'claw',          // catches openclaw, nanoclaw, picoclaw, ironclaw, zeroclaw, nemoclaw, clawdbot
  'nanobot',
  'moltbot',
  'hermes-agent',  // specific enough to avoid Facebook Hermes / unrelated tooling
  'lyrie',
  'atomic-agent',
  'openshell',
];

const INTERPRETERS = new Set(['node', 'nodejs', 'bun', 'deno', 'python', 'python3', 'uv', 'uvx', 'npx', 'bunx', 'tsx', 'ts-node']);
/** Subcommands / runner packages between an interpreter and its script:
 *  `bun run x.ts`, `deno run x.ts`, `uv run x.py`, `npx tsx x.ts`. */
const RUNNER_WORDS = new Set(['run', 'exec', 'dlx', 'tsx', 'ts-node']);

/** Standard per-user and system install roots for agent CLIs/packages. */
function installRoots(home: string): string[] {
  return [
    join(home, '.local'), join(home, '.npm-global'), join(home, '.nvm'), join(home, '.bun'),
    join(home, '.volta'), join(home, '.cargo'), join(home, '.pyenv'), join(home, '.hermes'),
    '/usr/local', '/usr/bin', '/usr/lib', '/opt/homebrew', '/opt',
  ];
}

/** First command + its script argument from a systemd ExecStart= line. */
export function systemdCommand(unit: string): string[] | undefined {
  const line = unit.split('\n').map(l => l.trim()).find(l => l.startsWith('ExecStart='));
  if (!line) return undefined;
  const cmd = line.slice('ExecStart='.length).replace(/^[-@:+!]+/, '').trim();
  const parts = cmd.match(/"[^"]*"|\S+/g)?.map(p => p.replace(/^"|"$/g, '')) ?? [];
  return parts.length > 0 ? parts : undefined;
}

/** Program / ProgramArguments from an XML launchd plist. */
export function launchdCommand(plist: string): string[] | undefined {
  const args = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(plist)?.[1];
  const parts = args ? [...args.matchAll(/<string>([^<]*)<\/string>/g)].map(m => m[1]) : [];
  const program = /<key>Program<\/key>\s*<string>([^<]*)<\/string>/.exec(plist)?.[1];
  if (program) parts.unshift(program);
  return parts.length > 0 ? parts : undefined;
}

/**
 * The service runs the agent itself when its executable (or, for an
 * interpreter like node, its script) is the installation's CLI or an
 * agent-named program/package under a standard install root. A keyword-named
 * binary in /tmp or ~/Downloads is still suspicious.
 */
/**
 * The command a service line runs: systemd's `%h` specifier expanded to the
 * home, and a leading `/usr/bin/env [-S] [-i] [VAR=value…]` dropped (it
 * starts the program named after it).
 */
export function effectiveCommand(parts: string[], home: string): string[] {
  let out = parts.map(p => p.replace(/%h/g, home));
  if (out.length > 0 && basename(out[0]) === 'env') {
    let i = 1;
    while (i < out.length && (out[i].startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(out[i]))) i++;
    // `env -S "node /x.js"`: the split string is one argument
    out = out.slice(i).flatMap(a => a.split(/\s+/)).filter(Boolean);
  }
  return out;
}

export function agentExecutable(rawParts: string[], keyword: string, ctx: ScanContext): string | undefined {
  const home = ctx.fs.homedir();
  const parts = effectiveCommand(rawParts, home);
  if (parts.length === 0) return undefined;
  const roots = [...installRoots(home), ctx.installation.installDir];
  const underRoot = (p: string) => roots.some(r => normalize(p).startsWith(`${normalize(r)}/`));
  const exe = parts[0];
  const script = INTERPRETERS.has(basename(exe))
    ? parts.slice(1).find(a => !a.startsWith('-') && !RUNNER_WORDS.has(a))
    : undefined;
  const target = script ?? exe;
  if (!target.startsWith('/')) return undefined;
  if (ctx.installation.cliBinary && normalize(target) === normalize(ctx.installation.cliBinary)) return target;
  // A script inside the scanned installation (Lyrie's `bun run
  // <checkout>/scripts/daemon.ts`) is the agent itself, whatever the
  // checkout directory is called.
  const installDir = normalize(ctx.installation.installDir);
  if (script && installDir !== '/' && normalize(script).startsWith(`${installDir}/`)) return target;
  const named = target.toLowerCase().split('/').some(seg => seg.includes(keyword));
  return named && underRoot(target) ? target : undefined;
}

async function classify(
  ctx: ScanContext, file: string, keyword: string, kind: 'LaunchAgent' | 'Systemd service',
  parse: (content: string) => string[] | undefined,
): Promise<Evidence> {
  let parts: string[] | undefined;
  try {
    parts = parse(await ctx.fs.readFile(file));
  } catch {}
  const own = parts ? agentExecutable(parts, keyword, ctx) : undefined;
  // the framework the unit names ("claw" alone would say little)
  const name = agentsNamedIn(basename(file))[0] ?? keyword;
  if (own) {
    return {
      file,
      detail: `${kind} for an installed agent ("${name}") — runs ${own}`,
      mitigated: true,
    };
  }
  const shown = parts ? effectiveCommand(parts, ctx.fs.homedir()) : undefined;
  const runs = shown && shown.length > 0 ? ` — runs ${shown.slice(0, 2).join(' ')}` : '';
  return { file, detail: `${kind} references "${name}"${runs}, not a recognized agent install location` };
}

/**
 * A service that runs another framework's own install is reported under that
 * framework's installation only — one unit must not appear under every agent
 * on the host. Suspicious units (not running a recognized install) and units
 * naming no known framework are reported under each agent.
 */
export function keep(evidence: Evidence[], entry: string, ctx: ScanContext, item: Evidence): void {
  const owners = agentsNamedIn(entry);
  if (item.mitigated && owners.length > 0 && !owners.includes(ctx.installation.agent)) return;
  evidence.push(item);
}

export const run001 = defineCheck({
  id: 'RUN-001',
  name: 'Unauthorized LaunchAgents',
  category: 'runtime',
  severity: 'warning',
  description: 'Check for unauthorized LaunchAgents (macOS) or systemd services (Linux) referencing agents',
  excludedAgents: CODING_AGENTS,
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    if (ctx.platform === 'darwin') {
      const home = ctx.fs.homedir();
      const launchDirs = [
        join(home, 'Library', 'LaunchAgents'),
        '/Library/LaunchAgents',
        '/Library/LaunchDaemons',
      ];

      for (const dir of launchDirs) {
        try {
          const entries = await ctx.fs.readdir(dir);
          for (const entry of entries) {
            const lower = entry.toLowerCase();
            for (const keyword of SUSPICIOUS_KEYWORDS) {
              if (lower.includes(keyword)) {
                keep(evidence, entry, ctx, await classify(ctx, join(dir, entry), keyword, 'LaunchAgent', launchdCommand));
                break;
              }
            }
          }
        } catch {}
      }
    }

    if (ctx.platform === 'linux') {
      const home = ctx.fs.homedir();
      const systemdDirs = [
        join(home, '.config', 'systemd', 'user'),
        '/etc/systemd/system',
      ];

      for (const dir of systemdDirs) {
        try {
          const entries = await ctx.fs.readdir(dir);
          for (const entry of entries) {
            const lower = entry.toLowerCase();
            for (const keyword of SUSPICIOUS_KEYWORDS) {
              if (lower.includes(keyword)) {
                keep(evidence, entry, ctx, await classify(ctx, join(dir, entry), keyword, 'Systemd service', systemdCommand));
                break;
              }
            }
          }
        } catch {}
      }
    }

    // Services that run an installed agent are reported as info (all mitigated)
    const suspicious = evidence.filter(e => !e.mitigated).length;
    return h.fromEvidence(evidence, {
      passed: 'No suspicious persistence mechanisms found',
      failed: (n) => suspicious === 0
        ? `Found ${n} agent service(s) — all run an installed agent`
        : `Found ${suspicious} suspicious persistence mechanism(s)`,
    });
  },
});
