import { basename, dirname, join, normalize } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { agentsNamedIn } from './agent-names.js';
import { cliCopyPaths } from '../../adapters/cli-installs.js';

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

/** Directories no installation owns as a whole: a job under them is not the agent's by location. */
function sharedDirs(home: string): Set<string> {
  return new Set([
    '/', home, join(home, '.local'), join(home, '.local', 'bin'), join(home, '.config'),
    '/usr', '/usr/bin', '/usr/local', '/usr/local/bin', '/usr/lib', '/bin', '/sbin',
    '/opt', '/opt/homebrew', '/opt/homebrew/bin', '/tmp', '/var', '/etc',
  ].map(p => normalize(p)));
}

/**
 * The package directory a CLI's resolved path lives in: `…/node_modules/<pkg>`
 * (or `@scope/pkg`) for an npm shim, the venv for a Python entry point.
 */
export function cliPackageRoot(real: string): string | undefined {
  const parts = normalize(real).split('/');
  const nm = parts.lastIndexOf('node_modules');
  if (nm >= 0 && nm + 1 < parts.length - 1) {
    const end = parts[nm + 1].startsWith('@') ? nm + 3 : nm + 2;
    if (end <= parts.length - 1) return parts.slice(0, end).join('/');
  }
  const bin = parts.lastIndexOf('bin');
  if (bin > 0 && /^\.?venv$/.test(parts[bin - 1])) return parts.slice(0, bin).join('/');
  return undefined;
}

/**
 * The installation's own executables (its CLI, every other copy of it, and
 * what each resolves to) and directories (its install dir, the CLI's
 * package). Every copy counts, whatever its version — `otherInstalls` keeps
 * only copies at another version, and the package an installer's service
 * runs is often a same-version nvm copy behind a ~/.local/bin wrapper. A
 * copy's package is taken both through its own link (as the job may spell
 * the path) and fully resolved. Only the installation's own paths are
 * resolved — a job's command is judged literally, so a local scan and a
 * probe snapshot agree.
 */
async function computeInstallationPaths(ctx: ScanContext): Promise<{ binaries: Set<string>; dirs: string[] }> {
  const home = ctx.fs.homedir();
  const shared = sharedDirs(home);
  const binaries = new Set<string>();
  const dirs: string[] = [];
  const addDir = (d: string | undefined) => {
    if (d && d.startsWith('/') && !shared.has(normalize(d))) dirs.push(normalize(d));
  };
  addDir(ctx.installation.installDir);
  const known = [ctx.installation.cliBinary, ...(ctx.installation.otherInstalls ?? []).map(o => o.path)]
    .filter((p): p is string => !!p && p.startsWith('/') && !p.endsWith('.app'));
  const names = [...new Set(known.map(p => basename(p)))];
  const copies = names.length > 0 ? await cliCopyPaths(home, ctx.fs, names) : [];
  for (const cli of new Set([...known, ...copies])) {
    binaries.add(normalize(cli));
    try {
      const link = await ctx.fs.readlink(cli);
      addDir(cliPackageRoot(link.startsWith('/') ? link : join(dirname(cli), link)));
    } catch {}
    let real: string | undefined;
    try { real = await ctx.fs.realpath(cli); } catch {}
    if (real) {
      binaries.add(normalize(real));
      addDir(cliPackageRoot(real));
    }
  }
  return { binaries, dirs: [...new Set(dirs)] };
}

/** One computation per check run: every unit and cron line is judged against the same paths. */
const pathsByContext = new WeakMap<ScanContext, Promise<{ binaries: Set<string>; dirs: string[] }>>();

function installationPaths(ctx: ScanContext): Promise<{ binaries: Set<string>; dirs: string[] }> {
  let p = pathsByContext.get(ctx);
  if (!p) { p = computeInstallationPaths(ctx); pathsByContext.set(ctx, p); }
  return p;
}

/**
 * The executable (or, for an interpreter like node, its script) when the
 * command runs the scanned installation itself: its CLI binary (or another
 * copy of it), or a program inside its install dir or CLI package. A
 * keyword-named program anywhere else — even under /usr/local or /opt — is
 * not the agent's: names are not evidence.
 */
export async function agentExecutable(rawParts: string[], ctx: ScanContext): Promise<string | undefined> {
  const home = ctx.fs.homedir();
  const parts = effectiveCommand(rawParts, home);
  if (parts.length === 0) return undefined;
  const exe = parts[0];
  const script = INTERPRETERS.has(basename(exe))
    ? parts.slice(1).find(a => !a.startsWith('-') && !RUNNER_WORDS.has(a))
    : undefined;
  // an interpreter running a script file is judged by the script; one
  // running a module (`python -m pkg`) by the interpreter itself
  const target = script?.startsWith('/') ? script : exe;
  if (!target.startsWith('/')) return undefined;
  const { binaries, dirs } = await installationPaths(ctx);
  const ownPath = (p: string) => binaries.has(p) || dirs.some(d => p.startsWith(`${d}/`));
  const t = normalize(target);
  if (ownPath(t)) return target;
  // Another link to the CLI (`~/.local/bin/openclaw` → the npm package): only
  // a program named like the CLI is resolved — those locations are CLI
  // candidates the probe collects, so a snapshot resolves them too
  const cliNames = new Set([...binaries].map(b => basename(b)));
  if (cliNames.has(basename(t))) {
    try {
      if (ownPath(normalize(await ctx.fs.realpath(t)))) return target;
    } catch {}
  }
  return undefined;
}

/**
 * Names systemd reads from a unit directory: a unit file (systemd.unit(5):
 * the name ends in its type suffix), a drop-in directory (`<unit>.d`) or a
 * dependency directory (`.wants`/`.requires`/`.upholds`). Anything else there
 * — an installer's `openclaw-gateway.service.bak`, a
 * `….reconcile-<id>.receipt.bak` JSON receipt, an editor's `~` copy — is
 * never loaded, so it starts nothing.
 */
const SYSTEMD_LOADED = /\.(?:service|socket|timer|path|mount|automount|swap|target|slice|scope|device)(?:\.(?:d|wants|requires|upholds))?$/;

export function systemdLoads(name: string): boolean {
  return SYSTEMD_LOADED.test(name.toLowerCase());
}

async function classify(
  ctx: ScanContext, file: string, keyword: string, kind: 'LaunchAgent' | 'Systemd service',
  parse: (content: string) => string[] | undefined,
): Promise<Evidence> {
  let parts: string[] | undefined;
  try {
    parts = parse(await ctx.fs.readFile(file));
  } catch {}
  const own = parts ? await agentExecutable(parts, ctx) : undefined;
  // the framework the unit names ("claw" alone would say little)
  const name = agentsNamedIn(basename(file))[0] ?? keyword;
  if (own) {
    return {
      file,
      detail: `${kind} for an installed agent ("${ctx.installation.agent}") — runs ${own}`,
      mitigated: true,
    };
  }
  const shown = parts ? effectiveCommand(parts, ctx.fs.homedir()) : undefined;
  const runs = shown && shown.length > 0 ? ` — runs ${shown.slice(0, 2).join(' ')}` : '';
  return { file, detail: `${kind} references "${name}"${runs}, not the installed agent's own program` };
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
                evidence.push(await classify(ctx, join(dir, entry), keyword, 'LaunchAgent', launchdCommand));
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
            if (!systemdLoads(lower)) continue;
            for (const keyword of SUSPICIOUS_KEYWORDS) {
              if (lower.includes(keyword)) {
                evidence.push(await classify(ctx, join(dir, entry), keyword, 'Systemd service', systemdCommand));
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
