import { basename, dirname, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { recordLoadError } from '../core/config-loader.js';
import { getUserHomeDirs } from './openclaw.js';

/**
 * NanoClaw v2 (github.com/nanocoai/nanoclaw) is not a package or a binary: it
 * runs as `node dist/index.js` from a git checkout, wherever the user cloned it.
 * Everything the host reads lives in two places:
 *
 *   <checkout>/              .env (secrets + host settings), data/ (central
 *                            v2.db, per-session DBs, ncl.sock admin socket),
 *                            groups/, container/skills/ (mounted into every
 *                            agent container), .claude/skills/ (operator skills),
 *                            src/channels/index.ts (installed channel barrel)
 *   ~/.config/nanoclaw/      mount-allowlist.json (kept outside the checkout so
 *                            agents cannot edit it), account.json,
 *                            registry-auth.json, device-key.json, host-id
 *
 * The version exists only in `<checkout>/package.json` (`bin` is `ncl`, an
 * admin client with no --version). There is no NANOCLAW_HOME / NANOCLAW_PORT /
 * ~/.nanoclaw.env / ~/.config/nanoclaw/config.json in v2.
 */

/** Checkout-name globs (per user home), kept in sync with the probe manifest. */
const CHECKOUT_NAME_RE = /nanoclaw/i;
/** Case-insensitive `*nanoclaw*` for the probe's doublestar globs. */
const CHECKOUT_NAME_GLOB = '*[nN][aA][nN][oO][cC][lL][aA][wW]*';
/**
 * Common parent directories people clone into (one level below home), in
 * lower case: any spelling on disk matches (~/GitHub, ~/Projects, ~/SRC).
 */
const CHECKOUT_PARENTS = [
  'src', 'code', 'projects', 'dev', 'developer', 'git', 'repos', 'workspace',
  'work', 'github',
];

/** Every-case glob for one name: `src` → `[sS][rR][cC]`. */
function anyCaseGlob(name: string): string {
  return [...name].map(c => (c.toLowerCase() === c.toUpperCase() ? c : `[${c.toLowerCase()}${c.toUpperCase()}]`)).join('');
}

/** Service definitions written by `setup --step service` (per-checkout slug). */
const SYSTEMD_UNIT_RE = /^nanoclaw-v2-[a-z0-9_-]+\.service$/;
const LAUNCHD_PLIST_RE = /^com\.nanoclaw-v2-[a-z0-9_-]+\.plist$/;

/** Host-side identity/credential files under ~/.config/nanoclaw (never content). */
export const NANOCLAW_HOST_SECRET_FILES = ['account.json', 'registry-auth.json', 'device-key.json'];
const CONFIG_DIR_MARKERS = ['mount-allowlist.json', ...NANOCLAW_HOST_SECRET_FILES, 'host-id'];

export function nanoclawConfigDir(home: string): string {
  return join(home, '.config', 'nanoclaw');
}

/** True when `installDir` is a checkout (not the ~/.config/nanoclaw fallback). */
export function isNanoclawCheckout(installDir: string): boolean {
  return !(basename(installDir) === 'nanoclaw' && basename(dirname(installDir)) === '.config');
}

async function readCheckoutVersion(dir: string, fs: FSProvider): Promise<string | null | undefined> {
  // null → package.json readable but not NanoClaw; undefined → unreadable
  try {
    const pkg = JSON.parse(await fs.readFile(join(dir, 'package.json'))) as Record<string, unknown>;
    if (pkg?.name !== 'nanoclaw') return null;
    return typeof pkg.version === 'string' ? pkg.version : undefined;
  } catch {
    return undefined;
  }
}

async function safeReaddir(fs: FSProvider, dir: string): Promise<string[]> {
  try {
    return await fs.readdir(dir);
  } catch {
    return [];
  }
}

function expandHomePath(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return join(home, p.slice(2));
  return p;
}

/** Checkout directories named by installed service definitions (authoritative). */
async function serviceCheckouts(home: string, fs: FSProvider): Promise<string[]> {
  const out: string[] = [];
  const unitDirs = [join(home, '.config', 'systemd', 'user'), '/etc/systemd/system'];
  for (const dir of unitDirs) {
    for (const name of await safeReaddir(fs, dir)) {
      if (!SYSTEMD_UNIT_RE.test(name)) continue;
      try {
        const unit = await fs.readFile(join(dir, name));
        const wd = /^\s*WorkingDirectory\s*=\s*(.+?)\s*$/m.exec(unit)?.[1];
        const exec = /^\s*ExecStart\s*=\s*\S+\s+(\S+)\/dist\/index\.js\b/m.exec(unit)?.[1];
        const dirPath = wd ?? exec;
        if (dirPath) out.push(expandHomePath(dirPath, home));
      } catch {}
    }
  }
  const agentsDir = join(home, 'Library', 'LaunchAgents');
  for (const name of await safeReaddir(fs, agentsDir)) {
    if (!LAUNCHD_PLIST_RE.test(name)) continue;
    try {
      const plist = await fs.readFile(join(agentsDir, name));
      const wd = /<key>\s*WorkingDirectory\s*<\/key>\s*<string>([^<]+)<\/string>/.exec(plist)?.[1];
      if (wd) out.push(wd.trim());
    } catch {}
  }
  return out;
}

/** Checkout candidates found by name: ~/<*nanoclaw*> and ~/<parent>/<*nanoclaw*>. */
async function namedCheckoutCandidates(home: string, fs: FSProvider): Promise<string[]> {
  const out: string[] = [];
  const homeNames = await safeReaddir(fs, home);
  for (const name of homeNames) {
    if (CHECKOUT_NAME_RE.test(name)) out.push(join(home, name));
  }
  // Parents matched case-insensitively against the home listing, keeping the
  // on-disk spelling: on a case-insensitive file system ~/projects opens
  // ~/Projects too, and the checkout path would keep the wrong case (a remote
  // snapshot, keyed by the real case, can't match it). On a case-sensitive
  // one ~/github and ~/GitHub are both found. An unlistable home falls back
  // to the lower-case and capitalised spellings.
  const parents = homeNames.length > 0
    ? homeNames.filter(n => CHECKOUT_PARENTS.includes(n.toLowerCase()))
    : CHECKOUT_PARENTS.flatMap(p => [p, p[0].toUpperCase() + p.slice(1)]);
  for (const parent of parents) {
    for (const name of await safeReaddir(fs, join(home, parent))) {
      if (CHECKOUT_NAME_RE.test(name)) out.push(join(home, parent, name));
    }
  }
  return out;
}

/** `~/.local/bin/ncl` is a symlink to `<checkout>/bin/ncl` (setup service step). */
async function nclCheckout(home: string, fs: FSProvider): Promise<string | undefined> {
  const link = join(home, '.local', 'bin', 'ncl');
  try {
    const target = await fs.realpath(link);
    if (target !== link && target.endsWith('/bin/ncl')) return dirname(dirname(target));
  } catch {}
  return undefined;
}

export interface NanoclawCheckout {
  dir: string;
  version?: string;
}

/**
 * Locate NanoClaw checkouts for one user. Service units / launchd plists are
 * authoritative (accepted even when the checkout isn't readable, e.g. a remote
 * snapshot that didn't collect it — but not a stale unit on a live host);
 * name-based candidates and the `ncl` symlink must carry a package.json named
 * "nanoclaw".
 */
export async function findNanoclawCheckouts(home: string, fs: FSProvider): Promise<NanoclawCheckout[]> {
  const found: NanoclawCheckout[] = [];
  const seen = new Set<string>();
  const add = async (dir: string, authoritative: boolean, source?: string): Promise<void> => {
    let key = dir;
    try { key = await fs.realpath(dir); } catch {}
    // macOS/Windows file systems are case-insensitive by default: ~/projects
    // and ~/Projects (both common clone parents) are one directory. A local
    // realpath returns the on-disk case; a snapshot can't, so fold case.
    if (fs.platform === 'darwin' || fs.platform === 'win32') key = key.toLowerCase();
    if (seen.has(key)) return;
    const version = await readCheckoutVersion(dir, fs);
    if (version === null) return;
    // Every NanoClaw package.json carries a version; without one only a
    // service definition vouches for the directory.
    if (version === undefined && !(authoritative && (fs.kind === 'snapshot' || await fs.access(dir)))) return;
    // The probe collects checkouts only where the name globs reach; one a
    // service definition or the ncl link points elsewhere is reported, but
    // its files are not in the snapshot — say so instead of judging it blind
    if (version === undefined && fs.kind === 'snapshot' && source && !(await fs.access(dir))) {
      recordLoadError({
        filePath: dir,
        stage: 'read',
        message: `NanoClaw checkout named by ${source}, outside the paths the remote probe collects (~/*nanoclaw*, ~/<src|code|projects|…>/*nanoclaw*) — its .env, package.json and skills were not checked; scan the host locally`,
      });
    }
    seen.add(key);
    found.push({ dir, version: version ?? undefined });
  };

  for (const dir of await serviceCheckouts(home, fs)) await add(dir, true, 'a service definition');
  const ncl = await nclCheckout(home, fs);
  // On a snapshot the link vouches for a checkout the probe didn't collect —
  // only one named like NanoClaw: the snapshot can't show that the target
  // exists, and other tools ship a bin/ncl too (NCAR NCL)
  if (ncl) await add(ncl, fs.kind === 'snapshot' && /nanoclaw/i.test(basename(ncl)), '~/.local/bin/ncl');
  for (const dir of await namedCheckoutCandidates(home, fs)) await add(dir, false);
  return found;
}

async function tryLoad(path: string, fs: FSProvider, into: ParsedConfig[]): Promise<void> {
  const loaded = await loadConfigIfPresent(path, fs);
  if (loaded) into.push(loaded);
}

export const nanoclawAdapter: AgentAdapter = {
  agent: 'nanoclaw',
  displayName: 'NanoClaw',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const configDir = nanoclawConfigDir(home);
      const hostConfigs: ParsedConfig[] = [];
      await tryLoad(join(configDir, 'mount-allowlist.json'), fs, hostConfigs);

      const checkouts = await findNanoclawCheckouts(home, fs);
      for (const { dir, version } of checkouts) {
        const configFiles: ParsedConfig[] = [];
        await tryLoad(join(dir, '.env'), fs, configFiles);
        // The allowlist governs every checkout this user runs.
        configFiles.push(...hostConfigs);
        installations.push({
          agent: 'nanoclaw',
          version,
          installDir: dir,
          configFiles,
          skillsDir: this.getSkillsDir(dir),
          models: await this.getModels?.(configFiles, fs),
          user: options?.allUsers ? user : undefined,
        });
      }
      if (checkouts.length > 0) continue;

      // No checkout found (cloned somewhere unusual, or only `setup --step
      // mounts` has run): report the host config dir so the allowlist and
      // identity files are still assessed.
      let hasMarker = false;
      for (const name of CONFIG_DIR_MARKERS) {
        if (await fs.access(join(configDir, name))) { hasMarker = true; break; }
      }
      if (!hasMarker) continue;
      installations.push({
        agent: 'nanoclaw',
        installDir: configDir,
        configFiles: hostConfigs,
        skillsDir: undefined,
        models: [],
        user: options?.allUsers ? user : undefined,
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    return [
      join(home, 'nanoclaw', '.env'),
      join(nanoclawConfigDir(home), 'mount-allowlist.json'),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    // Skills mounted into every agent container. `.claude/skills` holds the
    // operator's Claude Code skills (upstream setup/add-* flows) — NC-005
    // checks its permissions, but it is not agent-executed code.
    return isNanoclawCheckout(installDir) ? join(installDir, 'container', 'skills') : undefined;
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    // NanoClaw has no gateway/API server. Its only listener is the webhook
    // server (0.0.0.0:WEBHOOK_PORT, hardcoded bind), started only when a
    // webhook-mode channel is installed — assessed by NC-004, which knows
    // whether one is. Admin access is the data/ncl.sock unix socket.
    return undefined;
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    // Agents run inside containers via a provider (claude by default);
    // NANOCLAW_DEFAULT_MODEL is the instance-wide default model, applied at
    // spawn when a group has none. Per-group models live in data/v2.db.
    const env = configs.find(c => c.format === 'env' && c.filePath.endsWith('.env'))?.data;
    const model = typeof env?.NANOCLAW_DEFAULT_MODEL === 'string' ? env.NANOCLAW_DEFAULT_MODEL.trim() : '';
    if (!model) return [];
    const provider = typeof env?.DEFAULT_AGENT_PROVIDER === 'string' && env.DEFAULT_AGENT_PROVIDER.trim()
      ? env.DEFAULT_AGENT_PROVIDER.trim().toLowerCase()
      : 'claude';
    return [{ id: model, provider }];
  },

  getMemoryFiles(installDir: string): string[] {
    if (!isNanoclawCheckout(installDir)) return [];
    return [
      join(installDir, 'data', 'v2.db'),
      join(installDir, 'data', 'v2-sessions'),
      join(installDir, 'groups'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return isNanoclawCheckout(installDir) ? [join(installDir, '.env')] : [];
  },

  getProbeManifest(): ProbeManifest {
    // Same candidates detect() walks: ~/<*nanoclaw*> and ~/<parent>/<*nanoclaw*>.
    // Each parent is an every-case class (`[pP][rR]…`): it matches any
    // spelling detect() accepts, and the probe matches it against the
    // directory listing — a literal is stat'ed, and on a case-insensitive
    // file system `projects` would then also collect ~/Projects under the
    // wrong case.
    const checkoutGlobs = [
      `~/${CHECKOUT_NAME_GLOB}`,
      `~/{${CHECKOUT_PARENTS.map(anyCaseGlob).join(',')}}/${CHECKOUT_NAME_GLOB}`,
    ];
    return {
      filePaths: [
        '~/.config/nanoclaw/mount-allowlist.json',
      ],
      globPatterns: [
        ...checkoutGlobs.flatMap(c => [
          `${c}/package.json`,
          `${c}/.env`,
          `${c}/src/channels/index.ts`,
          `${c}/container/skills/**`,
          // each agent group's MCP servers, written when its container starts
          `${c}/groups/*/container.json`,
        ]),
        '~/.config/systemd/user/nanoclaw-v2-*.service',
        '~/Library/LaunchAgents/com.nanoclaw-v2-*.plist',
      ],
      // Central/session databases, the admin socket, operator skills and the
      // host identity/credential files: permissions only, content never shipped.
      metadataGlobPatterns: [
        ...checkoutGlobs.flatMap(c => [
          `${c}/data/*`,
          `${c}/dist/index.js`,
          `${c}/.claude/skills/*/SKILL.md`,
          // the dir itself, so NC-005 sees its mode while it is still empty
          `${c}/.claude/skills`,
        ]),
        '~/.config/nanoclaw/*',
        // By name too: a glob can't list a traversable-but-unreadable dir
        ...NANOCLAW_HOST_SECRET_FILES.map(f => `~/.config/nanoclaw/${f}`),
        '~/.local/bin/ncl',
      ],
      commands: [],
      directoryListings: [
        '~/.config/nanoclaw',
      ],
      envPrefixes: ['NANOCLAW_'],
      systemPaths: [],
      systemDirListings: [],
    };
  },
};
