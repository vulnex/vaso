import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, CliInstall, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfigIfPresent } from './load-if-present.js';

/**
 * Lyrie (OTT-Cybersecurity-LLC/lyrie-ai, 3.x) is a Bun turborepo that runs
 * from its git checkout (`bun start` → scripts/start-all.ts); there is no
 * installed `bin`. Two locations matter:
 *
 *  - The checkout: `<checkout>/.env` is the config file (docs say
 *    `cp .env.example .env` at the repo root) — plus the layered
 *    `.env.local` / `.env.<NODE_ENV>[.local]` Bun also auto-loads from the cwd,
 *    `<checkout>/package.json` (name `lyrie-agent`) carries the version, and
 *    the Rust Shield binary is looked up only at
 *    `<checkout>/packages/shield/target/{release,debug}/lyrie-shield`.
 *  - The state dir `~/.lyrie/` (fixed — no relocation env var): pairing.json,
 *    edits.json, mcp.json, memory/lyrie-memory.db, skills/, migrations/, and
 *    config.json written by the separate Python CLI (`lyrie` = PyPI
 *    lyrie-omega) holding plaintext API keys.
 *
 * The Python `lyrie` CLI is a different product with its own version line
 * (lyrie-omega 1.x) — it is never reported as the agent version.
 */

export const LYRIE_PACKAGE_NAME = 'lyrie-agent';

/** Checkout locations probed relative to $HOME. `~/.lyrie` is where the
 *  upstream one-line installer (scripts/install.sh) clones the repo. */
const HOME_CHECKOUT_CANDIDATES = [
  '.lyrie',
  'lyrie-ai',
  'lyrie',
  'lyrie-agent',
  'src/lyrie-ai',
  'code/lyrie-ai',
  'projects/lyrie-ai',
  'git/lyrie-ai',
];

const SYSTEM_CHECKOUT_CANDIDATES = [
  '/opt/lyrie-ai',
  '/opt/lyrie',
];

/** Service units written by `bun run scripts/service.ts install` (label
 *  `ai.lyrie.daemon`; systemd unit name = label with dots → dashes). Their
 *  ExecStart/ProgramArguments reference `<checkout>/scripts/daemon.ts`. */
const SERVICE_FILES = [
  '.config/systemd/user/ai-lyrie-daemon.service',
  '.config/systemd/user/lyrie.service',
  'Library/LaunchAgents/ai.lyrie.daemon.plist',
];

const SHIELD_BINARY_RELATIVE = [
  'packages/shield/target/release/lyrie-shield',
  'packages/shield/target/debug/lyrie-shield',
];

/** `~/.lyrie` on the scanned host (snapshot home on --host scans). */
export function lyrieStateDir(fs: FSProvider): string {
  return join(fs.homedir(), '.lyrie');
}

/** Paths where Lyrie's AgenticThreatBridge looks for the Rust Shield binary. */
export function lyrieShieldBinaryPaths(checkout: string): string[] {
  return SHIELD_BINARY_RELATIVE.map(rel => join(checkout, rel));
}

async function readCheckoutPackage(dir: string, fs: FSProvider): Promise<{ version?: string } | undefined> {
  try {
    const pkg = JSON.parse(await fs.readFile(join(dir, 'package.json'))) as Record<string, unknown>;
    if (!pkg || typeof pkg !== 'object' || pkg.name !== LYRIE_PACKAGE_NAME) return undefined;
    return { version: typeof pkg.version === 'string' ? pkg.version : undefined };
  } catch {
    return undefined;
  }
}

/** True when `dir` is a Lyrie agent checkout (package.json name `lyrie-agent`). */
export async function isLyrieCheckout(dir: string, fs: FSProvider): Promise<boolean> {
  return (await readCheckoutPackage(dir, fs)) !== undefined;
}

/** Checkout roots referenced by installed Lyrie service units. */
async function checkoutsFromServices(home: string, fs: FSProvider): Promise<string[]> {
  const out: string[] = [];
  for (const rel of SERVICE_FILES) {
    let raw: string;
    try {
      raw = await fs.readFile(join(home, rel));
    } catch {
      continue;
    }
    for (const m of raw.matchAll(/(\/[^\s"'<>]+?)\/scripts\/(?:daemon|start-all)\.ts/g)) {
      out.push(m[1]);
    }
    for (const m of raw.matchAll(/^\s*WorkingDirectory\s*=\s*(\S+)\s*$/gm)) {
      out.push(m[1].replace(/^~(?=\/)/, home));
    }
  }
  return out;
}

export interface LyrieCheckout {
  dir: string;
  version?: string;
  /** Referenced by an installed service unit. */
  service: boolean;
}

/** Every Lyrie checkout on the host, service-referenced ones first. */
export async function findLyrieCheckouts(fs: FSProvider): Promise<LyrieCheckout[]> {
  const home = fs.homedir();
  const serviceDirs = await checkoutsFromServices(home, fs);
  const candidates = [
    ...serviceDirs,
    ...HOME_CHECKOUT_CANDIDATES.map(rel => join(home, rel)),
    ...SYSTEM_CHECKOUT_CANDIDATES,
  ];

  const seen = new Set<string>();
  const out: LyrieCheckout[] = [];
  for (const dir of candidates) {
    const pkg = await readCheckoutPackage(dir, fs);
    if (!pkg) continue;
    let key = dir;
    try { key = await fs.realpath(dir); } catch {}
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ dir, version: pkg.version, service: serviceDirs.includes(dir) });
  }
  return out;
}

async function tryLoad(path: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  return loadConfigIfPresent(path, fs);
}

/**
 * Bun auto-loads, in increasing precedence: `.env`, `.env.<NODE_ENV>`,
 * `.env.local` (skipped when NODE_ENV=test), `.env.<NODE_ENV>.local`
 * (bun.sh/docs/runtime/env); NODE_ENV defaults to development. The daemon's
 * launch environment isn't observable, so the mode is the NODE_ENV the base
 * `.env` sets, else Bun's default.
 */
export function lyrieEnvLayers(nodeEnv: string | undefined): string[] {
  const mode = nodeEnv?.trim().toLowerCase() || 'development';
  return [
    `.env.${mode}`,
    ...(mode === 'test' ? [] : ['.env.local']),
    `.env.${mode}.local`,
  ];
}

/** Every layered file name a probe should collect next to a checkout `.env`. */
const ENV_LAYER_FILES = [
  '.env.development', '.env.production', '.env.local', '.env.development.local', '.env.production.local',
];

const STATE_MARKERS = [
  'memory',
  'pairing.json',
  'edits.json',
  'mcp.json',
  'migrations',
  'skills',
  'config.json',
];

export const lyrieAdapter: AgentAdapter = {
  agent: 'lyrie',
  displayName: 'Lyrie',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const stateDir = lyrieStateDir(fs);

    const checkouts = await findLyrieCheckouts(fs);
    let hasState = false;
    for (const marker of STATE_MARKERS) {
      if (await fs.access(join(stateDir, marker))) {
        hasState = true;
        break;
      }
    }
    if (checkouts.length === 0 && !hasState) return [];

    // Primary: the checkout a service runs, else the first one with a .env
    // (a configured deployment), else the first found.
    const withEnv: LyrieCheckout[] = [];
    for (const c of checkouts) {
      if (await fs.access(join(c.dir, '.env'))) withEnv.push(c);
    }
    const primary = checkouts.find(c => c.service) ?? withEnv[0] ?? checkouts[0];

    const configFiles: ParsedConfig[] = [];
    const ordered = primary ? [primary, ...checkouts.filter(c => c !== primary)] : [];
    for (const c of ordered) {
      const env = await tryLoad(join(c.dir, '.env'), fs);
      if (env) configFiles.push(env);
      const nodeEnv = typeof env?.data.NODE_ENV === 'string' ? env.data.NODE_ENV : undefined;
      for (const name of lyrieEnvLayers(nodeEnv)) {
        const layer = await tryLoad(join(c.dir, name), fs);
        if (layer) configFiles.push(layer);
      }
    }
    // Python CLI key store (`lyrie auth set`) — plaintext provider/GitHub keys.
    const pyConfig = await tryLoad(join(stateDir, 'config.json'), fs);
    if (pyConfig) configFiles.push(pyConfig);

    const otherInstalls: CliInstall[] = checkouts
      .filter(c => c !== primary && c.version && c.version !== primary?.version)
      .map(c => ({ path: c.dir, version: c.version }));

    const primaryEnv = configFiles.find(c => primary && c.filePath === join(primary.dir, '.env'));

    return [{
      agent: 'lyrie',
      installDir: primary?.dir ?? stateDir,
      configFiles,
      skillsDir: join(stateDir, 'skills'),
      gateway: this.getGatewayInfo(primaryEnv?.data ?? {}),
      models: await this.getModels?.(configFiles, fs),
      otherInstalls: otherInstalls.length > 0 ? otherInstalls : undefined,
      version: primary?.version,
    }];
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const home = fs.homedir();
    return [
      ...HOME_CHECKOUT_CANDIDATES.map(rel => join(home, rel, '.env')),
      ...SYSTEM_CHECKOUT_CANDIDATES.map(dir => join(dir, '.env')),
      join(lyrieStateDir(fs), 'config.json'),
    ];
  },

  getSkillsDir(_installDir: string): string | undefined {
    // Skills live in the state dir regardless of where the checkout is
    // (SkillLoader.defaultPaths: ~/.lyrie/skills first).
    return join(new LocalFSProvider().homedir(), '.lyrie', 'skills');
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    // Lyrie 3.4.0 binds no inbound listener from its config: the chat
    // channels are outbound bot connections, and the WebChat channel
    // (LYRIE_WEBCHAT_ENABLED/HOST/PORT) is a skeleton whose Bun.serve call is
    // commented out upstream. Its exposure settings are evaluated by
    // LY-010/LY-011 instead of reporting a listener that does not exist.
    return undefined;
  },

  getModels(configs: ParsedConfig[], fs?: FSProvider): ModelRef[] {
    const out: ModelRef[] = [];
    const seen = new Set<string>();
    const push = (raw: unknown, provider: unknown, via?: string): void => {
      if (typeof raw !== 'string' || !raw.trim()) return;
      let id = raw.trim();
      let prov = typeof provider === 'string' && provider.trim() ? provider.trim() : undefined;
      const slash = id.indexOf('/');
      if (!prov && slash > 0) {
        prov = id.slice(0, slash);
        id = id.slice(slash + 1);
      }
      const key = `${prov ?? ''}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...(prov ? { provider: prov } : {}), ...(via ? { via } : {}) });
    };

    // packages/core/src/config.ts: LYRIE_PROVIDER (default "hermes") +
    // LYRIE_MODEL; LYRIE_FALLBACK_PROVIDER names only a provider.
    for (const env of configs.filter(c => c.format === 'env' || c.filePath.endsWith('.env'))) {
      push(env.data.LYRIE_MODEL, env.data.LYRIE_PROVIDER);
    }

    if (out.length === 0 && fs?.getEnv) {
      push(fs.getEnv('LYRIE_MODEL'), fs.getEnv('LYRIE_PROVIDER'), 'LYRIE_MODEL');
    }

    return out;
  },

  getMemoryFiles(_installDir: string): string[] {
    const stateDir = join(new LocalFSProvider().homedir(), '.lyrie');
    return [
      join(stateDir, 'memory', 'lyrie-memory.db'),
      join(stateDir, 'edits.json'),
      join(stateDir, 'pairing.json'),
    ];
  },

  getCredentialPaths(installDir: string, fs?: FSProvider): string[] {
    // installDir is the checkout (its .env) — or the state dir itself when
    // only state exists / the installer cloned into ~/.lyrie.
    const stateDir = lyrieStateDir(fs ?? new LocalFSProvider());
    return [
      join(installDir, '.env'),
      ...ENV_LAYER_FILES.map(f => join(installDir, f)),
      join(stateDir, 'config.json'),
    ];
  },

  getProbeManifest(): ProbeManifest {
    const homeCheckouts = HOME_CHECKOUT_CANDIDATES.map(rel => `~/${rel}`);
    return {
      filePaths: [
        ...homeCheckouts.flatMap(dir => [`${dir}/package.json`, `${dir}/.env`, ...ENV_LAYER_FILES.map(f => `${dir}/${f}`)]),
        '~/.lyrie/config.json',
        '~/.lyrie/pairing.json',
        '~/.lyrie/edits.json',
        '~/.lyrie/mcp.json',
        ...SERVICE_FILES.map(rel => `~/${rel}`),
      ],
      globPatterns: [
        '~/.lyrie/migrations/*.json',
        '~/.lyrie/skills/**',
      ],
      commands: [],
      directoryListings: [
        '~/.lyrie',
        '~/.lyrie/memory',
        '~/.lyrie/memory/archive',
        '~/.lyrie/skills',
        '~/.lyrie/migrations',
      ],
      envPrefixes: [
        'LYRIE_',
        'ANTHROPIC_',
        'OPENAI_',
        'GOOGLE_',
        'XAI_',
        'MINIMAX_',
        'OLLAMA_',
        'DAYTONA_',
        'MODAL_',
      ],
      systemPaths: SYSTEM_CHECKOUT_CANDIDATES.flatMap(dir => [`${dir}/package.json`, `${dir}/.env`, ...ENV_LAYER_FILES.map(f => `${dir}/${f}`)]),
      systemDirListings: [],
      // Conversation memory and the built Shield binary: existence + mode only.
      metadataGlobPatterns: [
        '~/.lyrie/memory/lyrie-memory.db',
        '~/.lyrie/memory/archive/*',
        ...[...homeCheckouts, ...SYSTEM_CHECKOUT_CANDIDATES]
          .flatMap(dir => SHIELD_BINARY_RELATIVE.map(rel => `${dir}/${rel}`)),
      ],
    };
  },

  // Layered architecture: Shield is Layer 1, sitting between channels and the
  // engine. Inversion edges fire when the Shield is degraded (Rust binary not
  // built, or the dev-mode SSRF bypass) or a DM channel is left open — in
  // either case untrusted channel input flows past the intended gate.
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network', trustLevel: 0 },
        { id: 'ch', label: 'Channel Gateway', trustLevel: 1 },
        { id: 'shld', label: 'Lyrie Shield (Layer 1)', trustLevel: 2 },
        { id: 'eng', label: 'Engine + EditEngine + MCP', trustLevel: 3 },
        { id: 'mem', label: 'Memory + Pairing + Edits', trustLevel: 4 },
      ],
      components: [
        { id: 'inbound', label: 'Network Ingress', zone: 'net' },
        {
          id: 'channels',
          label: 'Channel Adapters',
          zone: 'ch',
          guardCheckIds: ['LY-003', 'LY-010', 'LY-011'],
        },
        {
          id: 'shield',
          label: 'Lyrie Shield',
          zone: 'shld',
          guardCheckIds: ['LY-001', 'LY-002', 'LY-018'],
        },
        {
          id: 'engine',
          label: 'Engine + EditEngine',
          zone: 'eng',
          guardCheckIds: ['LY-012', 'LY-013', 'LY-014', 'LY-019'],
        },
        {
          id: 'memory',
          label: 'Memory + Pairing + Edits',
          zone: 'mem',
          guardCheckIds: ['LY-004', 'LY-006', 'LY-015', 'LY-020'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'channels', kind: 'data' },
        { from: 'channels', to: 'shield', kind: 'control' },
        { from: 'shield', to: 'engine', kind: 'data' },
        { from: 'engine', to: 'memory', kind: 'data' },
        {
          from: 'inbound',
          to: 'engine',
          label: 'shield bypass',
          triggerCheckIds: ['LY-002', 'LY-018'],
        },
        {
          from: 'inbound',
          to: 'memory',
          label: 'DM pairing bypass',
          triggerCheckIds: ['LY-003'],
        },
      ],
    };
  },
};
