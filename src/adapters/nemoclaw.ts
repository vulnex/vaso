import { dirname, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { discoverCliInstalls } from './cli-installs.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';

// Two install generations:
//  - Current (install.sh, v0.0.x tags): the repo is checked out to
//    ~/.nemoclaw/source, npm-linked into the active Node's global prefix, and
//    fronted by a ~/.local/bin/nemoclaw shim. package.json is pinned at 0.1.0
//    in every release, so the version comes from source/dist/build-identity.json
//    (then source/.version) — the same order `nemoclaw --version` uses.
//  - Legacy (early 2026): an npm-global package (/usr/bin/nemoclaw →
//    node_modules/nemoclaw), versioned only by that package.json.
const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/nemoclaw',
  '/usr/bin/nemoclaw',
  '/opt/homebrew/bin/nemoclaw',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/nemoclaw',
  '.npm-global/bin/nemoclaw',
  '.volta/bin/nemoclaw',
  '.bun/bin/nemoclaw',
];

/** The installer-managed checkout, when this is a current-generation install. */
function sourceDir(home: string): string {
  return join(home, '.nemoclaw', 'source');
}

/** Every nemoclaw CLI copy. A current install's ~/.local/bin shim is primary
 *  over a legacy npm-global left in /usr/bin — login shells put ~/.local/bin
 *  first, so it is the one users run. Each copy is versioned by the install
 *  generation it belongs to. */
async function findCLIInstalls(home: string, fs: FSProvider) {
  const src = sourceDir(home);
  const hasSource = await fs.access(src);
  return discoverCliInstalls(home, fs, {
    names: ['nemoclaw'],
    systemPaths: SYSTEM_CLI_PATHS,
    userRelPaths: USER_CLI_RELATIVE_PATHS,
    preferPath: hasSource ? join(home, '.local', 'bin', 'nemoclaw') : undefined,
    version: async (bin, canExec) => {
      let real = bin;
      try { real = await fs.realpath(bin); } catch {}
      const isCurrent = hasSource && (bin === join(home, '.local', 'bin', 'nemoclaw') || real.startsWith(`${src}/`));
      if (isCurrent) return readSourceInstallVersion(home, fs);
      // An npm-global copy that is an `npm link` of a current checkout carries
      // the build identity (snapshots can't follow the link to tell).
      const identity = await readBuildIdentity(join(dirname(dirname(bin)), 'lib', 'node_modules', 'nemoclaw'), fs);
      if (identity) return identity;
      return (await readPackageVersion(bin, fs, 'nemoclaw'))
        ?? (canExec ? queryCliVersion(bin, fs, { argSets: [['--version']] }) : undefined);
    },
  });
}

// Candidate package.json locations for npm-globally-installed nemoclaw.
// SnapshotFSProvider doesn't follow symlinks, so we have to know the real
// install root rather than relying on realpath of /usr/bin/nemoclaw.
function nodeModulesPackageJsonCandidates(home: string): string[] {
  return [
    '/usr/lib/node_modules/nemoclaw/package.json',
    '/usr/local/lib/node_modules/nemoclaw/package.json',
    '/opt/homebrew/lib/node_modules/nemoclaw/package.json',
    `${home}/.npm-global/lib/node_modules/nemoclaw/package.json`,
    `${home}/.bun/install/global/node_modules/nemoclaw/package.json`,
    `${home}/.volta/tools/image/packages/nemoclaw/package.json`,
  ];
}

/** `nemoclawVersion` from `<root>/dist/build-identity.json`. */
async function readBuildIdentity(root: string, fs: FSProvider): Promise<string | undefined> {
  try {
    const identity = JSON.parse(await fs.readFile(join(root, 'dist', 'build-identity.json'))) as Record<string, unknown>;
    const v = identity.nemoclawVersion;
    if (typeof v === 'string' && /^\d+\.\d+\.\d+/.test(v)) return v;
  } catch {}
  return undefined;
}

/** Version of a current-generation install: dist/build-identity.json, then .version. */
async function readSourceInstallVersion(home: string, fs: FSProvider): Promise<string | undefined> {
  const root = sourceDir(home);
  const identity = await readBuildIdentity(root, fs);
  if (identity) return identity;
  try {
    const v = (await fs.readFile(join(root, '.version'))).trim().replace(/^v/, '');
    if (/^\d+\.\d+\.\d+/.test(v)) return v;
  } catch {}
  return undefined;
}

async function readNodePackageVersion(fs: FSProvider): Promise<string | undefined> {
  const home = fs.homedir();
  for (const p of nodeModulesPackageJsonCandidates(home)) {
    try {
      const raw = await fs.readFile(p);
      const pkg = JSON.parse(raw);
      if (pkg.version && /^\d+\.\d+\.\d+/.test(pkg.version)) return pkg.version;
    } catch {}
  }
  return undefined;
}

const PIP_VERSION_RE = /^Version:\s*(\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.]+)?)/m;
const SEMVER_RE = /^\s*(\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.]+)?)\s*$/m;
const IMPORT_META_SCRIPT = "from importlib.metadata import version; print(version('nemoclaw'))";

const PY_VERSIONS = ['3.8', '3.9', '3.10', '3.11', '3.12', '3.13', '3.14'] as const;
const PKG_DIRS = ['site-packages', 'dist-packages'] as const;
const NEMOCLAW_DIST_RE = /^nemoclaw[-_]/i;
const DIST_INFO_SUFFIX = ['.dist-info', '.egg-info'] as const;

function tryExec(fs: FSProvider, argv: [string, ...string[]]): string | undefined {
  try {
    return fs.execSync(argv[0], argv.slice(1), { timeout: 10000, isolateHome: true });
  } catch {
    return undefined;
  }
}

function parsePipShowVersion(fs: FSProvider, argv: [string, ...string[]]): string | undefined {
  const out = tryExec(fs, argv);
  if (!out) return undefined;
  return PIP_VERSION_RE.exec(out)?.[1];
}

function parsePyMetadataVersion(fs: FSProvider, python: string): string | undefined {
  const out = tryExec(fs, [python, '-c', IMPORT_META_SCRIPT]);
  if (!out) return undefined;
  return SEMVER_RE.exec(out)?.[1];
}

/**
 * Walk common Python install roots looking for a nemoclaw*.dist-info or
 * .egg-info directory and parse the Version field from METADATA/PKG-INFO.
 * Works for apt-, pip-, pipx- and pip-user-installed packages without needing
 * to spawn Python. The probe collects matching files via glob; SnapshotFSProvider
 * derives the parent directory listings from the collected file paths.
 */
async function findInstalledPackageVersion(fs: FSProvider): Promise<string | undefined> {
  const home = fs.homedir();
  const roots = [
    '/usr/lib',
    '/usr/local/lib',
    `${home}/.local/lib`,
    `${home}/.local/share/pipx/venvs/nemoclaw/lib`,
  ];

  for (const root of roots) {
    for (const ver of PY_VERSIONS) {
      for (const pkgs of PKG_DIRS) {
        const dir = `${root}/python${ver}/${pkgs}`;
        let entries;
        try {
          entries = await fs.readdirEntries(dir);
        } catch {
          continue;
        }
        for (const entry of entries) {
          if (!NEMOCLAW_DIST_RE.test(entry.name)) continue;
          if (!DIST_INFO_SUFFIX.some(s => entry.name.endsWith(s))) continue;
          for (const fname of ['METADATA', 'PKG-INFO']) {
            try {
              const content = await fs.readFile(`${dir}/${entry.name}/${fname}`);
              const m = PIP_VERSION_RE.exec(content);
              if (m?.[1]) return m[1];
            } catch {
              // not collected / not present, try next
            }
          }
        }
      }
    }
  }
  return undefined;
}

export const nemoclawAdapter: AgentAdapter = {
  agent: 'nemoclaw',
  displayName: 'NemoClaw',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const nemoDir = join(home, '.nemoclaw');

    if (!(await fs.access(nemoDir))) return [];

    const configFiles = [];

    // Load sandboxes.json — primary config describing sandbox deployments
    const sandboxesPath = join(nemoDir, 'sandboxes.json');
    {
      const loaded = await loadConfigIfPresent(sandboxesPath, fs);
      if (loaded) configFiles.push(loaded);
    }

    // Load credentials.json
    const credPath = join(nemoDir, 'credentials.json');
    {
      const loaded = await loadConfigIfPresent(credPath, fs);
      if (loaded) configFiles.push(loaded);
    }

    // Load config.json if present
    const configPath = join(nemoDir, 'config.json');
    {
      const loaded = await loadConfigIfPresent(configPath, fs);
      if (loaded) configFiles.push(loaded);
    }

    // Load state file for deployment info
    const statePath = join(nemoDir, 'state', 'nemoclaw.json');
    {
      const loaded = await loadConfigIfPresent(statePath, fs);
      if (loaded) configFiles.push(loaded);
    }

    // Directory exists but no config files means NemoClaw is not actually installed
    if (configFiles.length === 0) return [];

    // Version sources, in order:
    //   1. The primary CLI copy (current install: source build identity;
    //      legacy npm-global: its package.json — the legacy CLI has no version flag).
    //   2. The same sources without a resolvable binary.
    //   3. Python fallbacks for any python-packaged fork.
    //   4. CLI subcommand attempts.
    const installs = await findCLIInstalls(home, fs);
    const cliBinary = installs.primary?.path;
    let version = installs.primary?.version
      ?? (await readSourceInstallVersion(home, fs))
      ?? (await readNodePackageVersion(fs))
      ?? parsePyMetadataVersion(fs, 'python3')
      ?? parsePyMetadataVersion(fs, 'python')
      ?? parsePipShowVersion(fs, ['pip3', 'show', 'nemoclaw'])
      ?? parsePipShowVersion(fs, ['pip', 'show', 'nemoclaw'])
      ?? (await findInstalledPackageVersion(fs))
      ?? queryCliVersion('nemoclaw', fs, {
        argSets: [['version'], ['--version'], ['help']],
      });
    if (!version) {
      try {
        const stateRaw = await fs.readFile(statePath);
        const state = JSON.parse(stateRaw) as Record<string, unknown>;
        version = state.blueprintVersion as string | undefined;
      } catch {}
    }

    // Extract sandbox names for display
    let agentName: string | undefined;
    try {
      const sandboxesRaw = await fs.readFile(sandboxesPath);
      const sandboxes = JSON.parse(sandboxesRaw) as Record<string, unknown>;
      const defaultSandbox = sandboxes.defaultSandbox as string | undefined;
      const sandboxMap = sandboxes.sandboxes as Record<string, unknown> | undefined;
      const count = sandboxMap ? Object.keys(sandboxMap).length : 0;
      if (defaultSandbox) {
        agentName = count > 1
          ? `${defaultSandbox} (+${count - 1} more)`
          : defaultSandbox;
      }
    } catch {}

    return [{
      agent: 'nemoclaw',
      agentName,
      installDir: nemoDir,
      configFiles,
      cliBinary,
      otherInstalls: installs.others.length > 0 ? installs.others : undefined,
      version,
      models: await this.getModels?.(configFiles),
    }];
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    return [
      join(home, '.nemoclaw', 'sandboxes.json'),
      join(home, '.nemoclaw', 'credentials.json'),
      join(home, '.nemoclaw', 'config.json'),
      join(home, '.nemoclaw', 'state', 'nemoclaw.json'),
    ];
  },

  getSkillsDir(_installDir: string): string | undefined {
    // NemoClaw sandboxes run skills inside the container, not on host
    return undefined;
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    // NemoClaw doesn't expose a gateway on the host — agent runs inside sandbox
    return undefined;
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    const sb = configs.find(c => c.filePath.endsWith('sandboxes.json'));
    const map = sb?.data?.sandboxes as Record<string, unknown> | undefined;
    if (!map) return [];
    const out: ModelRef[] = [];
    for (const [name, cfg] of Object.entries(map)) {
      const c = cfg as Record<string, unknown> | undefined;
      const id = c?.model as string | undefined;
      if (!id) continue;
      out.push({ id, provider: c?.provider as string | undefined, via: name });
    }
    return out;
  },

  getCredentialPaths(installDir: string): string[] {
    return [join(installDir, 'credentials.json')];
  },

  getCLICommand(): string {
    return 'nemoclaw';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.nemoclaw/sandboxes.json',
        '~/.nemoclaw/credentials.json',
        '~/.nemoclaw/config.json',
        '~/.nemoclaw/state/nemoclaw.json',
        // Current installs: version identity of the ~/.nemoclaw/source checkout
        // and the ~/.local/bin shim.
        '~/.nemoclaw/source/dist/build-identity.json',
        '~/.nemoclaw/source/.version',
        '~/.local/bin/nemoclaw',
        // Bundled blueprint (CFG-018 base policy, CFG-019 image digest pin)
        '~/.nemoclaw/source/nemoclaw-blueprint/blueprint.yaml',
        '~/.nemoclaw/source/nemoclaw-blueprint/policies/openclaw-sandbox.yaml',
        // Legacy installs: NemoClaw was shipped as an npm-global Node.js package — its
        // package.json holds the canonical version. Cover the common
        // global-install prefixes.
        '/usr/lib/node_modules/nemoclaw/package.json',
        '/usr/local/lib/node_modules/nemoclaw/package.json',
        '~/.npm-global/lib/node_modules/nemoclaw/package.json',
        '~/.bun/install/global/node_modules/nemoclaw/package.json',
        '~/.volta/tools/image/packages/nemoclaw/package.json',
      ],
      globPatterns: [
        // npm-linked copies under each nvm Node (remote: the link isn't followable)
        '~/.nvm/versions/node/*/lib/node_modules/nemoclaw/dist/build-identity.json',
        '~/.nemoclaw/blueprints/**',
        '~/.nemoclaw/policies/**',
        // nvm installs live under a per-version subdir.
        '~/.nvm/versions/node/*/lib/node_modules/nemoclaw/package.json',
        // Defensive: also collect any nearby package.json walking up from the
        // /usr/bin/nemoclaw shim, and Python METADATA in case a fork is
        // packaged that way.
        '/usr/lib/python*/site-packages/nemoclaw*/METADATA',
        '/usr/lib/python*/dist-packages/nemoclaw*/METADATA',
        '/usr/local/lib/python*/site-packages/nemoclaw*/METADATA',
        '/usr/local/lib/python*/dist-packages/nemoclaw*/METADATA',
        '~/.local/lib/python*/site-packages/nemoclaw*/METADATA',
      ],
      commands: [
        { id: 'nemoclaw-which', cmd: 'which', args: ['nemoclaw'], timeout: 3000 },
        { id: 'nemoclaw-version-flag', cmd: 'nemoclaw', args: ['--version'], timeout: 15000 },
        { id: 'nemoclaw-version-sub', cmd: 'nemoclaw', args: ['version'], timeout: 15000 },
        { id: 'nemoclaw-help', cmd: 'nemoclaw', args: ['help'], timeout: 15000 },
        // NemoClaw is a pip/pipx/uv-installed Python CLI without a built-in
        // version flag. importlib.metadata works regardless of install method
        // and is the most reliable source.
        {
          id: 'nemoclaw-py3-meta',
          cmd: 'python3',
          args: ['-c', "from importlib.metadata import version; print(version('nemoclaw'))"],
          timeout: 10000,
        },
        {
          id: 'nemoclaw-py-meta',
          cmd: 'python',
          args: ['-c', "from importlib.metadata import version; print(version('nemoclaw'))"],
          timeout: 10000,
        },
        { id: 'nemoclaw-pip3-show', cmd: 'pip3', args: ['show', 'nemoclaw'], timeout: 10000 },
        { id: 'nemoclaw-pip-show', cmd: 'pip', args: ['show', 'nemoclaw'], timeout: 10000 },
      ],
      directoryListings: [
        '~/.nemoclaw',
        '~/.nemoclaw/source',
        '~/.nemoclaw/source/nemoclaw-blueprint',
        '~/.nemoclaw/source/nemoclaw-blueprint/policies',
        '~/.nemoclaw/source/nemoclaw-blueprint/policies/presets',
        '~/.nemoclaw/state',
        '~/.nemoclaw/blueprints',
        '~/.nemoclaw/policies',
      ],
      envPrefixes: ['NEMOCLAW_'],
      systemPaths: [
        '/usr/bin/nemoclaw',
        '/usr/local/bin/nemoclaw',
      ],
      systemDirListings: [],
    };
  },

  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network', trustLevel: 0 },
        { id: 'gw', label: 'Gateway', trustLevel: 1 },
        { id: 'cpu', label: 'CPU Sandbox', trustLevel: 2 },
        { id: 'gpu', label: 'GPU Isolation', trustLevel: 3 },
        { id: 'host', label: 'Host FS', trustLevel: 4 },
      ],
      components: [
        { id: 'inbound', label: 'Network Ingress', zone: 'net' },
        {
          id: 'gateway',
          label: 'NemoClaw Gateway',
          zone: 'gw',
          guardCheckIds: ['CFG-001', 'CFG-004', 'NET-001', 'CFG-020'],
        },
        {
          id: 'sandbox',
          label: 'CPU Sandbox',
          zone: 'cpu',
          guardCheckIds: ['CFG-016', 'CFG-017', 'CFG-022', 'CFG-024'],
        },
        {
          id: 'gpu',
          label: 'GPU Boundary',
          zone: 'gpu',
          guardCheckIds: ['CFG-018', 'CFG-019', 'CFG-021', 'CFG-023'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem',
          zone: 'host',
          guardCheckIds: ['RUN-001', 'POL-001'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'gateway', kind: 'data' },
        { from: 'gateway', to: 'sandbox', kind: 'control' },
        { from: 'sandbox', to: 'gpu', kind: 'resource' },
        { from: 'gpu', to: 'fs', kind: 'data', label: 'model artifacts' },
        {
          from: 'inbound',
          to: 'fs',
          label: 'sandbox bypass',
          triggerCheckIds: ['CFG-017', 'CFG-022', 'CFG-024'],
        },
      ],
    };
  },
};

