import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';

const RUNTIME_FILES = ['.env'];

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/lyrie',
  '/opt/homebrew/bin/lyrie',
  '/usr/bin/lyrie',
];

const USER_CLI_RELATIVE_PATHS = [
  '.bun/bin/lyrie',
  '.local/bin/lyrie',
];

export const lyrieAdapter: AgentAdapter = {
  agent: 'lyrie',
  displayName: 'Lyrie',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const lyrieDir = join(home, '.lyrie');

    const runtimeMarkers = [
      join(lyrieDir, 'memory'),
      join(lyrieDir, 'pairing.json'),
      join(lyrieDir, 'edits.json'),
      join(lyrieDir, 'migrations'),
    ];

    let hasRuntime = false;
    for (const marker of runtimeMarkers) {
      if (await fs.access(marker)) {
        hasRuntime = true;
        break;
      }
    }

    const cliBinary = await findCLIBinary(home, fs);

    if (!hasRuntime && !cliBinary) return [];

    const configFiles = [];
    for (const filename of RUNTIME_FILES) {
      const filePath = join(lyrieDir, filename);
      if (await fs.access(filePath)) {
        try {
          configFiles.push(await loadConfig(filePath, fs));
        } catch {}
      }
    }

    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    const version =
      queryCliVersion(cliBinary, fs, { argSets: [['--version'], ['version']] }) ??
      (await readPackageVersion(cliBinary, fs)) ??
      '0.1.0';

    return [{
      agent: 'lyrie',
      installDir: lyrieDir,
      configFiles,
      skillsDir: this.getSkillsDir(lyrieDir),
      gateway: this.getGatewayInfo(merged),
      models: await this.getModels?.(configFiles, fs),
      cliBinary,
      version,
    }];
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    const lyrieDir = join(home, '.lyrie');
    return RUNTIME_FILES.map(f => join(lyrieDir, f));
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    // WebChat is the only locally-bound HTTP listener Lyrie ships; other
    // channels are webhook- or connection-based (no inbound bind).
    const webchatPort = config.LYRIE_WEBCHAT_PORT as string | undefined;
    const webchatHost = config.LYRIE_WEBCHAT_HOST as string | undefined;
    if (!webchatPort) return undefined;

    const port = parseInt(webchatPort, 10);
    if (Number.isNaN(port)) return undefined;

    return {
      host: webchatHost ?? '127.0.0.1',
      port,
    };
  },

  getModels(configs: ParsedConfig[], fs?: FSProvider): ModelRef[] {
    const out: ModelRef[] = [];
    const seen = new Set<string>();
    const push = (raw: unknown, via?: string): void => {
      if (typeof raw !== 'string' || !raw.trim()) return;
      const trimmed = raw.trim();
      const slash = trimmed.indexOf('/');
      const provider = slash !== -1 ? trimmed.slice(0, slash) : undefined;
      const id = slash !== -1 ? trimmed.slice(slash + 1) : trimmed;
      const key = `${provider ?? ''}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...(provider ? { provider } : {}), ...(via ? { via } : {}) });
    };

    const env = configs.find(c => c.filePath.endsWith('.env'));
    if (env) {
      push(env.data.LYRIE_MODEL);
      push(env.data.LYRIE_DEFAULT_MODEL);
      push(env.data.LYRIE_FALLBACK_MODEL, 'fallback');
      // Per-channel overrides surfaced as `via=<channel>`
      for (const [k, v] of Object.entries(env.data)) {
        const m = /^LYRIE_([A-Z]+)_MODEL$/.exec(k);
        if (!m) continue;
        const slot = m[1].toLowerCase();
        if (slot === 'default' || slot === 'fallback') continue;
        if (typeof v === 'string') push(v, slot);
      }
    }

    if (out.length === 0 && fs?.getEnv) {
      push(fs.getEnv('LYRIE_MODEL'), 'LYRIE_MODEL');
    }

    return out;
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'memory', 'lyrie-memory.db'),
      join(installDir, 'edits.json'),
      join(installDir, 'pairing.json'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, '.env'),
    ];
  },

  getCLICommand(): string {
    return 'lyrie';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.lyrie/.env',
        '~/.lyrie/memory/lyrie-memory.db',
        '~/.lyrie/edits.json',
        '~/.lyrie/pairing.json',
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.bun/bin/lyrie',
        '~/.local/bin/lyrie',
      ],
      globPatterns: [
        '~/.lyrie/memory/archive/*.db',
        '~/.lyrie/migrations/*.json',
        '~/.lyrie/skills/**',
      ],
      commands: [
        { id: 'lyrie-which', cmd: 'which', args: ['lyrie'], timeout: 3000 },
        { id: 'lyrie-version', cmd: 'lyrie', args: ['--version'], timeout: 15000 },
        { id: 'lyrie-shield-version', cmd: 'lyrie-shield', args: ['--version'], timeout: 15000 },
      ],
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
        'TELEGRAM_',
        'DISCORD_',
        'SLACK_',
        'WHATSAPP_',
        'MATRIX_',
        'FEISHU_',
        'DAYTONA_',
        'MODAL_',
      ],
      systemPaths: SYSTEM_CLI_PATHS,
      systemDirListings: [],
    };
  },

  // Layered architecture: Shield is Layer 1, sitting between channels and the
  // engine. Inversion edges fire when Shield is degraded (passive mode or
  // missing binary) or DM pairing is left open — in either case untrusted
  // channel input flows past the intended security gate.
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
          guardCheckIds: ['LY-001', 'LY-002'],
        },
        {
          id: 'engine',
          label: 'Engine + EditEngine',
          zone: 'eng',
          guardCheckIds: ['LY-012', 'LY-013', 'LY-014'],
        },
        {
          id: 'memory',
          label: 'Memory + Pairing + Edits',
          zone: 'mem',
          guardCheckIds: ['LY-006', 'LY-015', 'LY-018'],
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
          triggerCheckIds: ['LY-001', 'LY-002'],
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

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join(home, rel);
    if (await fs.access(p)) return p;
  }
  try {
    const result = fs.execSync('which', ['lyrie'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}
  return undefined;
}
