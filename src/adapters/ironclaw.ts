import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { queryCliVersion } from './version-query.js';

const CONFIG_FILENAMES = [
  '.env',
  'config.toml',
  'settings.json',
  'mcp-servers.json',
];

export const ironclawAdapter: AgentAdapter = {
  agent: 'ironclaw',
  displayName: 'IronClaw',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const ironDir = join(home, '.ironclaw');
    const configFiles = [];

    for (const filename of CONFIG_FILENAMES) {
      const filePath = join(ironDir, filename);
      if (await fs.access(filePath)) {
        try {
          configFiles.push(await loadConfig(filePath, fs));
        } catch {}
      }
    }

    // Also check for CLI binary
    const cliBinary = await findCLIBinary(home, fs);

    if (configFiles.length === 0 && !cliBinary) return [];

    // Merge all config data to extract gateway info
    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    // Extract version from TOML config, fallback to CLI
    const tomlConfig = configFiles.find(c => c.filePath.endsWith('.toml'));
    const version =
      (tomlConfig?.data?.version as string) ??
      ((tomlConfig?.data?.package as Record<string, unknown>)?.version as string) ??
      queryCliVersion(cliBinary ?? 'ironclaw', fs);

    return [{
      agent: 'ironclaw',
      installDir: ironDir,
      configFiles,
      skillsDir: this.getSkillsDir(ironDir),
      gateway: this.getGatewayInfo(merged),
      models: await this.getModels?.(configFiles, fs),
      cliBinary,
      version,
    }];
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    const ironDir = join(home, '.ironclaw');
    return CONFIG_FILENAMES.map(f => join(ironDir, f));
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    // Check .env-style keys first
    const envHost = config.GATEWAY_HOST as string | undefined;
    const envPort = config.GATEWAY_PORT as string | undefined;
    if (envHost || envPort) {
      return {
        host: envHost,
        port: envPort ? parseInt(envPort, 10) : undefined,
      };
    }

    // Check TOML [gateway] section
    const gw = config.gateway as Record<string, unknown> | undefined;
    if (gw) {
      return {
        host: gw.host as string | undefined,
        port: gw.port as number | undefined,
        tls: gw.tls as boolean | undefined,
      };
    }

    return undefined;
  },

  getModels(configs: ParsedConfig[], fs?: FSProvider): ModelRef[] {
    // IronClaw does not store the model in config.toml. `LLM_BACKEND` selects
    // a backend (nearai, ollama, openai_compatible, openai, anthropic,
    // github_copilot, tinfoil, openai_codex, gemini_oauth, minimax) and the
    // chosen backend reads its own `<NAME>_MODEL` env var.
    //
    // We honor LLM_BACKEND if set; otherwise we surface every backend whose
    // model env var is populated, so the user sees what's actually configured.
    const out: ModelRef[] = [];
    const seen = new Set<string>();

    const BACKEND_ENV: Record<string, { model: string }> = {
      nearai: { model: 'NEARAI_MODEL' },
      ollama: { model: 'OLLAMA_MODEL' },
      openai_compatible: { model: 'LLM_MODEL' },
      openai: { model: 'OPENAI_MODEL' },
      anthropic: { model: 'ANTHROPIC_MODEL' },
      github_copilot: { model: 'GITHUB_COPILOT_MODEL' },
      tinfoil: { model: 'TINFOIL_MODEL' },
      openai_codex: { model: 'OPENAI_CODEX_MODEL' },
      gemini_oauth: { model: 'GEMINI_MODEL' },
      minimax: { model: 'MINIMAX_MODEL' },
    };

    const lookup = (key: string): string | undefined => {
      // Prefer .env file over process env so a project-local override wins.
      const env = configs.find(c => c.filePath.endsWith('.env'));
      const fromFile = env?.data?.[key];
      if (typeof fromFile === 'string' && fromFile.trim()) return fromFile.trim();
      const fromProc = fs?.getEnv?.(key);
      if (typeof fromProc === 'string' && fromProc.trim()) return fromProc.trim();
      return undefined;
    };

    const push = (id: string | undefined, provider: string, via?: string): void => {
      if (!id) return;
      const key = `${provider}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, provider, ...(via ? { via } : {}) });
    };

    const selected = lookup('LLM_BACKEND');
    if (selected && BACKEND_ENV[selected]) {
      push(lookup(BACKEND_ENV[selected].model), selected);
    } else {
      // No LLM_BACKEND set — list every backend whose model env is populated.
      for (const [backend, keys] of Object.entries(BACKEND_ENV)) {
        push(lookup(keys.model), backend, selected ? undefined : 'env-detected');
      }
    }

    return out;
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'memory.json'),
      join(installDir, 'conversations.db'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, '.env'),
      join(installDir, 'config.toml'),
      join(installDir, 'settings.json'),
    ];
  },

  getCLICommand(): string {
    return 'ironclaw';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.ironclaw/.env',
        '~/.ironclaw/config.toml',
        '~/.ironclaw/settings.json',
        '~/.ironclaw/mcp-servers.json',
        '~/.ironclaw/memory.json',
        '~/.ironclaw/conversations.db',
      ],
      globPatterns: [
        '~/.ironclaw/skills/**',
      ],
      commands: [
        { id: 'ironclaw-which', cmd: 'which', args: ['ironclaw'], timeout: 3000 },
        { id: 'ironclaw-version', cmd: 'ironclaw', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.ironclaw',
        '~/.ironclaw/skills',
        '~/.cargo/bin',
      ],
      envPrefixes: ['IRONCLAW_', 'GATEWAY_'],
      systemPaths: [],
      systemDirListings: [],
    };
  },

  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network', trustLevel: 0 },
        { id: 'gw', label: 'gRPC Gateway', trustLevel: 1 },
        { id: 'sbx', label: 'Sandbox', trustLevel: 2 },
        { id: 'host', label: 'Host FS', trustLevel: 3 },
      ],
      components: [
        { id: 'inbound', label: 'Network Ingress', zone: 'net' },
        {
          id: 'gateway',
          label: 'IronClaw gRPC Gateway',
          zone: 'gw',
          guardCheckIds: ['IC-001', 'IC-002', 'IC-003', 'IC-004', 'IC-010'],
        },
        {
          id: 'sandbox',
          label: 'Sandbox Boundary',
          zone: 'sbx',
          guardCheckIds: ['IC-005', 'IC-006', 'IC-011', 'IC-012'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem',
          zone: 'host',
          guardCheckIds: ['IC-007', 'IC-008', 'IC-009'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'gateway', kind: 'data' },
        { from: 'gateway', to: 'sandbox', kind: 'control' },
        { from: 'sandbox', to: 'fs', kind: 'data' },
        {
          from: 'inbound',
          to: 'fs',
          label: 'sandbox bypass',
          triggerCheckIds: ['IC-005', 'IC-008'],
        },
      ],
    };
  },
};

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  const cargoPath = join(home, '.cargo', 'bin', 'ironclaw');
  if (await fs.access(cargoPath)) return cargoPath;

  try {
    const result = fs.execSync('which', ['ironclaw'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}

  return undefined;
}
