import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { queryCliVersion } from './version-query.js';

export const nanoclawAdapter: AgentAdapter = {
  agent: 'nanoclaw',
  displayName: 'NanoClaw',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const configDir = join(home, '.config', 'nanoclaw');
    const envPath = join(home, '.nanoclaw.env');
    const configFiles = [];

    // Check .env file with NanoClaw vars
    if (await fs.access(envPath)) {
      try {
        const config = await loadConfig(envPath, fs);
        if (config.data.NANOCLAW_HOME || config.data.NANOCLAW_PORT) {
          configFiles.push(config);
        }
      } catch {}
    }

    // Check config dir
    const mountAllowlistPath = join(configDir, 'mount-allowlist.json');
    if (await fs.access(mountAllowlistPath)) {
      try {
        configFiles.push(await loadConfig(mountAllowlistPath, fs));
      } catch {}
    }

    const configPath = join(configDir, 'config.json');
    if (await fs.access(configPath)) {
      try {
        configFiles.push(await loadConfig(configPath, fs));
      } catch {}
    }

    if (configFiles.length === 0) return [];

    // Extract version from config, fallback to CLI
    const mainConfig = configFiles.find(c => c.filePath.endsWith('config.json'));
    const version = (mainConfig?.data?.version as string) ?? queryCliVersion('nanoclaw', fs);

    return [{
      agent: 'nanoclaw',
      installDir: configDir,
      configFiles,
      skillsDir: this.getSkillsDir(configDir),
      models: await this.getModels?.(configFiles, fs),
      version,
    }];
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    return [
      join(home, '.nanoclaw.env'),
      join(home, '.config', 'nanoclaw', 'config.json'),
      join(home, '.config', 'nanoclaw', 'mount-allowlist.json'),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getModels(_configs: ParsedConfig[], _fs?: FSProvider): ModelRef[] {
    // NanoClaw does not select a model itself — it shells out to an inner
    // coding agent (claude, codex, opencode, …) chosen via the per-session
    // `agent_provider` field, which lives in the SQLite DB, not a config
    // file. The actual model is whatever that inner agent is configured for.
    // VASO can't read SQLite without a DB driver dependency, and even if it
    // could, the model question is answered by the inner agent's adapter.
    return [];
  },

  getCLICommand(): string {
    return 'nanoclaw';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.nanoclaw.env',
        '~/.config/nanoclaw/config.json',
        '~/.config/nanoclaw/mount-allowlist.json',
      ],
      globPatterns: [
        '~/.config/nanoclaw/skills/**',
      ],
      commands: [
        { id: 'nanoclaw-which', cmd: 'which', args: ['nanoclaw'], timeout: 3000 },
        { id: 'nanoclaw-version', cmd: 'nanoclaw', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.config/nanoclaw',
        '~/.config/nanoclaw/skills',
      ],
      envPrefixes: ['NANOCLAW_'],
      systemPaths: [],
      systemDirListings: [],
    };
  },
};

