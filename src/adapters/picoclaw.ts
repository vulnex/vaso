import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { queryCliVersion } from './version-query.js';

export const picoclawAdapter: AgentAdapter = {
  agent: 'picoclaw',
  displayName: 'PicoClaw',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const picoDir = join(home, '.picoclaw');
    const configFiles = [];

    const configPath = join(picoDir, 'config.json');
    if (await fs.access(configPath)) {
      try {
        configFiles.push(await loadConfig(configPath, fs));
      } catch {}
    }

    const authPath = join(picoDir, 'auth.json');
    if (await fs.access(authPath)) {
      try {
        configFiles.push(await loadConfig(authPath, fs));
      } catch {}
    }

    if (configFiles.length === 0) return [];

    // Merge all config data to extract gateway info
    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    // Extract version from config, fallback to CLI
    const mainConfig = configFiles.find(c => c.filePath.endsWith('config.json'));
    const version = (mainConfig?.data?.version as string) ?? queryCliVersion('picoclaw', fs);

    return [{
      agent: 'picoclaw',
      installDir: picoDir,
      configFiles,
      skillsDir: this.getSkillsDir(picoDir),
      gateway: this.getGatewayInfo(merged),
      models: await this.getModels?.(configFiles),
      version,
    }];
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    return [
      join(home, '.picoclaw', 'config.json'),
      join(home, '.picoclaw', 'auth.json'),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    const gw = config.gateway as Record<string, unknown> | undefined;
    if (!gw) return undefined;

    return {
      host: gw.host as string | undefined,
      port: gw.port as number | undefined,
      authMode: (config.auth as Record<string, unknown>)?.mode as string | undefined,
      tls: gw.tls as boolean | undefined,
    };
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    // PicoClaw stores models in a top-level `model_list[]` array; each entry
    // is `{ model_name, model: "<provider>/<id>", api_key, api_base }`.
    // `agents.defaults.model_name` references the active entry. Duplicate
    // `model_name` entries with different api_key/api_base form a load-balance
    // pool — we surface each unique (provider, id, model_name) once.
    const out: ModelRef[] = [];
    const seen = new Set<string>();
    const push = (modelStr: unknown, slot: string, isDefault: boolean): void => {
      if (typeof modelStr !== 'string' || !modelStr.trim()) return;
      const trimmed = modelStr.trim();
      const slash = trimmed.indexOf('/');
      const provider = slash !== -1 ? trimmed.slice(0, slash) : undefined;
      const id = slash !== -1 ? trimmed.slice(slash + 1) : trimmed;
      const via = isDefault ? undefined : slot;
      const key = `${provider ?? ''}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...(provider ? { provider } : {}), ...(via ? { via } : {}) });
    };

    const main = configs.find(c => c.filePath.endsWith('config.json'));
    if (!main) return out;

    const defaultName =
      ((main.data?.agents as Record<string, unknown> | undefined)?.defaults as
        | Record<string, unknown>
        | undefined)?.model_name as string | undefined;

    const list = main.data?.model_list;
    if (Array.isArray(list)) {
      for (const entry of list) {
        const e = entry as Record<string, unknown> | undefined;
        const name = e?.model_name as string | undefined;
        const model = e?.model;
        if (!name) continue;
        push(model, name, name === defaultName);
      }
    }

    return out;
  },

  getCLICommand(): string {
    return 'picoclaw';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.picoclaw/config.json',
        '~/.picoclaw/auth.json',
      ],
      globPatterns: [
        '~/.picoclaw/skills/**',
      ],
      commands: [
        { id: 'picoclaw-which', cmd: 'which', args: ['picoclaw'], timeout: 3000 },
        { id: 'picoclaw-version', cmd: 'picoclaw', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.picoclaw',
        '~/.picoclaw/skills',
      ],
      envPrefixes: ['PICOCLAW_'],
      systemPaths: [],
      systemDirListings: [],
    };
  },
};

