import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { getNestedValue } from '../core/utils.js';
import { queryCliVersion } from './version-query.js';

const CONFIG_FILENAMES = [
  'config.toml',
  'auth-profiles.json',
];

export const zeroclawAdapter: AgentAdapter = {
  agent: 'zeroclaw',
  displayName: 'ZeroClaw',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const zeroDir = join(home, '.zeroclaw');
    const configFiles = [];

    for (const filename of CONFIG_FILENAMES) {
      const filePath = join(zeroDir, filename);
      if (await fs.access(filePath)) {
        try {
          configFiles.push(await loadConfig(filePath, fs));
        } catch {}
      }
    }

    // Also check for CLI binary
    const cliBinary = await findCLIBinary(home, fs);

    if (configFiles.length === 0 && !cliBinary) return [];

    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    // Extract version from TOML config, fallback to CLI
    const tomlConfig = configFiles.find(c => c.filePath.endsWith('.toml'));
    const version =
      (tomlConfig?.data?.version as string) ??
      ((tomlConfig?.data?.package as Record<string, unknown>)?.version as string) ??
      queryCliVersion(cliBinary ?? 'zeroclaw', fs);

    return [{
      agent: 'zeroclaw',
      installDir: zeroDir,
      configFiles,
      skillsDir: this.getSkillsDir(zeroDir),
      gateway: this.getGatewayInfo(merged),
      models: await this.getModels?.(configFiles, fs),
      cliBinary,
      version,
    }];
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    const zeroDir = join(home, '.zeroclaw');
    return CONFIG_FILENAMES.map(f => join(zeroDir, f));
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'workspace', 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    // Check [server] section first, then [gateway]
    const serverHost = getNestedValue(config, 'server.host') as string | undefined;
    const serverPort = getNestedValue(config, 'server.port') as number | undefined;
    if (serverHost || serverPort) {
      return {
        host: serverHost,
        port: serverPort ?? 3000,
      };
    }

    const gwHost = getNestedValue(config, 'gateway.host') as string | undefined;
    const gwPort = getNestedValue(config, 'gateway.port') as number | undefined;
    if (gwHost || gwPort) {
      return {
        host: gwHost,
        port: gwPort ?? 3000,
      };
    }

    return undefined;
  },

  getModels(configs: ParsedConfig[], fs?: FSProvider): ModelRef[] {
    // ZeroClaw uses top-level `default_provider` + `default_model` in
    // config.toml. Provider strings can carry an embedded base-URL in the
    // form "<name>:<url>" (e.g. "anthropic-custom:https://api.z.ai/...").
    // Additional models surface via `model_routes = []` and
    // `[reliability.model_fallbacks]`. Process env: ZEROCLAW_PROVIDER /
    // ZEROCLAW_MODEL override the file values.
    const out: ModelRef[] = [];
    const seen = new Set<string>();

    const stripUrl = (provider: string | undefined): string | undefined => {
      if (!provider) return undefined;
      const colon = provider.indexOf(':');
      return colon !== -1 ? provider.slice(0, colon) : provider;
    };

    const push = (rawId: unknown, rawProvider?: unknown, via?: string): void => {
      if (typeof rawId !== 'string' || !rawId.trim()) return;
      const trimmed = rawId.trim();
      let provider =
        typeof rawProvider === 'string' && rawProvider.trim()
          ? stripUrl(rawProvider.trim())
          : undefined;
      let id = trimmed;
      if (!provider && trimmed.includes('/')) {
        const slash = trimmed.indexOf('/');
        provider = trimmed.slice(0, slash);
        id = trimmed.slice(slash + 1);
      }
      const key = `${provider ?? ''}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...(provider ? { provider } : {}), ...(via ? { via } : {}) });
    };

    const toml = configs.find(c => c.filePath.endsWith('config.toml'));
    if (toml) {
      push(toml.data?.default_model, toml.data?.default_provider);

      // model_routes: array of { name, provider, model } or similar shapes
      const routes = toml.data?.model_routes;
      if (Array.isArray(routes)) {
        for (const r of routes) {
          const route = r as Record<string, unknown> | undefined;
          const name = (route?.name as string | undefined) ?? (route?.id as string | undefined);
          push(route?.model, route?.provider, name);
        }
      }

      // [reliability.model_fallbacks]: { <key>: <model_id_or_array> }
      const reliability = toml.data?.reliability as Record<string, unknown> | undefined;
      const fallbacks = reliability?.model_fallbacks as Record<string, unknown> | undefined;
      if (fallbacks) {
        for (const [slot, val] of Object.entries(fallbacks)) {
          if (typeof val === 'string') {
            push(val, undefined, `fallback:${slot}`);
          } else if (Array.isArray(val)) {
            for (const v of val) {
              if (typeof v === 'string') push(v, undefined, `fallback:${slot}`);
            }
          }
        }
      }
    }

    if (out.length === 0 && fs?.getEnv) {
      push(fs.getEnv('ZEROCLAW_MODEL'), fs.getEnv('ZEROCLAW_PROVIDER'), 'ZEROCLAW_MODEL');
    }

    return out;
  },

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, 'config.toml'),
      join(installDir, 'auth-profiles.json'),
      join(installDir, '.secret_key'),
    ];
  },

  getCLICommand(): string {
    return 'zeroclaw';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.zeroclaw/config.toml',
        '~/.zeroclaw/auth-profiles.json',
        '~/.zeroclaw/.secret_key',
      ],
      globPatterns: [
        '~/.zeroclaw/workspace/skills/**',
      ],
      commands: [
        { id: 'zeroclaw-which', cmd: 'which', args: ['zeroclaw'], timeout: 3000 },
        { id: 'zeroclaw-version', cmd: 'zeroclaw', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.zeroclaw',
        '~/.zeroclaw/workspace',
        '~/.zeroclaw/workspace/skills',
        '~/.cargo/bin',
      ],
      envPrefixes: ['ZEROCLAW_'],
      systemPaths: [],
      systemDirListings: [],
    };
  },
};

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  const cargoPath = join(home, '.cargo', 'bin', 'zeroclaw');
  if (await fs.access(cargoPath)) return cargoPath;

  try {
    const result = fs.execSync('which', ['zeroclaw'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}

  return undefined;
}
