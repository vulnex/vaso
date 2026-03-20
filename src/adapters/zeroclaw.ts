import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { getNestedValue } from '../core/utils.js';

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
        { id: 'zeroclaw-version', cmd: 'zeroclaw', args: ['--version'], timeout: 3000 },
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

function queryCliVersion(binary: string, fs: FSProvider): string | undefined {
  try {
    const output = fs.execSync(binary, ['--version'], { timeout: 3000 }).trim();
    const m = /(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)/.exec(output);
    return m?.[1];
  } catch {
    return undefined;
  }
}

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  const cargoPath = join(home, '.cargo', 'bin', 'zeroclaw');
  if (await fs.access(cargoPath)) return cargoPath;

  try {
    const result = fs.execSync('which', ['zeroclaw'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}

  return undefined;
}
