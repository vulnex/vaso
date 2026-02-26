import { join } from 'node:path';
import { homedir } from 'node:os';
import { execFileSync } from 'node:child_process';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import { loadConfig } from '../core/config-loader.js';
import { pathExists } from '../core/utils.js';
import { getNestedValue } from '../core/utils.js';

const CONFIG_FILENAMES = [
  'config.toml',
  'auth-profiles.json',
];

export const zeroclawAdapter: AgentAdapter = {
  agent: 'zeroclaw',
  displayName: 'ZeroClaw',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const home = homedir();
    const zeroDir = join(home, '.zeroclaw');
    const configFiles = [];

    for (const filename of CONFIG_FILENAMES) {
      const filePath = join(zeroDir, filename);
      if (await pathExists(filePath)) {
        try {
          configFiles.push(await loadConfig(filePath));
        } catch {}
      }
    }

    // Also check for CLI binary
    const cliBinary = await findCLIBinary(home);

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
      queryCliVersion(cliBinary ?? 'zeroclaw');

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
    const home = homedir();
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
};

function queryCliVersion(binary: string): string | undefined {
  try {
    const output = execFileSync(binary, ['--version'], {
      encoding: 'utf-8',
      timeout: 3000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    const m = /(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)/.exec(output);
    return m?.[1];
  } catch {
    return undefined;
  }
}

async function findCLIBinary(home: string): Promise<string | undefined> {
  const cargoPath = join(home, '.cargo', 'bin', 'zeroclaw');
  if (await pathExists(cargoPath)) return cargoPath;

  try {
    const result = execFileSync('which', ['zeroclaw'], {
      encoding: 'utf-8',
      timeout: 3000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    if (result) return result;
  } catch {}

  return undefined;
}
