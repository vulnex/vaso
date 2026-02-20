import { access, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { AgentAdapter } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import { loadConfig } from '../core/config-loader.js';

const CONFIG_FILENAMES = [
  'openclaw.json',
  'config.yaml',
  'config.json',
  'gateway.yaml',
  '.env',
];

function getSearchDirs(): string[] {
  const home = homedir();
  const dirs = [
    join(home, '.openclaw'),
    join(home, '.clawdbot'),
    join(home, '.moltbot'),
    '/etc/openclaw',
  ];

  if (process.env.OPENCLAW_HOME) {
    dirs.unshift(process.env.OPENCLAW_HOME);
  }

  return dirs;
}

async function dirExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export const openclawAdapter: AgentAdapter = {
  agent: 'openclaw',
  displayName: 'OpenClaw',

  async detect(): Promise<AgentInstallation | null> {
    const searchDirs = getSearchDirs();

    for (const dir of searchDirs) {
      if (!(await dirExists(dir))) continue;

      const configFiles = [];
      for (const filename of CONFIG_FILENAMES) {
        const filePath = join(dir, filename);
        try {
          const config = await loadConfig(filePath);
          configFiles.push(config);
        } catch {
          // File doesn't exist or can't be parsed
        }
      }

      if (configFiles.length === 0) continue;

      // Extract version and dirs from openclaw.json
      const mainConfig = configFiles.find(c => c.filePath.endsWith('openclaw.json'));
      const version = mainConfig?.data?.version as string | undefined;
      const workspace = mainConfig?.data?.workspace as string | undefined;
      const skillsDir = this.getSkillsDir(dir);

      // Merge all config data to extract gateway info
      const merged: Record<string, unknown> = {};
      for (const c of configFiles) {
        Object.assign(merged, c.data);
      }

      return {
        agent: 'openclaw',
        version,
        installDir: dir,
        configFiles,
        skillsDir,
        gateway: this.getGatewayInfo(merged),
      };
    }

    return null;
  },

  getConfigPaths(): string[] {
    const dirs = getSearchDirs();
    return dirs.flatMap(dir =>
      CONFIG_FILENAMES.map(f => join(dir, f))
    );
  },

  getSkillsDir(installDir: string): string | undefined {
    const candidates = [
      join(installDir, 'skills'),
      join(installDir, 'custom_skills'),
    ];
    // Return the first candidate (existence checked at runtime)
    return candidates[0];
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    const gw = config.gateway as Record<string, unknown> | undefined;
    if (!gw) return undefined;

    return {
      host: gw.host as string | undefined,
      port: gw.port as number | undefined,
      authMode: (gw.auth as Record<string, unknown>)?.mode as string | undefined,
      tls: gw.tls as boolean | undefined,
    };
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
      join(installDir, 'credentials.json'),
      join(installDir, 'auth.json'),
    ];
  },

  getCLICommand(): string {
    return 'openclaw';
  },
};
