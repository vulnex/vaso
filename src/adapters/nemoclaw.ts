import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { queryCliVersion } from './version-query.js';

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
    if (await fs.access(sandboxesPath)) {
      try {
        configFiles.push(await loadConfig(sandboxesPath, fs));
      } catch {}
    }

    // Load credentials.json
    const credPath = join(nemoDir, 'credentials.json');
    if (await fs.access(credPath)) {
      try {
        configFiles.push(await loadConfig(credPath, fs));
      } catch {}
    }

    // Load config.json if present
    const configPath = join(nemoDir, 'config.json');
    if (await fs.access(configPath)) {
      try {
        configFiles.push(await loadConfig(configPath, fs));
      } catch {}
    }

    // Load state file for deployment info
    const statePath = join(nemoDir, 'state', 'nemoclaw.json');
    if (await fs.access(statePath)) {
      try {
        configFiles.push(await loadConfig(statePath, fs));
      } catch {}
    }

    // Directory exists but no config files means NemoClaw is not actually installed
    if (configFiles.length === 0) return [];

    // Extract version from CLI or state
    let version = queryCliVersion('nemoclaw', fs);
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
      version,
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
      ],
      globPatterns: [
        '~/.nemoclaw/blueprints/**',
        '~/.nemoclaw/policies/**',
      ],
      commands: [
        { id: 'nemoclaw-which', cmd: 'which', args: ['nemoclaw'], timeout: 3000 },
        { id: 'nemoclaw-version', cmd: 'nemoclaw', args: ['--version'], timeout: 3000 },
      ],
      directoryListings: [
        '~/.nemoclaw',
        '~/.nemoclaw/state',
        '~/.nemoclaw/blueprints',
        '~/.nemoclaw/policies',
      ],
      envPrefixes: ['NEMOCLAW_'],
      systemPaths: [],
      systemDirListings: [],
    };
  },
};

