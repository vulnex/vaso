import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { getUserHomeDirs } from './openclaw.js';

const CODEX_DIR_NAME = '.codex';
const CONFIG_FILES = ['config.toml', 'auth.json'];

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/codex',
  '/opt/homebrew/bin/codex',
  '/usr/bin/codex',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/codex',
  '.npm-global/bin/codex',
  '.volta/bin/codex',
  '.bun/bin/codex',
  '.cargo/bin/codex',
];

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join(home, rel);
    if (await fs.access(p)) return p;
  }
  try {
    const result = fs.execSync('which', ['codex'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}
  return undefined;
}

function queryCliVersion(binary: string | undefined, fs: FSProvider): string | undefined {
  if (!binary) return undefined;
  try {
    const output = fs.execSync(binary, ['--version'], { timeout: 3000 }).trim();
    const m = /(\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.]+)?)/.exec(output);
    if (m?.[1]) return m[1];
  } catch {}
  return undefined;
}

export const codexAdapter: AgentAdapter = {
  agent: 'codex',
  displayName: 'Codex',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const codexDir = join(home, CODEX_DIR_NAME);
      const cliBinary = await findCLIBinary(home, fs);
      const hasCodexDir = await fs.access(codexDir);

      if (!hasCodexDir && !cliBinary) continue;

      const configFiles = [];
      if (hasCodexDir) {
        for (const filename of CONFIG_FILES) {
          const filePath = join(codexDir, filename);
          if (!(await fs.access(filePath))) continue;
          try {
            configFiles.push(await loadConfig(filePath, fs));
          } catch {}
        }
      }

      const version = queryCliVersion(cliBinary, fs);

      installations.push({
        agent: 'codex',
        version,
        installDir: codexDir,
        configFiles,
        user: options?.allUsers ? user : undefined,
        cliBinary,
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    const codexDir = join(home, CODEX_DIR_NAME);
    return CONFIG_FILES.map(f => join(codexDir, f));
  },

  getSkillsDir(_installDir: string): string | undefined {
    return undefined;
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'instructions.md'),
      join(installDir, 'AGENTS.md'),
      join(installDir, 'history.jsonl'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, 'auth.json'),
    ];
  },

  getCLICommand(): string {
    return 'codex';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.codex/config.toml',
        '~/.codex/auth.json',
        '~/.codex/instructions.md',
        '~/.codex/AGENTS.md',
      ],
      globPatterns: [],
      commands: [
        { id: 'codex-which', cmd: 'which', args: ['codex'], timeout: 3000 },
        { id: 'codex-version', cmd: 'codex', args: ['--version'], timeout: 3000 },
      ],
      directoryListings: [
        '~/.codex',
      ],
      envPrefixes: ['CODEX_', 'OPENAI_'],
      systemPaths: SYSTEM_CLI_PATHS,
      systemDirListings: [],
    };
  },
};
