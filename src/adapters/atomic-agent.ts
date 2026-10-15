import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { getUserHomeDirs } from './openclaw.js';
import { discoverCliInstalls } from './cli-installs.js';
import { queryCliVersion } from './version-query.js';

// Installer (`curl -fsSL https://atomicagent.io/install | sh`) drops a Node SEA
// binary plus the `atag` alias symlink into ~/.local/bin.
const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/atomic-agent',
  '/opt/homebrew/bin/atomic-agent',
  '/usr/bin/atomic-agent',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/atomic-agent',
];

/** `<stateDir>/config.json` holds settings; `<stateDir>/.env` holds secrets
 *  for providers, skills and channels (upstream keeps them out of config.json). */
const CONFIG_FILENAMES = ['config.json', '.env'];

/**
 * Atomic Agent keeps everything under one state dir: `~/.atomic-agent`, or
 * `$ATOMIC_AGENT_STATE_DIR` when set. The override is read from the scanned
 * host's environment (the snapshot's env on --host scans).
 */
export function atomicAgentStateDir(home: string, fs: FSProvider): string {
  const override = fs.getEnv('ATOMIC_AGENT_STATE_DIR')?.trim();
  return override || join(home, '.atomic-agent');
}

export const atomicAgentAdapter: AgentAdapter = {
  agent: 'atomic-agent',
  displayName: 'Atomic Agent',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const stateDir = atomicAgentStateDir(home, fs);
      if (!(await fs.access(stateDir))) continue;

      const configFiles: ParsedConfig[] = [];
      for (const name of CONFIG_FILENAMES) {
        const filePath = join(stateDir, name);
        try {
          {
            const loaded = await loadConfigIfPresent(filePath, fs);
            if (loaded) configFiles.push(loaded);
          }
        } catch {}
      }
      // config.json is written on first run; a bare state dir is not an install.
      if (configFiles.length === 0) continue;

      const installs = await discoverCliInstalls(home, fs, {
        names: ['atomic-agent'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        version: (bin, canExec) => (canExec ? queryCliVersion(bin, fs, { timeoutMs: 10000 }) : undefined),
      });
      const cliBinary = installs.primary?.path;
      // `atomic-agent --version` prints "atomic-agent 0.6.5"; the SEA binary
      // starts Node, so allow more than a native binary would need.
      const version = installs.primary?.version;

      const configJson = configFiles.find(c => c.filePath.endsWith('config.json'));
      installations.push({
        agent: 'atomic-agent',
        version,
        installDir: stateDir,
        configFiles,
        skillsDir: this.getSkillsDir(stateDir),
        gateway: this.getGatewayInfo(configJson?.data ?? {}),
        models: await this.getModels?.(configFiles, fs),
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const stateDir = atomicAgentStateDir(fs.homedir(), fs);
    return CONFIG_FILENAMES.map(f => join(stateDir, f));
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    // The HTTP service (`atomic-agent serve --host --port --api-key`) is
    // configured only by CLI flags, never persisted — nothing to read here.
    return undefined;
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    const out: ModelRef[] = [];
    const seen = new Set<string>();
    const push = (rawId: unknown, provider?: string, via?: string): void => {
      if (typeof rawId !== 'string' || !rawId.trim()) return;
      const id = rawId.trim();
      const key = `${provider ?? ''}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...(provider ? { provider } : {}), ...(via ? { via } : {}) });
    };

    const config = configs.find(c => c.filePath.endsWith('config.json'))?.data;
    if (!config) return out;

    // Cloud/remote providers: llm.providers[] keyed by id; the active one
    // first, then the rest as named slots.
    const llm = config.llm as Record<string, unknown> | undefined;
    const providers = Array.isArray(llm?.providers)
      ? (llm!.providers as unknown[]).filter((p): p is Record<string, unknown> => !!p && typeof p === 'object')
      : [];
    const active = typeof llm?.activeTextProvider === 'string' ? llm.activeTextProvider : undefined;
    const ordered = [
      ...providers.filter(p => p.id === active),
      ...providers.filter(p => p.id !== active),
    ];
    for (const p of ordered) {
      const provider = typeof p.kind === 'string' ? p.kind : undefined;
      const via = p.id === active ? undefined : (typeof p.id === 'string' ? p.id : undefined);
      push(p.model ?? p.defaultChatModel, provider, via);
    }

    // Managed local model (llama.cpp): localModels.managed.modelId.
    const local = config.localModels as Record<string, unknown> | undefined;
    const managed = local?.managed as Record<string, unknown> | undefined;
    push(managed?.modelId, 'llama-server', out.length > 0 ? 'localModels' : undefined);

    return out;
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'memory.sqlite'),
      join(installDir, 'sessions.sqlite'),
      join(installDir, 'tasks.sqlite'),
      join(installDir, 'traces'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return [join(installDir, '.env')];
  },

  getCLICommand(): string {
    return 'atomic-agent';
  },

  // Atomic Agent's privilege gradient: untrusted input (web pages, HTTP
  // service/webhooks, channels) → approval ladder → tool fan-out (shell, HTTP,
  // MCP, skills, subscription CLIs) → host filesystem, secrets and remote
  // endpoints. Inversions: a raised ladder (AT-001), unapproved HTTP egress
  // (AT-003), pure_read MCP trust (AT-006), secretless webhooks (AT-008) and
  // an un-locked-down subscription CLI (AT-009).
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Web Pages / Webhooks / Channels', trustLevel: 0 },
        { id: 'approval', label: 'Approval Ladder', trustLevel: 1 },
        { id: 'tools', label: 'Shell + HTTP + MCP + Skills', trustLevel: 2 },
        { id: 'host', label: 'Host FS + Secrets + Endpoints', trustLevel: 3 },
      ],
      components: [
        {
          id: 'inbound',
          label: 'Untrusted Input (serve API, webhooks, browsed pages)',
          zone: 'net',
          guardCheckIds: ['AT-008'],
        },
        {
          id: 'approval-ladder',
          label: 'Approval Ladder + Read Scope',
          zone: 'approval',
          guardCheckIds: ['AT-001', 'AT-002', 'AT-003'],
        },
        {
          id: 'tool-fanout',
          label: 'Shell / HTTP / MCP / Subscription CLI',
          zone: 'tools',
          guardCheckIds: ['AT-006', 'AT-007', 'AT-009'],
        },
        {
          id: 'host',
          label: 'State Dir (.env, memory, traces) + Inference Endpoints',
          zone: 'host',
          guardCheckIds: ['AT-004', 'AT-005', 'AT-010', 'AT-011'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'approval-ladder', kind: 'data' },
        { from: 'approval-ladder', to: 'tool-fanout', kind: 'control' },
        { from: 'tool-fanout', to: 'host', kind: 'data' },
        {
          from: 'inbound',
          to: 'tool-fanout',
          label: 'approval bypass',
          triggerCheckIds: ['AT-001', 'AT-003', 'AT-006', 'AT-008'],
        },
        {
          from: 'tool-fanout',
          to: 'host',
          label: 'vendor CLI outside the ladder',
          triggerCheckIds: ['AT-009'],
        },
      ],
    };
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.atomic-agent/config.json',
        '~/.atomic-agent/.env',
        // User-relative CLI install location — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.local/bin/atomic-agent',
      ],
      globPatterns: [
        '~/.atomic-agent/skills/**',
      ],
      // Memory, session transcripts, task payloads and tool traces are private
      // data — permissions only, content never shipped.
      metadataGlobPatterns: [
        '~/.atomic-agent/*.sqlite',
        '~/.atomic-agent/traces/*',
        // Session tokens and channel session state (AT-005/AT-011)
        '~/.atomic-agent/atomic-mail/session.json',
        '~/.atomic-agent/*-session.json',
        '~/.atomic-agent/*-sessions.json',
      ],
      commands: [
        { id: 'atomic-agent-which', cmd: 'which', args: ['atomic-agent'], timeout: 3000 },
        { id: 'atomic-agent-version', cmd: 'atomic-agent', args: ['--version'], timeout: 10000 },
      ],
      directoryListings: [
        '~/.atomic-agent',
        '~/.atomic-agent/skills',
      ],
      envPrefixes: ['ATOMIC_AGENT_'],
      systemPaths: SYSTEM_CLI_PATHS,
      systemDirListings: [],
    };
  },
};
