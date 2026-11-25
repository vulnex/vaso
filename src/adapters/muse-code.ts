import { basename, dirname, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, CliInstall, GatewayInfo, ModelRef, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { getUserHomeDirs } from './openclaw.js';
import { discoverCliInstalls } from './cli-installs.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { withoutLoadedConfigs, scanCwd } from './project-configs.js';
import { envPath, xdgPath } from './env-path.js';

/**
 * Meta Muse Code (`muse`), Meta's terminal coding agent — not the Muse
 * desktop app (`meta-muse`). Layout verified against 1.4.25 (R9361.1) on
 * Linux with the CLI's own echo provider:
 *
 *   $XDG_CONFIG_HOME/muse (else ~/.config/muse — the same on macOS)
 *     settings.json   schema_version 1; permissions (named permission
 *                     profiles + default_profile), mcpServers, hooks,
 *                     endpoint_transport, telemetry, context, skills, …
 *     trust.json      { projects: { <exact path>: { decision: "trusted" } } }
 *     auth.json       provider API keys (0600; $MUSE_AUTH_PATH relocates it)
 *     skills/<id>/    user skills
 *   $XDG_DATA_HOME/muse (else ~/.local/share/muse)
 *     sessions/YYYY/MM/DD/<id>/session.jsonl, cron.db …  full transcripts
 *     session-index.db, tui-history.jsonl, local-tracing/
 *   <workspace>: .mcp.json, .muse/hooks.json, .agents/skills/, AGENTS.md —
 *     MCP servers, hooks and skills load only once that exact directory is
 *     trusted (trust is not inherited by subdirectories).
 *
 * Installed by a bash launcher (`muse`, usually ~/.local/bin) that checks
 * for updates, may start a device-code login and downloads
 * `muse-bin-<version>` next to itself. It is never run: the version comes
 * from `.muse-version` beside it.
 */
export const MUSE_CODE_SETTINGS = 'settings.json';
export const MUSE_CODE_TRUST = 'trust.json';
export const MUSE_CODE_AUTH = 'auth.json';
export const MUSE_CODE_PROJECT_HOOKS = join('.muse', 'hooks.json');
export const MUSE_CODE_PROJECT_MCP = '.mcp.json';

const LAUNCHER_MARKER = 'muse-code/launcher';
const VERSION_FILE = '.muse-version';
const SYSTEM_CLI_PATHS = ['/usr/local/bin/muse', '/opt/homebrew/bin/muse'];
const USER_CLI_RELATIVE_PATHS = [join('.local', 'bin', 'muse')];
const PROJECT_SKILL_DIR = join('.agents', 'skills');

/** Only the scanning user's environment is observable; other homes use the defaults. */
function ownEnv(home: string, fs: FSProvider, name: string): string | undefined {
  return home === fs.homedir() ? xdgPath(fs.getEnv(name)) : undefined;
}

export function museConfigDir(home: string, fs: FSProvider): string {
  return join(ownEnv(home, fs, 'XDG_CONFIG_HOME') ?? join(home, '.config'), 'muse');
}

export function museDataDir(home: string, fs: FSProvider): string {
  return join(ownEnv(home, fs, 'XDG_DATA_HOME') ?? join(home, '.local', 'share'), 'muse');
}

/** auth.json, or where $MUSE_AUTH_PATH puts it (scanning user only). */
export function museAuthPath(home: string, fs: FSProvider): string {
  const override = home === fs.homedir() ? envPath(fs.getEnv('MUSE_AUTH_PATH'), home) : undefined;
  return override ?? join(museConfigDir(home, fs), MUSE_CODE_AUTH);
}

/**
 * The Muse Code launcher's version: `.muse-version` beside it names the
 * `muse-bin-<version>` it runs (e.g. `1.4.25-R9361.1`, reported as 1.4.25).
 * Any other program called `muse` lacks the launcher marker → undefined.
 */
async function launcherVersion(bin: string, fs: FSProvider): Promise<{ muse: boolean; version?: string }> {
  let real = bin;
  try {
    real = await fs.realpath(bin);
  } catch {}
  let head: string;
  try {
    head = (await fs.readFile(real)).slice(0, 4096);
  } catch {
    return { muse: false };
  }
  if (!head.includes(LAUNCHER_MARKER)) return { muse: false };
  try {
    const raw = (await fs.readFile(join(dirname(real), VERSION_FILE))).trim();
    const m = /^(\d+\.\d+\.\d+)(?:-R[\d.]+)?$/.exec(raw);
    return { muse: true, version: m?.[1] };
  } catch {
    return { muse: true };
  }
}

async function loadJson(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  const parsed = await loadConfigIfPresent(filePath, fs);
  return parsed && parsed.data && typeof parsed.data === 'object' && !Array.isArray(parsed.data) ? parsed : undefined;
}

/** Muse launchers among the `muse` programs found, primary first. */
async function museInstalls(home: string, fs: FSProvider): Promise<{ primary?: CliInstall; others: CliInstall[] }> {
  const verdicts = new Map<string, { muse: boolean; version?: string }>();
  const found = await discoverCliInstalls(home, fs, {
    names: ['muse'],
    systemPaths: SYSTEM_CLI_PATHS,
    userRelPaths: USER_CLI_RELATIVE_PATHS,
    nvm: false,
    async version(bin) {
      const v = await launcherVersion(bin, fs);
      verdicts.set(bin, v);
      return v.version;
    },
  });
  const all = [found.primary, ...found.others].filter((i): i is CliInstall => !!i && verdicts.get(i.path)?.muse === true);
  return { primary: all[0], others: all.slice(1) };
}

export const museCodeAdapter: AgentAdapter = {
  agent: 'muse-code',
  displayName: 'Meta Muse Code',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const configDir = museConfigDir(home, fs);
      const installs = await museInstalls(home, fs);
      const hasConfig = await fs.access(configDir);
      const hasData = await fs.access(museDataDir(home, fs));
      // Positive signal required: the launcher, or Muse's own config / data dir
      if (!installs.primary && !hasConfig && !hasData) continue;

      const configFiles: ParsedConfig[] = [];
      for (const file of [MUSE_CODE_SETTINGS, MUSE_CODE_TRUST]) {
        const parsed = await loadJson(join(configDir, file), fs);
        if (parsed) configFiles.push(parsed);
      }
      const skillsDir = join(configDir, 'skills');
      const hasSkills = await fs.access(skillsDir);
      installations.push({
        agent: 'muse-code',
        version: installs.primary?.version,
        installDir: configDir,
        configFiles,
        skillsDir: hasSkills ? skillsDir : undefined,
        skillsDirs: hasSkills ? [skillsDir] : undefined,
        user: options?.allUsers ? user : undefined,
        cliBinary: installs.primary?.path,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
        models: await this.getModels?.(configFiles, fs),
      });
    }

    // Project scope: the workspace Muse runs in (its MCP servers, hooks and
    // skills load once that directory is trusted)
    const cwd = scanCwd(fs);
    if (!cwd || installations.length === 0) return installations;
    const projectConfigs: ParsedConfig[] = [];
    for (const rel of [MUSE_CODE_PROJECT_MCP, MUSE_CODE_PROJECT_HOOKS]) {
      const parsed = await loadJson(join(cwd, rel), fs);
      if (parsed) projectConfigs.push(parsed);
    }
    const configs = await withoutLoadedConfigs(projectConfigs, installations, fs);
    const skills = join(cwd, PROJECT_SKILL_DIR);
    const hasSkills = await fs.access(skills);
    if (configs.length > 0 || hasSkills) {
      installations.push({
        agent: 'muse-code',
        agentName: `project:${basename(cwd)}`,
        installDir: join(cwd, '.muse'),
        configFiles: configs,
        skillsDir: hasSkills ? skills : undefined,
        skillsDirs: hasSkills ? [skills] : undefined,
        profile: 'project',
      });
    }
    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const dir = museConfigDir(fs.homedir(), fs);
    return [join(dir, MUSE_CODE_SETTINGS), join(dir, MUSE_CODE_TRUST)];
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getMemoryFiles(installDir: string): string[] {
    // Project rules: <workspace>/AGENTS.md, else CLAUDE.md (MSC-012)
    return basename(installDir) === '.muse' ? [join(dirname(installDir), 'AGENTS.md')] : [];
  },

  getCredentialPaths(installDir: string): string[] {
    return basename(installDir) === '.muse' ? [] : [join(installDir, MUSE_CODE_AUTH)];
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    // Top-level `model` (provider `provider`, default meta)
    const settings = configs.find(c => basename(c.filePath) === MUSE_CODE_SETTINGS);
    const model = settings?.data.model;
    if (typeof model !== 'string' || !model.trim()) return [];
    const provider = typeof settings?.data.provider === 'string' && settings.data.provider.trim() ? settings.data.provider : 'meta';
    return [{ id: model, provider, via: 'model' }];
  },

  getCLICommand(): string {
    return 'muse';
  },

  getProbeManifest(): ProbeManifest {
    const config = '~/.config/muse';
    const data = '~/.local/share/muse';
    return {
      filePaths: [
        `${config}/${MUSE_CODE_SETTINGS}`,
        `${config}/${MUSE_CODE_TRUST}`,
        // The launcher (identified by its marker) and the version it runs
        ...USER_CLI_RELATIVE_PATHS.map(p => `~/${p}`),
        `~/.local/bin/${VERSION_FILE}`,
        ...SYSTEM_CLI_PATHS,
        ...SYSTEM_CLI_PATHS.map(p => join(dirname(p), VERSION_FILE)),
      ],
      globPatterns: [
        // User skills — SKL/IOC checks read them
        `${config}/skills/**`,
      ],
      // Credentials and conversation data: existence and permissions only,
      // never content
      metadataGlobPatterns: [
        `${config}/${MUSE_CODE_AUTH}`,
        `${data}/session-index.db*`,
        `${data}/tui-history.jsonl`,
        `${data}/sessions/**`,
        `${data}/local-tracing/**`,
        `${data}/runtime/**`,
        `~/.local/bin/muse-bin-*`,
      ],
      commands: [
        { id: 'muse-which', cmd: 'which', args: ['muse'], timeout: 3000 },
      ],
      directoryListings: [config, data, `${data}/sessions`],
      // Named, non-secret variables only (MUSE_CUSTOM_HEADERS can carry tokens)
      envPrefixes: ['MUSE_PERMISSION_PROFILE_FAIL_OPEN', 'MUSE_CUA_DEV_POLICY', 'MUSE_DISABLE_APPROVAL_JUDGE', 'MUSE_AUTH_PATH'],
      systemPaths: SYSTEM_CLI_PATHS,
      systemDirListings: [],
    };
  },
};
