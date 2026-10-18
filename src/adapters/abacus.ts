import { basename, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { getUserHomeDirs } from './openclaw.js';
import { discoverCliInstalls, nodeManagerPackageJsonGlobs, retainedVersionGlobs, type RetainedVersionsDir } from './cli-installs.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { withoutLoadedConfigs, scanCwd } from './project-configs.js';

/**
 * Abacus.AI CLI (`abacusai`, alias `abacus`) and AbacusAI Desktop. Both share
 * ~/.abacusai: the CLI's config/MCP files and encrypted keystore, and the
 * desktop app's per-mode MCP and agent configs under ~/.abacusai/desktop.
 * Layout taken from the 2.10.2 CLI binary and the 2.2.4 desktop app.
 */
export const ABACUS_DIR = '.abacusai';

// Official installer target; npm installs (@abacus-ai/cli) are found through
// the Node version manager roots.
const NPM_PACKAGE_NAME = '@abacus-ai/cli';
const USER_CLI_RELATIVE_PATHS = [join(ABACUS_DIR, 'bin', 'abacusai')];

// The desktop app ships its own CLI copy, used by its agent: the .deb installs
// to /opt/AbacusAI Desktop, the macOS .pkg to /Applications/AbacusAI Desktop.app.
const DESKTOP_APP_LINUX = '/opt/AbacusAI Desktop';
const DESKTOP_APP_MAC = '/Applications/AbacusAI Desktop.app';
const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/abacusai',
  '/opt/homebrew/bin/abacusai',
  ...['linux-x64', 'linux-arm64'].map(p => `${DESKTOP_APP_LINUX}/resources/native/cli/${p}/abacusai`),
  ...['darwin-arm64', 'darwin-x64'].map(p => `${DESKTOP_APP_MAC}/Contents/Resources/native/cli/${p}/abacusai`),
];

// The updater keeps each version at ~/.abacusai/versions/<version>/abacusai.
const RETAINED_VERSIONS: RetainedVersionsDir[] = [{ dir: join(ABACUS_DIR, 'versions'), binary: 'abacusai' }];

// User scope: config.json (settings, `mcpServers` as an array) and mcp.json
// (`mcpServers` map). The desktop app keeps one MCP file and one agent config
// per mode (`code`, `cowork`) and hands them to its CLI.
const USER_CONFIG_FILES = ['config.json', 'mcp.json'];
const DESKTOP_MODES = ['code', 'cowork'];
const DESKTOP_CONFIG_FILES = DESKTOP_MODES.flatMap(m => [`mcp-${m}.json`, `agent-config-${m}.json`]);

// Project scope (<workspace>/.abacusai): same schema as the user files, but the
// CLI drops escalating keys unless the workspace is trusted.
const PROJECT_CONFIG_FILES = [join(ABACUS_DIR, 'config.json'), join(ABACUS_DIR, 'mcp.json')];

// Skill roots the CLI loads: <name>/SKILL.md beneath each.
const USER_SKILL_DIRS = [join(ABACUS_DIR, 'skills'), join('.agents', 'skills')];
const PROJECT_SKILL_DIRS = [join(ABACUS_DIR, 'skills'), join('.agents', 'skills')];

const NPM_SHIM = /[\\/]node_modules[\\/]@abacus-ai[\\/]cli[\\/]/;

/**
 * Version of one CLI copy. The native (bun-compiled) binary answers
 * `--version` ("Abacus.AI CLI version 2.10.2") without side effects. The npm
 * package is a Node shim that, when its binary cache under $HOME is missing —
 * always the case under the throwaway HOME used for version queries —
 * downloads and installs the ~130 MB binary; it is never executed, and its
 * version comes from @abacus-ai/cli's package.json.
 */
async function abacusCliVersion(bin: string, canExec: boolean, fs: FSProvider): Promise<string | undefined> {
  let real = bin;
  try {
    real = await fs.realpath(bin);
  } catch {}
  if (NPM_SHIM.test(real)) return readPackageVersion(bin, fs, NPM_PACKAGE_NAME);
  return canExec ? queryCliVersion(bin, fs, { timeoutMs: 5000 }) : undefined;
}

/** Electron user-data dir of AbacusAI Desktop (cookies, provider key stores). */
export function abacusDesktopDataDir(home: string, fs: FSProvider): string {
  if (fs.platform === 'darwin') return join(home, 'Library', 'Application Support', 'AbacusAI Desktop');
  if (fs.platform === 'win32') {
    const appData = fs.getEnv('APPDATA')?.trim();
    return join(appData || join(home, 'AppData', 'Roaming'), 'AbacusAI Desktop');
  }
  const xdg = fs.getEnv('XDG_CONFIG_HOME')?.trim();
  return join(xdg || join(home, '.config'), 'AbacusAI Desktop');
}

async function loadJson(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  // The shared loader parses JSON/JSONC/JSON5 and reports an unreadable or
  // unparseable file as CONFIG-LOAD instead of dropping it silently
  const parsed = await loadConfigIfPresent(filePath, fs);
  return parsed && parsed.data && typeof parsed.data === 'object' && !Array.isArray(parsed.data) ? parsed : undefined;
}

async function existingDirs(base: string, rels: string[], fs: FSProvider): Promise<string[]> {
  const found: string[] = [];
  for (const rel of rels) {
    const dir = join(base, rel);
    if (await fs.access(dir)) found.push(dir);
  }
  return found;
}

export const abacusAdapter: AgentAdapter = {
  agent: 'abacus',
  displayName: 'Abacus.AI CLI / Desktop',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];
    const desktopApp = fs.platform === 'darwin'
      ? (await fs.access(DESKTOP_APP_MAC) ? DESKTOP_APP_MAC : undefined)
      : (await fs.access(DESKTOP_APP_LINUX) ? DESKTOP_APP_LINUX : undefined);

    for (const { home, user } of userDirs) {
      const configDir = join(home, ABACUS_DIR);
      const installs = await discoverCliInstalls(home, fs, {
        names: ['abacusai', 'abacus'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        retainedVersions: RETAINED_VERSIONS,
        version: (bin, canExec) => abacusCliVersion(bin, canExec, fs),
      });
      const cliBinary = installs.primary?.path;
      const hasConfigDir = await fs.access(configDir);
      const hasDesktopData = await fs.access(abacusDesktopDataDir(home, fs));

      // Positive signal required: state dir, desktop user data, or a CLI binary.
      if (!hasConfigDir && !hasDesktopData && !cliBinary) continue;

      const configFiles: ParsedConfig[] = [];
      if (hasConfigDir) {
        const paths = [
          ...USER_CONFIG_FILES.map(f => join(configDir, f)),
          ...DESKTOP_CONFIG_FILES.map(f => join(configDir, 'desktop', f)),
        ];
        for (const filePath of paths) {
          const parsed = await loadJson(filePath, fs);
          if (parsed) configFiles.push(parsed);
        }
      }

      const skillsDirs = await existingDirs(home, USER_SKILL_DIRS, fs);
      installations.push({
        agent: 'abacus',
        version: installs.primary?.version,
        installDir: configDir,
        configFiles,
        skillsDir: skillsDirs[0],
        skillsDirs: skillsDirs.length > 0 ? skillsDirs : undefined,
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
        appBundle: desktopApp,
        models: await this.getModels?.(configFiles, fs),
      });
    }

    // Project scope: the workspace is the directory the CLI runs in.
    const cwd = scanCwd(fs);
    if (!cwd) return installations;
    const projectConfigs: ParsedConfig[] = [];
    for (const rel of PROJECT_CONFIG_FILES) {
      const filePath = join(cwd, rel);
      const parsed = await loadJson(filePath, fs);
      if (parsed) projectConfigs.push(parsed);
    }
    const userSkillDirs = new Set(installations.flatMap(i => i.skillsDirs ?? []));
    const projectSkillDirs = (await existingDirs(cwd, PROJECT_SKILL_DIRS, fs)).filter(d => !userSkillDirs.has(d));
    const configs = await withoutLoadedConfigs(projectConfigs, installations, fs);
    if (configs.length > 0 || projectSkillDirs.length > 0) {
      installations.push({
        agent: 'abacus',
        agentName: `project:${basename(cwd)}`,
        installDir: join(cwd, ABACUS_DIR),
        configFiles: configs,
        skillsDir: projectSkillDirs[0],
        skillsDirs: projectSkillDirs.length > 0 ? projectSkillDirs : undefined,
        profile: 'project',
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    return USER_CONFIG_FILES.map(f => join(home, ABACUS_DIR, f));
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getMemoryFiles(installDir: string): string[] {
    // <workspace>/.abacusai/AGENTS.md; ABA-012 also covers the workspace-root AGENTS.md
    return [join(installDir, 'AGENTS.md')];
  },

  getCredentialPaths(installDir: string): string[] {
    // AES-GCM store whose key derives from hostname + $USER — readable means
    // decryptable. Only the user installation has one.
    return [join(installDir, 'keystore.enc')];
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    // `model` / `smallModel`: a bare Abacus.AI llmName or `providerId/modelId`
    // for a configured local provider. Project files override user ones.
    const models: ModelRef[] = [];
    const seen = new Set<string>();
    for (const config of [...configs].reverse()) {
      for (const key of ['model', 'smallModel']) {
        const value = config.data[key];
        if (typeof value !== 'string' || !value.trim() || seen.has(value)) continue;
        seen.add(value);
        const slash = value.indexOf('/');
        models.push(slash > 0
          ? { id: value.slice(slash + 1), provider: value.slice(0, slash), via: key }
          : { id: value, provider: 'abacus', via: key });
      }
    }
    return models;
  },

  getCLICommand(): string {
    return 'abacusai';
  },

  getProbeManifest(): ProbeManifest {
    const desktopLinux = '~/.config/AbacusAI Desktop';
    const desktopMac = '~/Library/Application Support/AbacusAI Desktop';
    return {
      filePaths: [
        ...USER_CONFIG_FILES.map(f => `~/${ABACUS_DIR}/${f}`),
        ...DESKTOP_CONFIG_FILES.map(f => `~/${ABACUS_DIR}/desktop/${f}`),
        `~/${ABACUS_DIR}/trusted-workspaces.json`,
        `~/${ABACUS_DIR}/AGENTS.md`,
        ...USER_CLI_RELATIVE_PATHS.map(p => `~/${p}`),
      ],
      // npm copies are never run (the shim installs on run) — version them from package.json
      globPatterns: [
        ...nodeManagerPackageJsonGlobs(NPM_PACKAGE_NAME),
        ...['/usr/local', '/usr', '/opt/homebrew'].map(p => `${p}/lib/node_modules/${NPM_PACKAGE_NAME}/package.json`),
        `~/.npm-global/lib/node_modules/${NPM_PACKAGE_NAME}/package.json`,
        // User skill roots — SKL/IOC checks read them
        ...USER_SKILL_DIRS.map(d => `~/${d}/**`),
      ],
      // Credential stores, session metadata, logs and past versions:
      // existence and permissions only, never content
      metadataGlobPatterns: [
        `~/${ABACUS_DIR}/keystore.enc*`,
        // By name too: a glob can't list a directory that is traversable
        // but not readable (mode 100), where a local scan still stats these
        `~/${ABACUS_DIR}/keystore.enc`,
        `~/${ABACUS_DIR}/keystore.enc.unreadable`,
        // Every prompt typed, in plaintext — never shipped off the host
        `~/${ABACUS_DIR}/history.jsonl`,
        `~/${ABACUS_DIR}/projects/**`,
        `~/${ABACUS_DIR}/logs/**`,
        ...retainedVersionGlobs(RETAINED_VERSIONS),
        // Desktop state and key stores (ABA-003 / ABA-015 check their modes)
        ...[desktopLinux, desktopMac].flatMap(d => [`${d}/*.json`, `${d}/Cookies`]),
      ],
      commands: [
        { id: 'abacusai-which', cmd: 'which', args: ['abacusai'], timeout: 3000 },
        { id: 'abacusai-version', cmd: 'abacusai', args: ['--version'], timeout: 5000 },
      ],
      directoryListings: [`~/${ABACUS_DIR}`, `~/${ABACUS_DIR}/desktop`, `~/${ABACUS_DIR}/versions`, `~/${ABACUS_DIR}/bin`, desktopLinux, desktopMac],
      envPrefixes: ['ABACUS_', 'CODELLM_'],
      systemPaths: [...SYSTEM_CLI_PATHS, DESKTOP_APP_LINUX, DESKTOP_APP_MAC],
      systemDirListings: [],
    };
  },
};
