import { mkdtemp, cp, mkdir, readFile, writeFile, chmod, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { rm } from 'node:fs/promises';
import { execSync } from 'node:child_process';
import { Glob } from 'glob';

const PROJECT_ROOT = resolve(import.meta.dirname, '../../..');
const FIXTURES_DIR = join(PROJECT_ROOT, 'testing/fixtures');

export type AgentName = 'openclaw' | 'nanoclaw' | 'picoclaw' | 'ironclaw' | 'nanobot' | 'zeroclaw';
export type Scenario = 'insecure' | 'secure';

interface AgentFixtureSpec {
  /** Path(s) under temp HOME to install fixtures */
  targetDirs: string[];
  /** Extra files at the HOME root level (e.g., .nanoclaw.env) */
  rootFiles?: string[];
  /** Post-copy hook for special handling */
  postCopy?: (tempHome: string, scenario: Scenario) => Promise<void>;
}

/**
 * Mapping from agent name to fixture installation spec.
 * Derived from each adapter's detect() method.
 */
const AGENT_SPECS: Record<AgentName, AgentFixtureSpec> = {
  openclaw: {
    targetDirs: ['.openclaw'],
  },
  nanoclaw: {
    targetDirs: ['.config/nanoclaw'],
    rootFiles: ['.nanoclaw.env'],
    postCopy: async (tempHome: string) => {
      // Rewrite NANOCLAW_HOME from Docker path to temp path
      const envPath = join(tempHome, '.nanoclaw.env');
      if (existsSync(envPath)) {
        let content = await readFile(envPath, 'utf-8');
        content = content.replace(
          /NANOCLAW_HOME=.*/,
          `NANOCLAW_HOME=${join(tempHome, '.config/nanoclaw')}`
        );
        await writeFile(envPath, content);
      }
    },
  },
  picoclaw: {
    targetDirs: ['.picoclaw'],
  },
  ironclaw: {
    targetDirs: ['.ironclaw'],
  },
  nanobot: {
    targetDirs: ['.nanobot'],
  },
  zeroclaw: {
    targetDirs: ['.zeroclaw'],
  },
};

export interface E2EEnvironment {
  tempHome: string;
  cleanup: () => Promise<void>;
}

export interface CreateE2EOptions {
  /** Agents to install. If omitted, installs all. */
  agents?: AgentName[];
  /** Scenario for all agents. Defaults to 'insecure'. */
  scenario?: Scenario;
  /** Per-agent scenario overrides. */
  agentScenarios?: Partial<Record<AgentName, Scenario>>;
  /** File permission mode for config files. Defaults to 0o644 (insecure). */
  configPermissions?: number;
}

/**
 * Create a temporary HOME directory with agent fixtures installed.
 * Each adapter's detect() method will naturally discover these installations.
 */
export async function createE2EEnvironment(options: CreateE2EOptions = {}): Promise<E2EEnvironment> {
  const tempHome = await mkdtemp(join(tmpdir(), 'vaso-e2e-'));
  const agents = options.agents ?? (Object.keys(AGENT_SPECS) as AgentName[]);
  const defaultScenario = options.scenario ?? 'insecure';
  const configPerm = options.configPermissions ?? 0o644;

  for (const agent of agents) {
    const spec = AGENT_SPECS[agent];
    const scenario = options.agentScenarios?.[agent] ?? defaultScenario;
    const fixtureDir = join(FIXTURES_DIR, agent, scenario);

    if (!existsSync(fixtureDir)) {
      continue; // Skip if fixture doesn't exist for this scenario
    }

    // Copy fixture contents to each target directory
    for (const targetDir of spec.targetDirs) {
      const targetPath = join(tempHome, targetDir);
      await mkdir(targetPath, { recursive: true });
      await cp(fixtureDir, targetPath, { recursive: true });
    }

    // Copy root-level files (e.g., .nanoclaw.env lives at HOME root, not in .config/)
    if (spec.rootFiles) {
      for (const rootFile of spec.rootFiles) {
        const srcFile = join(fixtureDir, rootFile);
        if (existsSync(srcFile)) {
          await cp(srcFile, join(tempHome, rootFile));
        }
      }
    }

    // Run post-copy hook if defined
    if (spec.postCopy) {
      await spec.postCopy(tempHome, scenario);
    }

    // Set file permissions on config files
    await setPermissionsRecursive(
      spec.targetDirs.map(d => join(tempHome, d)),
      configPerm
    );
  }

  // Create VASO directories to prevent IOC staleness warnings
  await mkdir(join(tempHome, '.vaso/ioc'), { recursive: true });
  await mkdir(join(tempHome, '.vaso/plugins'), { recursive: true });

  return {
    tempHome,
    cleanup: async () => {
      // Reset permissions so rm can traverse and delete everything
      try {
        execSync(`chmod -R u+rwX "${tempHome}"`, { stdio: 'ignore' });
      } catch {
        // Best-effort
      }
      await rm(tempHome, { recursive: true, force: true });
    },
  };
}

/**
 * Recursively set file permissions on regular files within the given directories.
 * Directories are left writable so cleanup can delete them.
 */
async function setPermissionsRecursive(dirs: string[], mode: number): Promise<void> {
  for (const dir of dirs) {
    if (!existsSync(dir)) continue;

    const glob = new Glob('**/*', { cwd: dir, nodir: true, absolute: true });
    for await (const entry of glob) {
      try {
        const s = await stat(entry);
        if (s.isFile()) {
          await chmod(entry, mode);
        }
      } catch {
        // Ignore errors
      }
    }
  }
}
