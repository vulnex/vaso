import { join } from 'node:path';
import type { FSProvider } from '../../core/fs-provider.js';
import { nemoclawLegacyRoots } from '../../adapters/nemoclaw-paths.js';

// Shared NemoClaw on-disk state for CFG-016–024. Two install generations:
//  - Current (install.sh, v0.0.x): repo checked out to ~/.nemoclaw/source; the
//    sandbox registry (~/.nemoclaw/sandboxes.json) is the only persisted record
//    of deployments — state/nemoclaw.json and blueprints/<ver>/ are no longer
//    written, and applied policy presets live in the OpenShell gateway.
//  - Legacy (early 2026 npm-global package): state/nemoclaw.json records the
//    deployment and blueprintVersion; the blueprint ships in node_modules.

export function nemoclawDir(fs: FSProvider): string {
  return join(fs.homedir(), '.nemoclaw');
}

/** Blueprint directories to inspect, current install first. */
export function blueprintDirCandidates(fs: FSProvider): string[] {
  const home = fs.homedir();
  return [
    join(home, '.nemoclaw', 'source', 'nemoclaw-blueprint'),
    ...nemoclawLegacyRoots(home).map(root => join(root, 'nemoclaw-blueprint')),
  ];
}

export async function findBlueprintDir(fs: FSProvider): Promise<string | undefined> {
  for (const dir of blueprintDirCandidates(fs)) {
    if (await fs.access(dir)) return dir;
  }
  return undefined;
}

export interface RegisteredSandbox {
  name: string;
  entry: Record<string, unknown>;
}

/**
 * Sandboxes the registry records as created: an entry whose `name` matches its
 * key and that is not a pending reservation (`pendingRouteReservation` /
 * `pendingCreateIdentity` mark an onboard that never finished). Entries with
 * `stopped: true` are still deployed, just stopped on purpose.
 */
export async function registeredSandboxes(fs: FSProvider): Promise<{ file: string; sandboxes: RegisteredSandbox[] } | undefined> {
  const file = join(nemoclawDir(fs), 'sandboxes.json');
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(await fs.readFile(file)) as Record<string, unknown>;
  } catch {
    return undefined;
  }
  const map = data.sandboxes;
  if (!map || typeof map !== 'object' || Array.isArray(map)) return { file, sandboxes: [] };
  const sandboxes: RegisteredSandbox[] = [];
  for (const [key, raw] of Object.entries(map as Record<string, unknown>)) {
    if (!raw || typeof raw !== 'object') continue;
    const entry = raw as Record<string, unknown>;
    if (entry.name !== undefined && entry.name !== key) continue;
    if (entry.pendingRouteReservation === true || entry.pendingCreateIdentity) continue;
    sandboxes.push({ name: key, entry });
  }
  return { file, sandboxes };
}
