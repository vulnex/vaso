import type { AdapterRegistry } from '../adapters/registry.js';
import { buildProbeManifest } from '../core/manifest-builder.js';
import type { ProbeSnapshot } from '../core/snapshot-types.js';
import { loadSnapshotFile, SnapshotLoadError, snapshotErrorLines } from '../core/snapshot-load.js';

export async function probeManifest(adapters: AdapterRegistry): Promise<void> {
  const allAdapters = adapters.getAdapters();
  const manifest = buildProbeManifest(allAdapters);
  console.log(JSON.stringify(manifest, null, 2));
}

export async function probeValidate(snapshotPath: string): Promise<void> {
  let snapshot: ProbeSnapshot;
  try {
    snapshot = await loadSnapshotFile(snapshotPath);
  } catch (err) {
    if (!(err instanceof SnapshotLoadError)) throw err;
    for (const line of snapshotErrorLines(err)) console.error(line);
    // An unusable snapshot means VASO could not run: exit 2, like scan/detect
    process.exitCode = 2;
    return;
  }

  console.log(`Snapshot: ${snapshotPath}`);
  console.log(`  Host:      ${snapshot.hostname}`);
  console.log(`  Platform:  ${snapshot.platform}`);
  console.log(`  Timestamp: ${snapshot.timestamp}`);
  console.log(`  Files:     ${Object.keys(snapshot.files).length} collected`);
  console.log(`  Dirs:      ${Object.keys(snapshot.directories).length} collected`);
  console.log(`  Commands:  ${Object.keys(snapshot.commandOutputs).length} collected`);
  if (snapshot.privilege) {
    console.log(`  Privilege:  ${snapshot.privilege.isRoot ? 'root' : 'user'} (${snapshot.privilege.username})`);
    console.log(`  Users:     ${snapshot.privilege.scannedUsers.join(', ')}`);
  }
  console.log('Snapshot is valid.');
}
