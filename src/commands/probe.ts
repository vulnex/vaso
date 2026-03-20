import { readFile } from 'node:fs/promises';
import type { AdapterRegistry } from '../adapters/registry.js';
import { buildProbeManifest } from '../core/manifest-builder.js';
import type { ProbeSnapshot } from '../core/snapshot-types.js';

export async function probeManifest(adapters: AdapterRegistry): Promise<void> {
  const allAdapters = adapters.getAdapters();
  const manifest = buildProbeManifest(allAdapters);
  console.log(JSON.stringify(manifest, null, 2));
}

export async function probeValidate(snapshotPath: string): Promise<void> {
  const raw = await readFile(snapshotPath, 'utf-8');
  const snapshot = JSON.parse(raw) as ProbeSnapshot;

  const errors: string[] = [];
  if (snapshot.version !== 1) errors.push(`Unsupported snapshot version: ${snapshot.version}`);
  if (!snapshot.platform) errors.push('Missing platform field');
  if (!snapshot.hostname) errors.push('Missing hostname field');
  if (!snapshot.files || typeof snapshot.files !== 'object') errors.push('Missing or invalid files field');
  if (!snapshot.directories || typeof snapshot.directories !== 'object') errors.push('Missing or invalid directories field');
  if (!snapshot.commandOutputs || typeof snapshot.commandOutputs !== 'object') errors.push('Missing or invalid commandOutputs field');

  if (errors.length > 0) {
    console.error('Snapshot validation failed:');
    for (const e of errors) console.error(`  - ${e}`);
    process.exitCode = 1;
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
