import type { AgentAdapter } from '../adapters/adapter.js';
import type { ProbeManifest } from './snapshot-types.js';

export function buildProbeManifest(adapters: AgentAdapter[]): ProbeManifest {
  const merged: ProbeManifest = {
    filePaths: [],
    globPatterns: [],
    commands: [],
    directoryListings: [],
    envPrefixes: [],
    systemPaths: [],
    systemDirListings: [],
  };

  for (const adapter of adapters) {
    if (adapter.getProbeManifest) {
      const m = adapter.getProbeManifest();
      merged.filePaths.push(...m.filePaths);
      merged.globPatterns.push(...m.globPatterns);
      merged.commands.push(...m.commands);
      merged.directoryListings.push(...m.directoryListings);
      merged.envPrefixes.push(...m.envPrefixes);
      if (m.systemPaths) merged.systemPaths!.push(...m.systemPaths);
      if (m.systemDirListings) merged.systemDirListings!.push(...m.systemDirListings);
    }
  }

  // Add common runtime/network check commands
  merged.commands.push(
    { id: 'netstat-tcp', cmd: 'netstat', args: ['-an', '-p', 'tcp'], timeout: 5000 },
    { id: 'ss-tcp', cmd: 'ss', args: ['-tn'], timeout: 5000 },
    { id: 'ps-ancestry', cmd: 'ps', args: ['-eo', 'pid,ppid,comm'], timeout: 5000 },
    { id: 'crontab-list', cmd: 'crontab', args: ['-l'], timeout: 5000 },
    { id: 'launchctl-list', cmd: 'launchctl', args: ['list'], timeout: 5000 },
  );

  // Add runtime check paths
  merged.directoryListings.push('~/Library/LaunchAgents');
  merged.systemDirListings!.push('/Library/LaunchAgents', '/Library/LaunchDaemons');

  // Deduplicate
  merged.filePaths = [...new Set(merged.filePaths)];
  merged.globPatterns = [...new Set(merged.globPatterns)];
  merged.directoryListings = [...new Set(merged.directoryListings)];
  merged.envPrefixes = [...new Set(merged.envPrefixes)];
  merged.systemPaths = [...new Set(merged.systemPaths!)];
  merged.systemDirListings = [...new Set(merged.systemDirListings!)];

  // Deduplicate commands by id
  const seen = new Set<string>();
  merged.commands = merged.commands.filter(c => {
    if (seen.has(c.id)) return false;
    seen.add(c.id);
    return true;
  });

  return merged;
}
