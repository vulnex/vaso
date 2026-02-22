import { readdirSync, rmSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export default function globalTeardown() {
  const tmp = tmpdir();
  let cleaned = 0;

  try {
    for (const entry of readdirSync(tmp)) {
      if (entry.startsWith('vaso-e2e-')) {
        const dirPath = join(tmp, entry);
        // Reset permissions before deleting (files may have been chmod'd to 0o600)
        try {
          execSync(`chmod -R u+rwX "${dirPath}"`, { stdio: 'ignore' });
        } catch {
          // Best effort
        }
        rmSync(dirPath, { recursive: true, force: true });
        cleaned++;
      }
    }
  } catch {
    // Best-effort cleanup — ignore errors
  }

  if (cleaned > 0) {
    console.log(`[e2e] Cleaned ${cleaned} leftover vaso-e2e-* temp directories`);
  }
}
