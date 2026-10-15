import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Unit tests never touch the developer's real home: code under test writes
// ~/.vaso state (fix backups, baselines, MCP history, feed caches) through
// os.homedir(), which reads $HOME on each call. Each test file gets a
// throwaway HOME; a test that needs its own still sets process.env.HOME.
process.env.HOME = mkdtempSync(join(tmpdir(), 'vaso-test-home-'));
