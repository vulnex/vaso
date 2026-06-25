import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Read version from package.json at runtime so it can never drift from the
// manifest. This module lives at src/ depth 1 so the '..' hop reaches
// package.json in BOTH forms it runs in:
//   - bundled: tsup inlines it into dist/cli.js (splitting: false), one dir
//     below package.json (<pkg>/dist/cli.js → <pkg>/package.json)
//   - unbundled (vitest): src/version.ts → repo-root package.json
// Consumed by the CLI (`--version`) and every reporter that stamps a tool
// version, so there is exactly one source of truth.
export const VERSION = (JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'),
    'utf8',
  ),
) as { version: string }).version;
