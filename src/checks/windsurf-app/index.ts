import type { CheckModule } from '../../core/types.js';
import { ws001 } from './ws-001-auto-execution-policy.js';
import { ws002 } from './ws-002-broad-command-allowlist.js';
import { ws003 } from './ws-003-mcp-plaintext-secrets.js';
import { ws004 } from './ws-004-unpinned-mcp.js';
import { ws005 } from './ws-005-insecure-mcp-url.js';
import { ws006 } from './ws-006-workflow-turbo-directive.js';
import { ws007 } from './ws-007-legacy-api-key-file.js';
import { ws008 } from './ws-008-state-db-readable.js';

export const windsurfChecks: CheckModule[] = [
  ws001,
  ws002,
  ws003,
  ws004,
  ws005,
  ws006,
  ws007,
  ws008,
];
