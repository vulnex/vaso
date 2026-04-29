import type { CheckModule } from '../../core/types.js';
import { qc001 } from './qc-001-plaintext-api-key.js';
import { qc002 } from './qc-002-credential-perms.js';
import { qc003 } from './qc-003-yolo-mode.js';
import { qc004 } from './qc-004-mcp-trust.js';
import { qc005 } from './qc-005-deny-vs-allow.js';
import { qc006 } from './qc-006-unpinned-mcp.js';
import { qc007 } from './qc-007-mcp-http.js';
import { qc008 } from './qc-008-auto-edit.js';
import { qc009 } from './qc-009-telemetry-prompts.js';
import { qc010 } from './qc-010-memory-secrets.js';

export const qwenCodeChecks: CheckModule[] = [
  qc001,
  qc002,
  qc003,
  qc004,
  qc005,
  qc006,
  qc007,
  qc008,
  qc009,
  qc010,
];
