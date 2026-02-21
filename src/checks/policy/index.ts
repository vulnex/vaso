import type { CheckModule } from '../../core/types.js';
import { pol001 } from './pol-001-exec-approval.js';
import { pol002 } from './pol-002-log-redaction.js';
import { pol003 } from './pol-003-session-credentials.js';
import { pol004 } from './pol-004-sandbox-enforcement.js';
import { pol005 } from './pol-005-plaintext-credentials.js';

export const policyChecks: CheckModule[] = [
  pol001,
  pol002,
  pol003,
  pol004,
  pol005,
];
