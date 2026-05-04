import type { CheckModule } from '../../core/types.js';
import { cg001 } from './cg-001-conversations-world-readable.js';
import { cg002 } from './cg-002-plaintext-email.js';
import { cg003 } from './cg-003-training-allowed.js';
import { cg004 } from './cg-004-precise-location.js';
import { cg005 } from './cg-005-codesign-team-id.js';
import { cg006 } from './cg-006-paired-apps-inventory.js';

export const chatgptDesktopChecks: CheckModule[] = [
  cg001,
  cg002,
  cg003,
  cg004,
  cg005,
  cg006,
];
