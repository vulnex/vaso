import type { CheckModule } from '../../core/types.js';
import { pc001 } from './pc-001-profile-data-perms.js';
import { pc002 } from './pc-002-extension-inventory.js';

export const cometChecks: CheckModule[] = [
  pc001,
  pc002,
];
