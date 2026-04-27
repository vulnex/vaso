import type { CheckModule } from '../../core/types.js';
import { oc001 } from './oc-001-subagent-config-downgrade.js';
import { oc003 } from './oc-003-legacy-bot-dirs.js';
import { oc004 } from './oc-004-openclaw-home-redirect.js';
import { oc005 } from './oc-005-profile-weaker-than-default.js';
import { oc006 } from './oc-006-memory-file-permissions.js';
import { oc007 } from './oc-007-etc-openclaw-writable.js';

export const openclawChecks: CheckModule[] = [
  oc001,
  oc003,
  oc004,
  oc005,
  oc006,
  oc007,
];
