import type { CheckModule } from '../../core/types.js';
import { mm001 } from './mm-001-codesign-team-id.js';
import { mm002 } from './mm-002-analytics-active.js';
import { mm003 } from './mm-003-app-data-perms.js';

export const metaMuseChecks: CheckModule[] = [
  mm001,
  mm002,
  mm003,
];
