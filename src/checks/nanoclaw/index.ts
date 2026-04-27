import type { CheckModule } from '../../core/types.js';
import { nc001 } from './nc-001-overbroad-mount-allowlist.js';
import { nc002 } from './nc-002-allowlist-writable.js';
import { nc003 } from './nc-003-nanoclaw-home-redirect.js';
import { nc004 } from './nc-004-nanoclaw-port-public-bind.js';
import { nc005 } from './nc-005-skills-dir-writable.js';

export const nanoclawChecks: CheckModule[] = [
  nc001,
  nc002,
  nc003,
  nc004,
  nc005,
];
