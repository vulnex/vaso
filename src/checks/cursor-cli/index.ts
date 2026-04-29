import type { CheckModule } from '../../core/types.js';
import { cur001 } from './cur-001-sandbox-disabled.js';
import { cur002 } from './cur-002-unsafe-approval.js';
import { cur003 } from './cur-003-overbroad-shell.js';
import { cur004 } from './cur-004-config-perms.js';
import { cur005 } from './cur-005-deny-vs-allow.js';
import { cur006 } from './cur-006-mcp-http.js';
import { cur007 } from './cur-007-privacy-mode.js';
import { cur008 } from './cur-008-sandbox-network.js';
import { cur009 } from './cur-009-overbroad-paths.js';
import { cur010 } from './cur-010-attribution.js';

export const cursorCliChecks: CheckModule[] = [
  cur001,
  cur002,
  cur003,
  cur004,
  cur005,
  cur006,
  cur007,
  cur008,
  cur009,
  cur010,
];
