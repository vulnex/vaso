import type { CheckModule } from '../../core/types.js';
import { cdx001 } from './cdx-001-approval-policy.js';
import { cdx002 } from './cdx-002-sandbox-mode.js';
import { cdx003 } from './cdx-003-auth-file-perms.js';
import { cdx004 } from './cdx-004-unpinned-mcp.js';
import { cdx005 } from './cdx-005-shell-env-policy.js';
import { cdx006 } from './cdx-006-trusted-projects-scope.js';
import { cdx007 } from './cdx-007-memory-secret-leak.js';
import { cdx008 } from './cdx-008-profile-downgrade.js';
import { cdx009 } from './cdx-009-unsafe-notify.js';

export const codexChecks: CheckModule[] = [
  cdx001,
  cdx002,
  cdx003,
  cdx004,
  cdx005,
  cdx006,
  cdx007,
  cdx008,
  cdx009,
];
