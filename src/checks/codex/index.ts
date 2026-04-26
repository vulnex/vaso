import type { CheckModule } from '../../core/types.js';
import { cdx001 } from './cdx-001-approval-policy.js';
import { cdx002 } from './cdx-002-sandbox-mode.js';
import { cdx003 } from './cdx-003-auth-file-perms.js';
import { cdx004 } from './cdx-004-unpinned-mcp.js';

export const codexChecks: CheckModule[] = [
  cdx001,
  cdx002,
  cdx003,
  cdx004,
];
