import type { CheckModule } from '../../core/types.js';
import { msc001 } from './msc-001-approval-disabled.js';
import { msc002 } from './msc-002-sandbox-disabled.js';
import { msc003 } from './msc-003-auth-permissions.js';
import { msc004 } from './msc-004-mcp-secrets.js';
import { msc005 } from './msc-005-unpinned-mcp.js';
import { msc006 } from './msc-006-insecure-mcp-url.js';
import { msc007 } from './msc-007-hook-commands.js';
import { msc008 } from './msc-008-session-data.js';
import { msc009 } from './msc-009-state-writable.js';
import { msc010 } from './msc-010-unsafe-env.js';
import { msc011 } from './msc-011-endpoint-redirect.js';
import { msc012 } from './msc-012-agents-md-secrets.js';

export const museCodeChecks: CheckModule[] = [
  msc001,
  msc002,
  msc003,
  msc004,
  msc005,
  msc006,
  msc007,
  msc008,
  msc009,
  msc010,
  msc011,
  msc012,
];
