import type { CheckModule } from '../../core/types.js';
import { opc001 } from './opc-001-auth-file-perms.js';
import { opc002 } from './opc-002-permissive-permissions.js';
import { opc003 } from './opc-003-unpinned-mcp.js';
import { opc004 } from './opc-004-auto-share.js';
import { opc005 } from './opc-005-unsafe-plugin-source.js';
import { opc006 } from './opc-006-subagent-permission-downgrade.js';
import { opc007 } from './opc-007-memory-secret-leak.js';
import { opc008 } from './opc-008-continue-on-deny.js';
import { opc009 } from './opc-009-enterprise-plaintext.js';
import { opc010 } from './opc-010-relative-plugin-path.js';
import { opc011 } from './opc-011-snapshot-disabled.js';
import { opc012 } from './opc-012-autoupdate-disabled.js';

export const opencodeChecks: CheckModule[] = [
  opc001,
  opc002,
  opc003,
  opc004,
  opc005,
  opc006,
  opc007,
  opc008,
  opc009,
  opc010,
  opc011,
  opc012,
];
