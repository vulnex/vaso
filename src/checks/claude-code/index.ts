import type { CheckModule } from '../../core/types.js';
import { cc001 } from './cc-001-bypass-permissions.js';
import { cc002 } from './cc-002-broad-bash-allow.js';
import { cc003 } from './cc-003-unsafe-hooks.js';
import { cc004 } from './cc-004-plaintext-api-key.js';
import { cc005 } from './cc-005-unpinned-mcp.js';
import { cc006 } from './cc-006-auto-trust-project-mcp.js';
import { cc007 } from './cc-007-api-key-helper-perms.js';
import { cc008 } from './cc-008-missing-deny-rules.js';

export const claudeCodeChecks: CheckModule[] = [
  cc001,
  cc002,
  cc003,
  cc004,
  cc005,
  cc006,
  cc007,
  cc008,
];
