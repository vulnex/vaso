import type { CheckModule } from '../../core/types.js';
import { dev001 } from './dev-001-broad-permissions.js';
import { dev002 } from './dev-002-credentials-perms.js';
import { dev003 } from './dev-003-plaintext-mcp-secrets.js';
import { dev004 } from './dev-004-unpinned-mcp.js';
import { dev005 } from './dev-005-insecure-mcp-url.js';
import { dev006 } from './dev-006-hooks-present.js';
import { dev007 } from './dev-007-agents-md-secrets.js';

export const devinChecks: CheckModule[] = [
  dev001,
  dev002,
  dev003,
  dev004,
  dev005,
  dev006,
  dev007,
];
