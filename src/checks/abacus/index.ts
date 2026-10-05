import type { CheckModule } from '../../core/types.js';
import { aba001 } from './aba-001-permission-mode.js';
import { aba002 } from './aba-002-broad-permissions.js';
import { aba003 } from './aba-003-credential-store-perms.js';
import { aba004 } from './aba-004-plaintext-mcp-secrets.js';
import { aba005 } from './aba-005-provider-api-keys.js';
import { aba006 } from './aba-006-unpinned-mcp.js';
import { aba007 } from './aba-007-insecure-mcp-url.js';
import { aba008 } from './aba-008-mcp-auto-approve.js';
import { aba009 } from './aba-009-workspace-trust.js';
import { aba010 } from './aba-010-external-mcp-configs.js';
import { aba011 } from './aba-011-insecure-endpoints.js';
import { aba012 } from './aba-012-agents-md-secrets.js';
import { aba013 } from './aba-013-sensitive-additional-dirs.js';
import { aba014 } from './aba-014-updates-disabled.js';
import { aba015 } from './aba-015-state-permissions.js';

export const abacusChecks: CheckModule[] = [
  aba001,
  aba002,
  aba003,
  aba004,
  aba005,
  aba006,
  aba007,
  aba008,
  aba009,
  aba010,
  aba011,
  aba012,
  aba013,
  aba014,
  aba015,
];
