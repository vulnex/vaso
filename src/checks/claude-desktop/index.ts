import type { CheckModule } from '../../core/types.js';
import { cd001 } from './cd-001-plaintext-api-key.js';
import { cd002 } from './cd-002-config-file-perms.js';
import { cd003 } from './cd-003-unpinned-mcp.js';
import { cd004 } from './cd-004-http-mcp.js';
import { cd005 } from './cd-005-unverified-mcpb-extensions.js';
import { cd006 } from './cd-006-always-approve.js';
import { cd007 } from './cd-007-filesystem-server-scope.js';
import { cd008 } from './cd-008-stdio-shell.js';
import { cd009 } from './cd-009-world-writable-command.js';
import { cd010 } from './cd-010-credentials-in-url.js';

export const claudeDesktopChecks: CheckModule[] = [
  cd001,
  cd002,
  cd003,
  cd004,
  cd005,
  cd006,
  cd007,
  cd008,
  cd009,
  cd010,
];
