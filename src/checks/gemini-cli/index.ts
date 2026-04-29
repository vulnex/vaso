import type { CheckModule } from '../../core/types.js';
import { gem001 } from './gem-001-plaintext-api-key.js';
import { gem002 } from './gem-002-credential-perms.js';
import { gem003 } from './gem-003-overbroad-allow.js';
import { gem004 } from './gem-004-yolo-guard.js';
import { gem005 } from './gem-005-sandbox-disabled.js';
import { gem006 } from './gem-006-sandbox-network.js';
import { gem007 } from './gem-007-unpinned-mcp.js';
import { gem008 } from './gem-008-mcp-http.js';
import { gem009 } from './gem-009-auto-edit.js';
import { gem010 } from './gem-010-memory-secrets.js';

export const geminiCliChecks: CheckModule[] = [
  gem001,
  gem002,
  gem003,
  gem004,
  gem005,
  gem006,
  gem007,
  gem008,
  gem009,
  gem010,
];
