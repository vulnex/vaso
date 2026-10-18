import type { CheckModule } from '../../core/types.js';
import { gb001 } from './gb-001-local-execution.js';
import { gb002 } from './gb-002-tool-auto-approve.js';
import { gb003 } from './gb-003-auto-review.js';
import { gb004 } from './gb-004-standing-grants.js';
import { gb005 } from './gb-005-egress-tunnel.js';
import { gb006 } from './gb-006-unprotected-credentials.js';
import { gb007 } from './gb-007-credential-perms.js';
import { gb008 } from './gb-008-runtime-data-perms.js';
import { gb009 } from './gb-009-messages-access.js';
import { gb010 } from './gb-010-computer-use.js';
import { gb011 } from './gb-011-updates-disabled.js';
import { gb012 } from './gb-012-endpoint-redirect.js';
import { gb013 } from './gb-013-webauthn-proxy.js';

export const grokBotChecks: CheckModule[] = [
  gb001, gb002, gb003, gb004, gb005, gb006, gb007, gb008, gb009, gb010, gb011, gb012, gb013,
];
