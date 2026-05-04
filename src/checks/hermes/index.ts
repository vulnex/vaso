import type { CheckModule } from '../../core/types.js';
import { hm001 } from './hm-001-plaintext-api-keys.js';
import { hm002 } from './hm-002-env-file-perms.js';
import { hm003 } from './hm-003-credential-file-perms.js';
import { hm004 } from './hm-004-api-server-no-auth.js';
import { hm005 } from './hm-005-api-server-cors.js';
import { hm006 } from './hm-006-plaintext-http-endpoint.js';
import { hm007 } from './hm-007-untrusted-custom-endpoint.js';
import { hm008 } from './hm-008-approvals-disabled.js';
import { hm009 } from './hm-009-tirith-disabled.js';
import { hm010 } from './hm-010-mcp-server-hardening.js';

export const hermesChecks: CheckModule[] = [
  hm001, hm002, hm003, hm004, hm005,
  hm006, hm007, hm008, hm009, hm010,
];
