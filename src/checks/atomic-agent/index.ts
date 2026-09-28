import type { CheckModule } from '../../core/types.js';
import { at001 } from './at-001-approval-level.js';
import { at002 } from './at-002-unrestricted-read-scope.js';
import { at003 } from './at-003-http-tool-unapproved.js';
import { at004 } from './at-004-plaintext-config-secrets.js';
import { at005 } from './at-005-credential-file-perms.js';
import { at006 } from './at-006-mcp-pure-read-trust.js';
import { at007 } from './at-007-mcp-server-hardening.js';
import { at008 } from './at-008-webhook-without-secret.js';
import { at009 } from './at-009-subscription-cli-safety-override.js';
import { at010 } from './at-010-plaintext-inference-endpoint.js';
import { at011 } from './at-011-private-state-perms.js';

export const atomicAgentChecks: CheckModule[] = [
  at001, at002, at003, at004, at005, at006,
  at007, at008, at009, at010, at011,
];
