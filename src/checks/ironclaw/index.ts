import type { CheckModule } from '../../core/types.js';
import { ic001 } from './ic-001-webhook-binding.js';
import { ic002 } from './ic-002-no-tls.js';
import { ic003 } from './ic-003-orchestrator-binding.js';
import { ic004 } from './ic-004-gateway-auth-token.js';
import { ic005 } from './ic-005-sandbox-disabled.js';
import { ic006 } from './ic-006-sandbox-full-access.js';
import { ic007 } from './ic-007-auto-approve-tools.js';
import { ic008 } from './ic-008-local-tools-bypass.js';
import { ic009 } from './ic-009-secrets-key-env.js';
import { ic010 } from './ic-010-telegram-no-owner.js';
import { ic011 } from './ic-011-broad-sandbox-domains.js';
import { ic012 } from './ic-012-docker-auto-pull.js';

export const ironclawChecks: CheckModule[] = [
  ic001,
  ic002,
  ic003,
  ic004,
  ic005,
  ic006,
  ic007,
  ic008,
  ic009,
  ic010,
  ic011,
  ic012,
];
