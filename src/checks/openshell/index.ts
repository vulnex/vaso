import type { CheckModule } from '../../core/types.js';
import { osh001 } from './osh-001-tls-disabled.js';
import { osh002 } from './osh-002-unauthenticated-users.js';
import { osh003 } from './osh-003-insecure-oidc.js';
import { osh004 } from './osh-004-non-expiring-credentials.js';
import { osh005 } from './osh-005-policy-fail-open.js';
import { osh006 } from './osh-006-extensions-fail-open.js';
import { osh007 } from './osh-007-resource-admission.js';
import { osh008 } from './osh-008-key-material-exposed.js';
import { osh009 } from './osh-009-config-writable.js';
import { osh010 } from './osh-010-client-tls-bypass.js';
import { osh011 } from './osh-011-broad-binaries.js';
import { osh012 } from './osh-012-uninspected-egress.js';
import { osh013 } from './osh-013-broad-destinations.js';
import { osh014 } from './osh-014-writable-system-paths.js';

export const openshellChecks: CheckModule[] = [
  osh001,
  osh002,
  osh003,
  osh004,
  osh005,
  osh006,
  osh007,
  osh008,
  osh009,
  osh010,
  osh011,
  osh012,
  osh013,
  osh014,
];
