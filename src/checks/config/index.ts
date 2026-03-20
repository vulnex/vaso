import type { CheckModule } from '../../core/types.js';
import { cfg001 } from './cfg-001-gateway-binding.js';
import { cfg002 } from './cfg-002-api-key-exposure.js';
import { cfg003 } from './cfg-003-file-permissions.js';
import { cfg004 } from './cfg-004-tls-config.js';
import { cfg005 } from './cfg-005-shell-allowlist.js';
import { cfg006 } from './cfg-006-workspace-restriction.js';
import { cfg007 } from './cfg-007-webhook-auth.js';
import { cfg008 } from './cfg-008-sandbox-disabled.js';
import { cfg009 } from './cfg-009-default-credentials.js';
import { cfg010 } from './cfg-010-rate-limiting.js';
import { cfg011 } from './cfg-011-node-cve.js';
import { cfg012 } from './cfg-012-auth-bypass.js';
import { cfg013 } from './cfg-013-dm-policy.js';
import { cfg014 } from './cfg-014-tool-policy.js';
import { cfg015 } from './cfg-015-mdns-broadcast.js';
import { cfg016 } from './cfg-016-nemoclaw-hardening.js';
import { cfg017 } from './cfg-017-nemoclaw-sandbox-active.js';
import { cfg018 } from './cfg-018-nemoclaw-network-policy.js';
import { cfg019 } from './cfg-019-nemoclaw-blueprint-integrity.js';
import { cfg020 } from './cfg-020-nemoclaw-api-key-exposure.js';
import { cfg021 } from './cfg-021-nemoclaw-gpu-isolation.js';
import { cfg022 } from './cfg-022-nemoclaw-policy-scope.js';
import { cfg023 } from './cfg-023-nemoclaw-model-pinning.js';
import { cfg024 } from './cfg-024-nemoclaw-default-sandbox.js';

export const configChecks: CheckModule[] = [
  cfg001,
  cfg002,
  cfg003,
  cfg004,
  cfg005,
  cfg006,
  cfg007,
  cfg008,
  cfg009,
  cfg010,
  cfg011,
  cfg012,
  cfg013,
  cfg014,
  cfg015,
  cfg016,
  cfg017,
  cfg018,
  cfg019,
  cfg020,
  cfg021,
  cfg022,
  cfg023,
  cfg024,
];
