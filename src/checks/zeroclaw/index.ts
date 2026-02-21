import type { CheckModule } from '../../core/types.js';
import { zc001 } from './zc-001-plaintext-api-keys.js';
import { zc002 } from './zc-002-xor-encryption.js';
import { zc003 } from './zc-003-public-bind-no-tunnel.js';
import { zc004 } from './zc-004-pairing-disabled.js';
import { zc005 } from './zc-005-full-autonomy.js';
import { zc006 } from './zc-006-workspace-unrestricted.js';
import { zc007 } from './zc-007-channel-wildcard.js';
import { zc008 } from './zc-008-open-skills.js';
import { zc009 } from './zc-009-whatsapp-no-secret.js';
import { zc010 } from './zc-010-composio-enabled.js';
import { zc011 } from './zc-011-browser-no-allowlist.js';
import { zc012 } from './zc-012-http-no-allowlist.js';
import { zc013 } from './zc-013-secret-key-perms.js';
import { zc014 } from './zc-014-no-os-sandbox.js';

export const zeroclawChecks: CheckModule[] = [
  zc001,
  zc002,
  zc003,
  zc004,
  zc005,
  zc006,
  zc007,
  zc008,
  zc009,
  zc010,
  zc011,
  zc012,
  zc013,
  zc014,
];
