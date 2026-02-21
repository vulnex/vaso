import type { CheckModule } from '../../core/types.js';
import { skl001 } from './skl-001-data-exfiltration.js';
import { skl002 } from './skl-002-obfuscated-code.js';
import { skl003 } from './skl-003-eval-exec.js';
import { skl004 } from './skl-004-curl-pipe.js';
import { skl005 } from './skl-005-reverse-shell.js';
import { skl006 } from './skl-006-credential-harvesting.js';
import { skl007 } from './skl-007-prompt-injection.js';
import { skl008 } from './skl-008-suspicious-network.js';
import { skl009 } from './skl-009-crypto-wallet.js';
import { skl010 } from './skl-010-unauthorized-fs.js';
import { skl011 } from './skl-011-dependency-audit.js';
import { skl012 } from './skl-012-code-complexity.js';

export const skillChecks: CheckModule[] = [
  skl001,
  skl002,
  skl003,
  skl004,
  skl005,
  skl006,
  skl007,
  skl008,
  skl009,
  skl010,
  skl011,
  skl012,
];
