import type { CheckModule } from '../../core/types.js';
import { nb001 } from './nb-001-channel-allow-from.js';
import { nb002 } from './nb-002-plaintext-secrets.js';
import { nb003 } from './nb-003-restrict-workspace.js';
import { nb004 } from './nb-004-exec-tool-filter.js';
import { nb005 } from './nb-005-ssrf-webfetch.js';
import { nb006 } from './nb-006-heartbeat-injection.js';
import { nb007 } from './nb-007-memory-injection.js';
import { nb008 } from './nb-008-bridge-token.js';
import { nb009 } from './nb-009-session-unencrypted.js';
import { nb010 } from './nb-010-cron-channels.js';
import { nb011 } from './nb-011-no-rate-limit.js';
import { nb012 } from './nb-012-clawhub-npx.js';

export const nanobotChecks: CheckModule[] = [
  nb001,
  nb002,
  nb003,
  nb004,
  nb005,
  nb006,
  nb007,
  nb008,
  nb009,
  nb010,
  nb011,
  nb012,
];
