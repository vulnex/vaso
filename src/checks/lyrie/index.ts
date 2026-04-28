import type { CheckModule } from '../../core/types.js';
import { ly001 } from './ly-001-shield-mode-passive.js';
import { ly002 } from './ly-002-shield-binary-missing.js';
import { ly003 } from './ly-003-dm-policy-open.js';
import { ly004 } from './ly-004-pairing-store-perms.js';
import { ly005 } from './ly-005-stale-pending-pairings.js';
import { ly006 } from './ly-006-env-file-perms.js';
import { ly007 } from './ly-007-unused-provider-keys.js';
import { ly008 } from './ly-008-remote-backend-creds.js';
import { ly009 } from './ly-009-dry-run-enabled.js';
import { ly010 } from './ly-010-webchat-unauthed.js';
import { ly011 } from './ly-011-webchat-cors-permissive.js';
import { ly012 } from './ly-012-stale-edit-approvals.js';
import { ly013 } from './ly-013-edits-store-perms.js';
import { ly014 } from './ly-014-executable-skill-files.js';
import { ly015 } from './ly-015-skills-dir-writable.js';
import { ly016 } from './ly-016-migration-import-detected.js';
import { ly017 } from './ly-017-migration-errors.js';
import { ly018 } from './ly-018-node-env-development.js';

export const lyrieChecks: CheckModule[] = [
  ly001, ly002, ly003, ly004, ly005, ly006,
  ly007, ly008, ly009, ly010, ly011, ly012,
  ly013, ly014, ly015, ly016, ly017, ly018,
];
