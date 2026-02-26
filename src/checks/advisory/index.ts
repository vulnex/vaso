import type { CheckModule } from '../../core/types.js';
import { adv001 } from './adv-001-version-vuln.js';
import { adv002 } from './adv-002-dependency-vuln.js';
import { adv003 } from './adv-003-eol-version.js';
import { adv004 } from './adv-004-known-exploit.js';
import { adv005 } from './adv-005-config-advisory.js';

export const advisoryChecks: CheckModule[] = [
  adv001,
  adv002,
  adv003,
  adv004,
  adv005,
];
