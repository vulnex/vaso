import type { CheckModule } from '../../core/types.js';
import { ioc001 } from './ioc-001-c2-ips.js';
import { ioc002 } from './ioc-002-malicious-domains.js';
import { ioc003 } from './ioc-003-file-hash.js';
import { ioc004 } from './ioc-004-malicious-publishers.js';
import { ioc005 } from './ioc-005-typosquatting.js';
import { ioc006 } from './ioc-006-skill-name-patterns.js';
import { ioc007 } from './ioc-007-binary-patterns.js';
import { ioc008 } from './ioc-008-virustotal.js';

export const iocChecks: CheckModule[] = [
  ioc001,
  ioc002,
  ioc003,
  ioc004,
  ioc005,
  ioc006,
  ioc007,
  ioc008,
];
