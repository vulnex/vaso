import type { CheckModule } from '../../core/types.js';
import { run001 } from './run-001-launch-agents.js';
import { run002 } from './run-002-suspicious-cron.js';
import { run003 } from './run-003-vscode-trojans.js';
import { run004 } from './run-004-docker-security.js';

export const runtimeChecks: CheckModule[] = [
  run001,
  run002,
  run003,
  run004,
];
