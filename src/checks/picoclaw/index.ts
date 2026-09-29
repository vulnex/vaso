import type { CheckModule } from '../../core/types.js';
import { pcl001 } from './pcl-001-workspace-restriction.js';
import { pcl002 } from './pcl-002-exec-guard.js';
import { pcl003 } from './pcl-003-open-channel.js';
import { pcl004 } from './pcl-004-remote-exec.js';
import { pcl005 } from './pcl-005-pico-websocket.js';
import { pcl006 } from './pcl-006-launcher-exposure.js';
import { pcl007 } from './pcl-007-broad-tool-paths.js';

export const picoclawChecks: CheckModule[] = [pcl001, pcl002, pcl003, pcl004, pcl005, pcl006, pcl007];
