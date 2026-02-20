import type { CheckModule } from '../../core/types.js';
import { net001 } from './net-001-gateway-exposure.js';
import { net002 } from './net-002-websocket-origin.js';
import { net003 } from './net-003-reverse-proxy.js';
import { net004 } from './net-004-port-scan.js';

export const networkChecks: CheckModule[] = [
  net001,
  net002,
  net003,
  net004,
];
