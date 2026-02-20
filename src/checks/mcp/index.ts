import type { CheckModule } from '../../core/types.js';
import { mcp001 } from './mcp-001-config-discovery.js';
import { mcp002 } from './mcp-002-transport-security.js';
import { mcp003 } from './mcp-003-credential-exposure.js';
import { mcp004 } from './mcp-004-overprivileged-tools.js';
import { mcp005 } from './mcp-005-tool-injection.js';
import { mcp006 } from './mcp-006-data-exfiltration.js';
import { mcp007 } from './mcp-007-prompt-injection.js';
import { mcp008 } from './mcp-008-server-provenance.js';
import { mcp009 } from './mcp-009-permission-scope.js';
import { mcp010 } from './mcp-010-rug-pull-risk.js';

export const mcpChecks: CheckModule[] = [
  mcp001,
  mcp002,
  mcp003,
  mcp004,
  mcp005,
  mcp006,
  mcp007,
  mcp008,
  mcp009,
  mcp010,
];
