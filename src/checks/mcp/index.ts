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
import { mcp011 } from './mcp-011-oauth-endpoint-https.js';
import { mcp012 } from './mcp-012-oauth-client-secret-exposure.js';
import { mcp013 } from './mcp-013-missing-pkce.js';
import { mcp014 } from './mcp-014-insecure-token-storage.js';
import { mcp015 } from './mcp-015-token-passthrough.js';
import { mcp016 } from './mcp-016-insecure-redirect-uri.js';
import { mcp017 } from './mcp-017-overly-broad-scopes.js';
import { mcp018 } from './mcp-018-missing-state-parameter.js';
import { mcp019 } from './mcp-019-toxic-tool-flow.js';
import { mcp020 } from './mcp-020-tool-definition-rug-pull.js';
import { mcp021 } from './mcp-021-stdio-shell-invocation.js';
import { mcp022 } from './mcp-022-world-writable-command.js';
import { mcp023 } from './mcp-023-streamable-http-origin-pinning.js';
import { mcp024 } from './mcp-024-tool-description-injection.js';
import { mcp025 } from './mcp-025-tool-name-collision.js';
import { mcp029 } from './mcp-029-remote-server-no-auth.js';
import { mcp031 } from './mcp-031-filesystem-sensitive-path.js';

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
  mcp011,
  mcp012,
  mcp013,
  mcp014,
  mcp015,
  mcp016,
  mcp017,
  mcp018,
  mcp019,
  mcp020,
  mcp021,
  mcp022,
  mcp023,
  mcp024,
  mcp025,
  mcp029,
  mcp031,
];
