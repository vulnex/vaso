import type { CheckModule } from '../../core/types.js';
import { ghc001 } from './ghc-001-dir-perms.js';
import { ghc002 } from './ghc-002-allow-all-permissions.js';
import { ghc003 } from './ghc-003-plaintext-token.js';
import { ghc004 } from './ghc-004-mcp-http.js';
import { ghc005 } from './ghc-005-prerelease-channel.js';
import { ghc006 } from './ghc-006-experimental-mode.js';
import { ghc007 } from './ghc-007-lsp-command-injection.js';
import { ghc008 } from './ghc-008-instructions-secrets.js';

export const copilotCliChecks: CheckModule[] = [
  ghc001,
  ghc002,
  ghc003,
  ghc004,
  ghc005,
  ghc006,
  ghc007,
  ghc008,
];
