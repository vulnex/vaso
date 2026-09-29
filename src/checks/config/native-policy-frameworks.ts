import type { AgentType } from '../../core/types.js';

/**
 * Frameworks whose shell allowlist, workspace scope and rate limits live in
 * their own schemas (covered by their framework check categories), so the
 * generic CFG-005/006/010 keys don't exist there. Several of them load config
 * strictly — an unknown key written by a fix makes the agent refuse to start.
 */
export const NATIVE_POLICY_FRAMEWORKS: AgentType[] = [
  'atomic-agent', 'picoclaw', 'nanoclaw', 'ironclaw', 'zeroclaw', 'nanobot', 'lyrie',
];
