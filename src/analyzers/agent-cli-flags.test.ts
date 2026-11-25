import { describe, it, expect } from 'vitest';
import { agentBypass } from './agent-cli-flags.js';

const lvl = (cmd: string) => agentBypass(cmd)?.level;

describe('agentBypass: vendor-documented approval/sandbox bypass flags', () => {
  it('full bypasses are critical', () => {
    for (const cmd of [
      'claude --dangerously-skip-permissions -p ${…}',
      'claude --permission-mode bypassPermissions -p x',
      'gemini --yolo -p x', 'gemini -y -p x', 'gemini --approval-mode=yolo -p x',
      'qwen --approval-mode yolo -p x',
      'q chat --trust-all-tools --no-interactive x', 'kiro-cli chat -a x',
      'codex exec --dangerously-bypass-approvals-and-sandbox x', 'codex --yolo x',
      'codex exec -a never -s danger-full-access x',
      'cursor-agent --force -p x', 'cursor-agent -f -p x',
      'copilot --allow-all-tools -p x', 'copilot --yolo -p x',
      'opencode run --auto x',
      'devin --permission-mode dangerous -p x',
      'abacusai --dangerously-skip-permissions x',
      'aider --yes-always --message x',
      'muse exec --yolo x', 'muse --approval-mode never x', 'muse exec --disable-approval x', 'muse --permission-profile :unrestricted x',
      'npx -y @anthropic-ai/claude-code --dangerously-skip-permissions -p x',
      "sh -c 'claude --dangerously-skip-permissions -p x'",
      '/usr/local/bin/gemini --yolo',
    ]) expect(lvl(cmd), cmd).toBe('critical');
  });

  it('partial approval and sandbox-off modes are warnings', () => {
    for (const cmd of [
      'claude --permission-mode acceptEdits -p x', 'gemini --approval-mode auto_edit', 'qwen --approval-mode auto-edit',
      'codex exec --sandbox danger-full-access x', 'codex exec -a never x', 'cursor-agent --sandbox disabled -p x',
      'copilot --allow-all-paths -p x', 'devin --permission-mode autonomous', 'q chat --trust-tools=fs_read x',
      'muse exec --disable-sandbox x', 'muse --sandbox-network enabled x',
    ]) expect(lvl(cmd), cmd).toBe('warning');
  });

  it('ordinary runs, other programs and flags of other subcommands are not bypasses', () => {
    for (const cmd of [
      'claude --version', 'claude -p x', 'gemini -p x', 'codex exec x', 'q --version', 'q translate -a x',
      'git -f push', 'npx -y prettier --write .', 'yolo --force', 'copilot --help', 'cursor-agent -p x',
      'muse exec x', 'muse --approval-mode on-request x', 'muse --permission-profile :read-only x',
    ]) expect(agentBypass(cmd), cmd).toBeUndefined();
    expect(agentBypass(undefined)).toBeUndefined();
  });
});
