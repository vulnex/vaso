import type { AgentAdapter } from './adapter.js';
import { adapterRegistry } from './registry.js';
import { openclawAdapter } from './openclaw.js';
import { nanoclawAdapter } from './nanoclaw.js';
import { picoclawAdapter } from './picoclaw.js';
import { ironclawAdapter } from './ironclaw.js';
import { nanobotAdapter } from './nanobot.js';
import { zeroclawAdapter } from './zeroclaw.js';
import { nemoclawAdapter } from './nemoclaw.js';
import { hermesAdapter } from './hermes.js';
import { lyrieAdapter } from './lyrie.js';
import { atomicAgentAdapter } from './atomic-agent.js';
import { claudeCodeAdapter } from './claude-code.js';
import { claudeDesktopAdapter } from './claude-desktop.js';
import { chatgptDesktopAdapter } from './chatgpt-desktop.js';
import { codexAdapter } from './codex.js';
import { opencodeAdapter } from './opencode.js';
import { geminiAdapter } from './gemini.js';
import { qwenCodeAdapter } from './qwen-code.js';
import { copilotCliAdapter } from './copilot-cli.js';
import { cursorCliAdapter } from './cursor-cli.js';
import { windsurfAdapter } from './windsurf.js';
import { devinAdapter } from './devin.js';
import { metaMuseAdapter } from './meta-muse.js';
import { cometAdapter } from './comet.js';
import { abacusAdapter } from './abacus.js';

/** Every built-in adapter, in registration order. */
export const allAdapters: AgentAdapter[] = [
  openclawAdapter,
  nanoclawAdapter,
  picoclawAdapter,
  ironclawAdapter,
  nanobotAdapter,
  zeroclawAdapter,
  nemoclawAdapter,
  hermesAdapter,
  lyrieAdapter,
  atomicAgentAdapter,
  claudeCodeAdapter,
  claudeDesktopAdapter,
  chatgptDesktopAdapter,
  codexAdapter,
  opencodeAdapter,
  geminiAdapter,
  qwenCodeAdapter,
  copilotCliAdapter,
  cursorCliAdapter,
  windsurfAdapter,
  devinAdapter,
  metaMuseAdapter,
  cometAdapter,
  abacusAdapter,
];

/** Register every built-in adapter into the shared adapterRegistry —
 *  the adapter-side counterpart of registerAllChecks(). */
export function registerAllAdapters(): void {
  for (const adapter of allAdapters) {
    adapterRegistry.register(adapter);
  }
}
