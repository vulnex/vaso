import type { AgentAdapter } from './adapter.js';
import type { AgentInstallation } from '../core/types.js';

export class AdapterRegistry {
  private adapters: AgentAdapter[] = [];

  register(adapter: AgentAdapter): void {
    this.adapters.push(adapter);
  }

  async detectAll(): Promise<AgentInstallation[]> {
    const results = await Promise.allSettled(
      this.adapters.map(a => a.detect())
    );

    return results
      .filter((r): r is PromiseFulfilledResult<AgentInstallation | null> =>
        r.status === 'fulfilled' && r.value !== null
      )
      .map(r => r.value!);
  }

  getAdapters(): AgentAdapter[] {
    return [...this.adapters];
  }
}

export const adapterRegistry = new AdapterRegistry();
