import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation } from '../core/types.js';

export class AdapterRegistry {
  private adapters: AgentAdapter[] = [];

  register(adapter: AgentAdapter): void {
    this.adapters.push(adapter);
  }

  async detectAll(options?: DetectOptions): Promise<AgentInstallation[]> {
    const results = await Promise.allSettled(
      this.adapters.map(a => a.detect(options))
    );

    return results
      .filter((r): r is PromiseFulfilledResult<AgentInstallation[]> =>
        r.status === 'fulfilled'
      )
      .flatMap(r => r.value);
  }

  getAdapters(): AgentAdapter[] {
    return [...this.adapters];
  }
}

export const adapterRegistry = new AdapterRegistry();
