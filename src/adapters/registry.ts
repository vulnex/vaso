import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, AgentType } from '../core/types.js';

export interface AdapterDetectionError {
  agent: AgentType;
  displayName: string;
  message: string;
}

export interface AdapterDetectionResult {
  installations: AgentInstallation[];
  errors: AdapterDetectionError[];
}

export class AdapterRegistry {
  private adapters: AgentAdapter[] = [];

  register(adapter: AgentAdapter): void {
    this.adapters.push(adapter);
  }

  async detectAllDetailed(options?: DetectOptions): Promise<AdapterDetectionResult> {
    const results = await Promise.allSettled(
      this.adapters.map(a => a.detect(options))
    );

    const installations: AgentInstallation[] = [];
    const errors: AdapterDetectionError[] = [];

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const adapter = this.adapters[i];
      if (result.status === 'fulfilled') {
        installations.push(...result.value);
      } else {
        errors.push({
          agent: adapter.agent,
          displayName: adapter.displayName,
          message: result.reason instanceof Error ? result.reason.message : String(result.reason),
        });
      }
    }

    return { installations, errors };
  }

  async detectAll(options?: DetectOptions): Promise<AgentInstallation[]> {
    return (await this.detectAllDetailed(options)).installations;
  }

  getAdapters(): AgentAdapter[] {
    return [...this.adapters];
  }
}

export const adapterRegistry = new AdapterRegistry();
