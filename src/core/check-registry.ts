import type { CheckModule, AgentType, CheckCategory } from './types.js';

export class CheckRegistry {
  private checks: CheckModule[] = [];

  register(check: CheckModule): void {
    if (this.checks.some(c => c.id === check.id)) {
      throw new Error(`Check "${check.id}" is already registered`);
    }
    this.checks.push(check);
  }

  registerAll(checks: CheckModule[]): void {
    for (const check of checks) {
      this.register(check);
    }
  }

  getAll(): CheckModule[] {
    return [...this.checks];
  }

  getByCategory(category: CheckCategory): CheckModule[] {
    return this.checks.filter(c => c.category === category);
  }

  getForAgent(agent: AgentType): CheckModule[] {
    return this.checks.filter(c =>
      !c.supportedAgents || c.supportedAgents.includes(agent)
    );
  }

  getForPlatform(platform: NodeJS.Platform): CheckModule[] {
    return this.checks.filter(c =>
      !c.supportedPlatforms || c.supportedPlatforms.includes(platform)
    );
  }

  getApplicable(agent: AgentType, platform: NodeJS.Platform): CheckModule[] {
    return this.checks.filter(c => {
      const agentMatch = !c.supportedAgents || c.supportedAgents.includes(agent);
      const platformMatch = !c.supportedPlatforms || c.supportedPlatforms.includes(platform);
      return agentMatch && platformMatch;
    });
  }

  count(): number {
    return this.checks.length;
  }
}

export const checkRegistry = new CheckRegistry();
