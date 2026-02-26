import { checkRegistry } from '../core/check-registry.js';
import { configChecks } from './config/index.js';
import { skillChecks } from './skills/index.js';
import { iocChecks } from './ioc/index.js';
import { networkChecks } from './network/index.js';
import { runtimeChecks } from './runtime/index.js';
import { mcpChecks } from './mcp/index.js';
import { ironclawChecks } from './ironclaw/index.js';
import { nanobotChecks } from './nanobot/index.js';
import { zeroclawChecks } from './zeroclaw/index.js';
import { policyChecks } from './policy/index.js';
import { advisoryChecks } from './advisory/index.js';

export function registerAllChecks(): void {
  checkRegistry.registerAll(configChecks);
  checkRegistry.registerAll(skillChecks);
  checkRegistry.registerAll(iocChecks);
  checkRegistry.registerAll(networkChecks);
  checkRegistry.registerAll(runtimeChecks);
  checkRegistry.registerAll(mcpChecks);
  checkRegistry.registerAll(ironclawChecks);
  checkRegistry.registerAll(nanobotChecks);
  checkRegistry.registerAll(zeroclawChecks);
  checkRegistry.registerAll(policyChecks);
  checkRegistry.registerAll(advisoryChecks);
}
