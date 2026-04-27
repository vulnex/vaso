import type { ZoneGraph } from './types.js';
import type { CheckRegistry } from './check-registry.js';
import type { AdapterRegistry } from '../adapters/registry.js';

export interface ZoneGraphValidationError {
  adapter: string;
  rule: string;
  detail: string;
}

export function validateZoneGraph(
  graph: ZoneGraph,
  knownCheckIds: ReadonlySet<string>,
  adapterName = '<graph>',
): ZoneGraphValidationError[] {
  const errors: ZoneGraphValidationError[] = [];

  const zoneIds = new Set(graph.zones.map(z => z.id));
  const componentIds = new Set(graph.components.map(c => c.id));

  const trustLevels = new Map<number, string>();
  for (const zone of graph.zones) {
    if (!zone.id) {
      errors.push({ adapter: adapterName, rule: 'zone-id-nonempty', detail: 'zone id must be a non-empty string' });
      continue;
    }
    const existing = trustLevels.get(zone.trustLevel);
    if (existing !== undefined) {
      errors.push({
        adapter: adapterName,
        rule: 'zone-trust-level-unique',
        detail: `zones "${existing}" and "${zone.id}" share trustLevel ${zone.trustLevel}`,
      });
    } else {
      trustLevels.set(zone.trustLevel, zone.id);
    }
  }

  for (const component of graph.components) {
    if (!component.id) {
      errors.push({ adapter: adapterName, rule: 'component-id-nonempty', detail: 'component id must be a non-empty string' });
      continue;
    }
    if (!zoneIds.has(component.zone)) {
      errors.push({
        adapter: adapterName,
        rule: 'component-zone-exists',
        detail: `component "${component.id}" references unknown zone "${component.zone}"`,
      });
    }
    for (const checkId of component.guardCheckIds ?? []) {
      if (!knownCheckIds.has(checkId)) {
        errors.push({
          adapter: adapterName,
          rule: 'check-id-registered',
          detail: `component "${component.id}" guardCheckIds references unknown check "${checkId}"`,
        });
      }
    }
  }

  const trustByComponent = new Map<string, number>();
  for (const component of graph.components) {
    const zone = graph.zones.find(z => z.id === component.zone);
    if (zone) trustByComponent.set(component.id, zone.trustLevel);
  }

  for (const edge of graph.edges) {
    if (!edge.from || !edge.to) {
      errors.push({ adapter: adapterName, rule: 'edge-endpoints-nonempty', detail: 'edge from/to must be non-empty strings' });
      continue;
    }
    if (!componentIds.has(edge.from)) {
      errors.push({
        adapter: adapterName,
        rule: 'edge-endpoint-exists',
        detail: `edge.from "${edge.from}" → "${edge.to}" references unknown component`,
      });
    }
    if (!componentIds.has(edge.to)) {
      errors.push({
        adapter: adapterName,
        rule: 'edge-endpoint-exists',
        detail: `edge.to "${edge.from}" → "${edge.to}" references unknown component`,
      });
    }
    for (const checkId of edge.triggerCheckIds ?? []) {
      if (!knownCheckIds.has(checkId)) {
        errors.push({
          adapter: adapterName,
          rule: 'check-id-registered',
          detail: `edge "${edge.from}" → "${edge.to}" triggerCheckIds references unknown check "${checkId}"`,
        });
      }
    }

    const fromTrust = trustByComponent.get(edge.from);
    const toTrust = trustByComponent.get(edge.to);
    if (
      fromTrust !== undefined &&
      toTrust !== undefined &&
      toTrust - fromTrust >= 2 &&
      (!edge.triggerCheckIds || edge.triggerCheckIds.length === 0)
    ) {
      errors.push({
        adapter: adapterName,
        rule: 'inversion-requires-trigger',
        detail: `edge "${edge.from}" → "${edge.to}" crosses ${toTrust - fromTrust} trust levels but has no triggerCheckIds (always-on inversion)`,
      });
    }
  }

  return errors;
}

export function validateAllZoneGraphs(
  adapters: AdapterRegistry,
  checks: CheckRegistry,
  fallback: () => ZoneGraph,
): ZoneGraphValidationError[] {
  const knownCheckIds = new Set(checks.getAll().map(c => c.id));
  const errors: ZoneGraphValidationError[] = [];

  for (const adapter of adapters.getAdapters()) {
    const graph = adapter.getZoneGraph?.() ?? fallback();
    errors.push(...validateZoneGraph(graph, knownCheckIds, adapter.agent));
  }

  return errors;
}

export class ZoneGraphValidationFailedError extends Error {
  constructor(public readonly errors: ZoneGraphValidationError[]) {
    const lines = errors.map(e => `  [${e.adapter}] ${e.rule}: ${e.detail}`);
    super(`ZoneGraph validation failed (${errors.length} error${errors.length === 1 ? '' : 's'}):\n${lines.join('\n')}`);
    this.name = 'ZoneGraphValidationFailedError';
  }
}

export function assertZoneGraphsValid(
  adapters: AdapterRegistry,
  checks: CheckRegistry,
  fallback: () => ZoneGraph,
): void {
  const errors = validateAllZoneGraphs(adapters, checks, fallback);
  if (errors.length > 0) throw new ZoneGraphValidationFailedError(errors);
}
