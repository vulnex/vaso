import type { AgentType, Severity } from '../core/types.js';

export interface Advisory {
  id: string;
  title: string;
  agent: AgentType | '*';
  affectedVersions: string; // semver constraint, e.g. ">=1.0.0 <1.5.3"
  fixedVersion?: string;
  severity: Severity;
  description: string;
  reference?: string;
  published: string; // ISO date
  exploitAvailable?: boolean;
  eolNotice?: boolean;
  tags?: string[];
  /** Dot-path config key + value regex to match against parsed configs */
  configPattern?: { key: string; valuePattern: string };
  /** Dependency name for package.json/Cargo.toml scanning */
  affectedDependency?: { name: string; versionConstraint: string };
}

export interface AdvisoryFeedMetadata {
  lastUpdated: string;
  feedVersion: number;
  feedUrl: string;
  lastCheckAt: string;
}

export interface AdvisoryFeedData {
  advisories: Advisory[];
}

export interface AdvisoryFeed {
  meta: {
    version: number;
    timestamp: string;
    description: string;
  };
  data: AdvisoryFeedData;
}

export interface AdvisoryUpdateResult {
  success: boolean;
  message: string;
  newAdvisories?: number;
  feedVersion?: number;
}
