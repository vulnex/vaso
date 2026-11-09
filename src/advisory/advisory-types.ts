import type { AgentType, Platform, Severity } from '../core/types.js';

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
  affectedDependency?: {
    name: string;
    versionConstraint: string;
    /** Registry the name belongs to; absent means npm. PyPI's `mcp` is not npm's `mcp`. */
    ecosystem?: 'npm' | 'pypi';
  };
  /**
   * The feature of the dependency the vulnerability needs (an HTTP transport,
   * the OAuth client). When the depending code is available and doesn't match
   * `sourcePattern`, a match is reported as not applying to that code.
   */
  appliesWhen?: { sourcePattern: string; usage: string };
  /**
   * Host platforms the vulnerability exists on (`['win32']` for a Windows-only
   * path-handling bug). Absent means every platform.
   */
  platforms?: Platform[];
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
