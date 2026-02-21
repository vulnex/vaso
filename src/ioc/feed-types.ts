/**
 * Type definitions for the IOC threat feed format and local metadata.
 */

/** Serialized RegExp as plain strings for JSON transport */
export interface SerializedRegExp {
  source: string;
  flags?: string;
}

/** Serialized binary pattern for JSON transport */
export interface SerializedBinaryPattern {
  name: string;
  /** Hex string for buffer patterns, regex source for regex patterns */
  pattern: string;
  type: 'buffer' | 'regex';
  flags?: string;
}

/** Feed data — all fields optional to allow partial feeds */
export interface IOCFeedData {
  c2Ips?: string[];
  maliciousDomains?: string[];
  fileHashes?: string[];
  maliciousPublishers?: string[];
  maliciousSkillPatterns?: SerializedRegExp[];
  trustedSkillNames?: string[];
  trustedMCPPackages?: string[];
  binaryPatterns?: SerializedBinaryPattern[];
}

/** Top-level feed JSON structure */
export interface IOCFeed {
  meta: {
    version: number;
    timestamp: string;
    description: string;
  };
  data: IOCFeedData;
}

/** Persisted to ~/.vaso/ioc/metadata.json */
export interface IOCFeedMetadata {
  lastUpdated: string;
  feedVersion: number;
  feedUrl: string;
  lastCheckAt: string;
}

/** Result returned by fetchAndUpdateFeed() */
export interface UpdateResult {
  success: boolean;
  message: string;
  newIndicators?: {
    c2Ips: number;
    maliciousDomains: number;
    fileHashes: number;
    maliciousPublishers: number;
    maliciousSkillPatterns: number;
    trustedSkillNames: number;
    trustedMCPPackages: number;
    binaryPatterns: number;
  };
  feedVersion?: number;
}
