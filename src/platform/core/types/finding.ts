/**
 * Enterprise finding schema aligned with OWASP / CWE / CAPEC / CVSS / NIST mappings.
 */

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type Confidence =
  | 'Confirmed'
  | 'High Confidence'
  | 'Medium Confidence'
  | 'Low Confidence'
  | 'Informational'
  /** @deprecated legacy aliases still accepted at ingest */
  | 'Likely'
  | 'Possible';
export type TestMode = 'passive' | 'active-safe' | 'authenticated';

export interface CvssV4 {
  vector: string;
  score: number;
  severity: Severity;
}

export interface HttpEvidence {
  request?: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
  };
  response?: {
    status: number;
    headers?: Record<string, string>;
    bodySnippet?: string;
    timingMs?: number;
  };
}

export interface StandardMappings {
  owaspTop10?: string[];
  owaspApiTop10?: string[];
  owaspAsvs?: string[];
  owaspMasvs?: string[];
  cwe: string[];
  capec?: string[];
  mitreAttack?: string[];
  nist80053?: string[];
}

export interface Finding {
  id: string;
  pluginId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  cvss?: CvssV4 | null;
  mappings: StandardMappings;
  affectedUrl: string;
  affectedEndpoint: string;
  parameter?: string;
  method?: string;
  evidence: Array<string | Record<string, unknown>>;
  http?: HttpEvidence[];
  screenshotPath?: string | null;
  screenshotFileName?: string | null;
  screenshotCaption?: string | null;
  /** PNG as base64 for HTML/PDF embedding */
  screenshotBase64?: string | null;
  screenshotLiveBase64?: string | null;
  impact: string;
  remediation: string;
  references: string[];
  status: 'Confirmed' | 'Likely' | 'Possible' | 'Informational' | 'Pass' | 'FalsePositive';
  issueFound: boolean;
  testMode: TestMode;
  module?: string;
  featureName?: string;
  techniques?: string[];
  /** Populated by VerificationEngine (Phase 5) */
  verification?: {
    signalCount: number;
    signals: string[];
    retestRecommended?: boolean;
  };
  /** Legacy bridge fields */
  cwe?: string[];
  owasp?: string;
  [key: string]: unknown;
}

export interface PluginManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  category: string;
  enabledByDefault: boolean;
  recommended: boolean;
  securityTypeIds: string[];
  owasp: string[];
  cwe: string[];
  modes: TestMode[];
  tags?: string[];
}

export interface AttackSurface {
  hosts: string[];
  subdomains: string[];
  pages: string[];
  endpoints: Array<{
    url: string;
    method: string;
    source?: string;
    authHeader?: string | null;
  }>;
  parameters: Array<{ endpoint: string; name: string; location: string }>;
  forms: unknown[];
  cookies: string[];
  headers: Record<string, string>;
  frameworks: string[];
  libraries: string[];
  authEndpoints: string[];
  apiBases: string[];
  websockets: string[];
  graphql: string[];
  openapi: string[];
  storageKeys: string[];
  robots?: string | null;
  sitemapUrls?: string[];
  raw?: Record<string, unknown>;
}

export interface AuthSession {
  ok: boolean;
  type: 'none' | 'password' | 'jwt' | 'bearer' | 'apiKey' | 'cookie' | 'oauth' | 'discovered';
  token?: string | null;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  message?: string;
  endpoint?: string;
}

export interface ScanRequest {
  targetUrl: string;
  projectId?: string;
  projectName?: string;
  environment?: string;
  testerName?: string;
  username?: string | null;
  password?: string | null;
  authHeader?: string | null;
  apiKey?: string | null;
  securityTypes?: string[];
  pluginIds?: string[];
  authorized: boolean;
  mode?: TestMode;
  /** Phase 6: reuse project baseline; prioritize new endpoints + prior confirmed issues */
  incremental?: boolean;
  /** Precision pack: quick | standard | deep */
  profile?: 'quick' | 'standard' | 'deep' | string;
  signal?: AbortSignal;
  onProgress?: (p: { stage: string; message: string; percent?: number }) => void;
}

export interface RiskSummary {
  overallScore: number;
  overallRisk: Severity;
  severityCounts: Record<Severity, number>;
  owaspCoverage: Record<string, number>;
  riskPriority: Array<{ findingId: string; priority: number; rationale: string }>;
}

export interface ScanResult {
  meta: Record<string, unknown>;
  attackSurface: AttackSurface;
  findings: Finding[];
  risk: RiskSummary;
  assessmentSummary: Array<Record<string, unknown>>;
  stats: Record<string, unknown>;
  recon?: Record<string, unknown>;
  /** Compatibility with v1 report builders */
  [key: string]: unknown;
}
