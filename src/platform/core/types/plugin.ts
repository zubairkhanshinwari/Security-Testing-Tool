import type { AttackSurface, AuthSession, Finding, PluginManifest, ScanRequest } from './finding';

export interface PluginContext {
  request: ScanRequest;
  attackSurface: AttackSurface;
  auth: AuthSession;
  page: any;
  browserContext: any;
  logger: {
    info: (msg: string, meta?: Record<string, unknown>) => void;
    warn: (msg: string, meta?: Record<string, unknown>) => void;
    error: (msg: string, meta?: Record<string, unknown>) => void;
    debug: (msg: string, meta?: Record<string, unknown>) => void;
  };
  config: Record<string, unknown>;
  selectedTypes: string[];
  /** Phase 6: endpoints to prioritize when incremental scanning */
  focusEndpoints?: string[];
  incremental?: boolean;
  /** Phase E: technology fingerprint for smart targeting */
  fingerprint?: Record<string, unknown>;
}

export interface DiscoveryResult {
  targets: Array<Record<string, unknown>>;
}

export interface ScanCandidate {
  id?: string;
  title: string;
  description?: string;
  endpoint: string;
  parameter?: string;
  method?: string;
  severityHint?: string;
  evidence?: unknown[];
  raw?: Record<string, unknown>;
  issueFound?: boolean;
}

/**
 * Security plugin contract — every module must implement these lifecycle methods.
 * Optional initialize/cleanup are invoked by PluginExecutionEngine (Phase 4).
 */
export interface SecurityPlugin {
  readonly manifest: PluginManifest;
  initialize?(ctx: PluginContext): Promise<void> | void;
  discover(ctx: PluginContext): Promise<DiscoveryResult>;
  scan(ctx: PluginContext, discovery: DiscoveryResult): Promise<ScanCandidate[]>;
  verify(ctx: PluginContext, candidates: ScanCandidate[]): Promise<Finding[]>;
  cleanup?(ctx: PluginContext): Promise<void> | void;
  report(findings: Finding[]): Promise<Record<string, unknown>>;
  score(findings: Finding[]): Promise<{ delta: number; notes: string[] }>;
}
