/**
 * Minimal dependency-injection container (service locator + factory registration).
 * Keeps engines loosely coupled and testable.
 */
export type Factory<T> = (c: Container) => T;

export class Container {
  private readonly singletons = new Map<string, unknown>();
  private readonly factories = new Map<string, Factory<unknown>>();

  register<T>(token: string, factory: Factory<T>, singleton = true): void {
    this.factories.set(token, factory as Factory<unknown>);
    if (!singleton) {
      // resolved on each get
    }
  }

  registerValue<T>(token: string, value: T): void {
    this.singletons.set(token, value);
  }

  get<T>(token: string): T {
    if (this.singletons.has(token)) return this.singletons.get(token) as T;
    const factory = this.factories.get(token);
    if (!factory) throw new Error(`DI: unknown token "${token}"`);
    const value = factory(this);
    this.singletons.set(token, value);
    return value as T;
  }

  has(token: string): boolean {
    return this.singletons.has(token) || this.factories.has(token);
  }
}

export const TOKENS = {
  Config: 'Config',
  Logger: 'Logger',
  PluginManager: 'PluginManager',
  BrowserEngine: 'BrowserEngine',
  SessionEngine: 'SessionEngine',
  DiscoveryEngine: 'DiscoveryEngine',
  ScanPlanningEngine: 'ScanPlanningEngine',
  PluginExecutionEngine: 'PluginExecutionEngine',
  ReconEngine: 'ReconEngine',
  AuthEngine: 'AuthEngine',
  AttackSurfaceEngine: 'AttackSurfaceEngine',
  VerificationEngine: 'VerificationEngine',
  EvidenceEngine: 'EvidenceEngine',
  RiskEngine: 'RiskEngine',
  ReportingEngine: 'ReportingEngine',
  ScanOrchestrator: 'ScanOrchestrator',
  ProjectStore: 'ProjectStore',
  // Compliance pipeline (additive — does not alter any DAST token above)
  ComplianceAssessmentEngine: 'ComplianceAssessmentEngine',
  ComplianceAssessmentStore: 'ComplianceAssessmentStore',
  CISBenchmarkManager: 'CISBenchmarkManager',
} as const;
