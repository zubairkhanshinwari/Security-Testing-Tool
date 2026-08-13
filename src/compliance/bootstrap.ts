import path from 'path';
import type { Container } from '../platform/core/di/container';
import { TOKENS } from '../platform/core/di/container';
import type { Logger } from '../platform/core/logging/logger';
import { CISBenchmarkManager } from './cis/CISBenchmarkManager';
import { CISBenchmarkRegistry } from './cis/CISBenchmarkRegistry';
import { SshLinuxConnectionProvider } from './linux/connection/SshLinuxConnectionProvider';
import { LinuxAssessmentEngine } from './linux/LinuxAssessmentEngine';
import { CompliancePlanner } from './planning/CompliancePlanner';
import { ComplianceAssessmentEngine } from './core/ComplianceAssessmentEngine';
import { ComplianceAssessmentStore } from './persistence/ComplianceAssessmentStore';
import { ComplianceReportingEngine } from './reporting/ComplianceReportingEngine';

export interface CompliancePlatform {
  complianceEngine: ComplianceAssessmentEngine;
  complianceStore: ComplianceAssessmentStore;
  complianceReporting: ComplianceReportingEngine;
  benchmarkManager: CISBenchmarkManager;
}

/**
 * Separate composition root for the compliance pipeline. Deliberately not
 * merged into src/platform/bootstrap.ts's construction sequence — it is
 * called alongside bootstrap(), from server.ts, and registers its own DI
 * tokens into the same Container instance without touching how any DAST
 * engine is constructed there.
 */
export function bootstrapCompliance(rootDir: string, container: Container, logger: Logger): CompliancePlatform {
  const benchmarksDir = path.join(rootDir, 'src', 'benchmarks');
  const benchmarkManager = new CISBenchmarkManager(
    benchmarksDir,
    logger.child('compliance:benchmark'),
    new CISBenchmarkRegistry(),
  );

  const connectionProvider = new SshLinuxConnectionProvider(logger.child('compliance:ssh'));
  const linuxAssessmentEngine = new LinuxAssessmentEngine(connectionProvider, logger.child('compliance:linux'));
  const planner = new CompliancePlanner();

  const complianceStore = new ComplianceAssessmentStore(
    path.join(rootDir, 'data', 'compliance', 'assessments'),
    path.join(rootDir, 'data', 'compliance', 'evidence'),
    logger.child('compliance:store'),
  );

  const complianceEngine = new ComplianceAssessmentEngine(
    benchmarkManager,
    linuxAssessmentEngine,
    planner,
    (assessmentId) => complianceStore.evidenceRepositoryFor(assessmentId),
    logger.child('compliance:engine'),
  );

  const complianceReporting = new ComplianceReportingEngine(
    path.join(rootDir, 'reports'),
    logger.child('compliance:report'),
  );

  container.registerValue(TOKENS.ComplianceAssessmentEngine, complianceEngine);
  container.registerValue(TOKENS.ComplianceAssessmentStore, complianceStore);
  container.registerValue(TOKENS.CISBenchmarkManager, benchmarkManager);

  return { complianceEngine, complianceStore, complianceReporting, benchmarkManager };
}
