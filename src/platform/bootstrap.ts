import path from 'path';
import { Container, TOKENS } from './core/di/container';
import { loadConfig } from './core/config/loadConfig';
import { createLogger } from './core/logging/logger';
import { PluginManager } from './plugins/PluginManager';
import { BrowserEngine } from './engines/browser/BrowserEngine';
import { SessionEngine } from './engines/session/SessionEngine';
import { DiscoveryEngine } from './engines/discovery/DiscoveryEngine';
import { ScanPlanningEngine } from './engines/planning/ScanPlanningEngine';
import { PluginExecutionEngine } from './engines/execution/PluginExecutionEngine';
import { ReconEngine } from './engines/recon/ReconEngine';
import { AuthEngine } from './engines/auth/AuthEngine';
import { AttackSurfaceEngine } from './engines/attack-surface/AttackSurfaceEngine';
import { VerificationEngine } from './engines/verification/VerificationEngine';
import { EvidenceEngine } from './engines/evidence/EvidenceEngine';
import { RiskEngine } from './engines/risk/RiskEngine';
import { ReportingEngine } from './engines/reporting/ReportingEngine';
import { ScanOrchestrator } from './engines/orchestrator/ScanOrchestrator';
import { ProjectStore } from './dashboard/ProjectStore';

export async function bootstrap(rootDir = process.cwd()) {
  const config = loadConfig(rootDir);
  const logger = createLogger(
    'secureassess',
    (config.logging?.level as any) || 'info',
    Boolean(config.logging?.json),
  );

  const container = new Container();
  container.registerValue(TOKENS.Config, config);
  container.registerValue(TOKENS.Logger, logger);

  const modulesDir = path.join(rootDir, config.plugins.directory || 'modules');
  const pluginManager = new PluginManager(
    modulesDir,
    logger.child('plugins'),
    config.plugins.disabled || [],
  );
  if (config.plugins.autoRegister !== false) {
    await pluginManager.autoRegister();
  }
  container.registerValue(TOKENS.PluginManager, pluginManager);

  const projectsDir = path.join(rootDir, config.storage.projectsDir);
  const scansDir = path.join(rootDir, config.storage.scansDir);
  const store = new ProjectStore(projectsDir, scansDir, logger.child('store'));
  container.registerValue(TOKENS.ProjectStore, store);

  const browserEngine = new BrowserEngine(logger.child('browser'), config as any);
  const recon = new ReconEngine(logger.child('recon'));
  const auth = new AuthEngine(logger.child('auth'));
  const discovery = new DiscoveryEngine(logger.child('discovery'), recon, browserEngine);
  const sessionEngine = new SessionEngine(logger.child('session'), auth, browserEngine);
  const surface = new AttackSurfaceEngine(logger.child('surface'));
  const planner = new ScanPlanningEngine(logger.child('planner'), pluginManager);
  const executor = new PluginExecutionEngine(logger.child('executor'), config as any);
  const verification = new VerificationEngine(logger.child('verify'));
  const evidence = new EvidenceEngine(logger.child('evidence'), config as any);
  const risk = new RiskEngine(logger.child('risk'));
  const reporting = new ReportingEngine(
    path.join(rootDir, config.storage.reportsDir),
    logger.child('report'),
    config as any,
  );

  container.registerValue(TOKENS.BrowserEngine, browserEngine);
  container.registerValue(TOKENS.SessionEngine, sessionEngine);
  container.registerValue(TOKENS.DiscoveryEngine, discovery);
  container.registerValue(TOKENS.ScanPlanningEngine, planner);
  container.registerValue(TOKENS.PluginExecutionEngine, executor);
  container.registerValue(TOKENS.ReconEngine, recon);
  container.registerValue(TOKENS.AuthEngine, auth);
  container.registerValue(TOKENS.AttackSurfaceEngine, surface);
  container.registerValue(TOKENS.VerificationEngine, verification);
  container.registerValue(TOKENS.EvidenceEngine, evidence);
  container.registerValue(TOKENS.RiskEngine, risk);
  container.registerValue(TOKENS.ReportingEngine, reporting);

  const orchestrator = new ScanOrchestrator(
    logger.child('orchestrator'),
    browserEngine,
    sessionEngine,
    discovery,
    surface,
    planner,
    executor,
    verification,
    evidence,
    risk,
    reporting,
    store,
    config as any,
    pluginManager,
  );
  container.registerValue(TOKENS.ScanOrchestrator, orchestrator);

  return { container, config, logger, orchestrator, pluginManager, store };
}

export type Platform = Awaited<ReturnType<typeof bootstrap>>;
