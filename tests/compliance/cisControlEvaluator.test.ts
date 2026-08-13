import { describe, it, expect, vi } from 'vitest';
import { DefaultCISControlEvaluator } from '../../src/compliance/cis/DefaultCISControlEvaluator';
import { LinuxCollector } from '../../src/compliance/linux/LinuxCollector';
import { LinuxEvidenceProvider } from '../../src/compliance/linux/LinuxEvidenceProvider';
import { ComplianceEventBus } from '../../src/compliance/core/ComplianceEventBus';
import { createLogger } from '../../src/platform/core/logging/logger';
import type { LinuxConnectionProvider, LinuxSession } from '../../src/compliance/linux/connection/LinuxConnectionProvider';
import type { ComplianceControl } from '../../src/compliance/models/ComplianceControl';
import type { ComplianceContext, EvidenceRepository } from '../../src/compliance/core/ComplianceContext';
import type { CISBenchmark } from '../../src/compliance/models/CISBenchmark';

const session: LinuxSession = { sessionId: 's1', assetId: 'asset-1', connectedAt: new Date().toISOString() };

function makeContext(overrides: Partial<ComplianceContext> = {}): ComplianceContext {
  const store: Record<string, unknown[]> = {};
  const evidenceRepository: EvidenceRepository = {
    add: (e) => {
      (store[e.controlId] ||= []).push(e);
    },
    list: (controlId) => (controlId ? ((store[controlId] || []) as any) : Object.values(store).flat() as any),
  };
  const benchmark: CISBenchmark = {
    benchmarkId: 'cis-ubuntu-linux',
    name: 'Test',
    version: '1.0.0',
    platform: 'ubuntu-linux',
    profile: 'server-level-1',
    controls: [],
  };
  return {
    assessmentId: 'a1',
    target: { assetId: 'asset-1', hostname: 'h', port: 22, osFamily: 'ubuntu', createdAt: '' },
    benchmark,
    benchmarkVersion: '1.0.0',
    profile: 'server-level-1',
    selectedControls: [],
    credentialRef: { type: 'env', ref: 'X' },
    evidenceRepository,
    configuration: { commandTimeoutMs: 5000, rateLimitPerHostPerMinute: 30, maxControlsPerAssessment: 500 },
    logger: createLogger('test', 'error'),
    eventBus: new ComplianceEventBus(),
    ...overrides,
  };
}

function providerReturning(stdout: string): LinuxConnectionProvider {
  return {
    connect: vi.fn(),
    disconnect: vi.fn(),
    isConnected: vi.fn().mockReturnValue(true),
    runAllowlistedOperation: async () => ({ stdout, stderr: '', exitCode: 0 }),
  };
}

function baseControl(overrides: Partial<ComplianceControl> = {}): ComplianceControl {
  return {
    controlId: 'EX-1.1',
    title: 'Ensure SSH root login is disabled',
    level: '1',
    automated: true,
    evidenceRequirements: [
      { evidenceType: 'file-content', target: '/etc/ssh/sshd_config', collectionMethod: 'read-file:/etc/ssh/sshd_config' },
    ],
    evaluationDefinition: {
      rules: [{ field: 'content', operator: 'matches-regex', value: '(?im)^\\s*PermitRootLogin\\s+no\\s*$' }],
      failureReason: 'PermitRootLogin is not set to no.',
    },
    remediationMetadata: { summary: 'Set PermitRootLogin no' },
    ...overrides,
  };
}

describe('DefaultCISControlEvaluator', () => {
  it('returns PASS when evidence satisfies every evaluation rule', async () => {
    const provider = providerReturning('PermitRootLogin no\n');
    const evaluator = new DefaultCISControlEvaluator(session, new LinuxCollector(provider, createLogger('test', 'error')), new LinuxEvidenceProvider());
    const control = baseControl();
    const context = makeContext();

    expect(evaluator.canEvaluate(control)).toBe(true);
    const evidence = await evaluator.collectEvidence(control, context);
    const result = await evaluator.evaluate(control, evidence, context);

    expect(result.status).toBe('PASS');
    expect(result.confidence).toBe('high');
    expect(evaluator.getResult()).toBe(result);
  });

  it('returns FAIL when evidence violates the evaluation rule', async () => {
    const provider = providerReturning('PermitRootLogin yes\n');
    const evaluator = new DefaultCISControlEvaluator(session, new LinuxCollector(provider, createLogger('test', 'error')), new LinuxEvidenceProvider());
    const control = baseControl();
    const context = makeContext();

    const evidence = await evaluator.collectEvidence(control, context);
    const result = await evaluator.evaluate(control, evidence, context);

    expect(result.status).toBe('FAIL');
    expect(result.reason).toContain('PermitRootLogin is not set to no');
    expect(result.remediation).toBe('Set PermitRootLogin no');
  });

  it('returns MANUAL_REVIEW for a control marked automated=false, without ever collecting evidence', async () => {
    const provider = providerReturning('should not be called');
    const runSpy = vi.spyOn(provider, 'runAllowlistedOperation');
    const evaluator = new DefaultCISControlEvaluator(session, new LinuxCollector(provider, createLogger('test', 'error')), new LinuxEvidenceProvider());
    const control = baseControl({ automated: false, evaluationDefinition: undefined });
    const context = makeContext();

    expect(evaluator.canEvaluate(control)).toBe(false);
    const result = await evaluator.evaluate(control, [], context);
    expect(result.status).toBe('MANUAL_REVIEW');
    expect(runSpy).not.toHaveBeenCalled();
  });

  it('returns MANUAL_REVIEW (never PASS) when an automated control has no evidence collected', async () => {
    const provider = providerReturning('irrelevant');
    const evaluator = new DefaultCISControlEvaluator(session, new LinuxCollector(provider, createLogger('test', 'error')), new LinuxEvidenceProvider());
    const control = baseControl();
    const context = makeContext();

    const result = await evaluator.evaluate(control, [], context);
    expect(result.status).toBe('MANUAL_REVIEW');
    expect(result.status).not.toBe('PASS');
  });

  it('returns ERROR when evidence collection failed rather than defaulting to PASS or FAIL', async () => {
    const failingProvider: LinuxConnectionProvider = {
      connect: vi.fn(),
      disconnect: vi.fn(),
      isConnected: vi.fn().mockReturnValue(true),
      runAllowlistedOperation: async () => {
        throw new Error('connection reset');
      },
    };
    const evaluator = new DefaultCISControlEvaluator(
      session,
      new LinuxCollector(failingProvider, createLogger('test', 'error')),
      new LinuxEvidenceProvider(),
    );
    const control = baseControl();
    const context = makeContext();

    const evidence = await evaluator.collectEvidence(control, context);
    const result = await evaluator.evaluate(control, evidence, context);

    expect(result.status).toBe('ERROR');
    expect(result.status).not.toBe('PASS');
  });
});
