import { describe, it, expect, vi } from 'vitest';
import { LinuxAssessmentEngine } from '../../src/compliance/linux/LinuxAssessmentEngine';
import { ComplianceEventBus } from '../../src/compliance/core/ComplianceEventBus';
import { createLogger } from '../../src/platform/core/logging/logger';
import type { LinuxConnectionProvider, LinuxSession } from '../../src/compliance/linux/connection/LinuxConnectionProvider';
import type { ComplianceControl } from '../../src/compliance/models/ComplianceControl';
import type { ComplianceContext, EvidenceRepository } from '../../src/compliance/core/ComplianceContext';
import type { CISBenchmark } from '../../src/compliance/models/CISBenchmark';

function control(id: string, collectionMethod: string): ComplianceControl {
  return {
    controlId: id,
    title: id,
    level: '1',
    automated: true,
    evidenceRequirements: [{ evidenceType: 'command-output', target: 'x', collectionMethod }],
    evaluationDefinition: { rules: [{ field: 'stdout', operator: 'equals', value: 'ok' }] },
    remediationMetadata: { summary: 'fix' },
  };
}

function makeContext(): ComplianceContext {
  const items: any[] = [];
  const evidenceRepository: EvidenceRepository = {
    add: (e) => items.push(e),
    list: () => items,
  };
  const benchmark: CISBenchmark = {
    benchmarkId: 'b', name: 'B', version: '1.0.0', platform: 'ubuntu-linux', profile: 'server-level-1', controls: [],
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
  };
}

describe('LinuxAssessmentEngine error isolation', () => {
  it('continues evaluating remaining controls after one control errors (PASS, FAIL, ERROR, PASS)', async () => {
    const provider: LinuxConnectionProvider = {
      connect: vi.fn().mockResolvedValue({ sessionId: 's1', assetId: 'asset-1', connectedAt: '' } as LinuxSession),
      disconnect: vi.fn().mockResolvedValue(undefined),
      isConnected: vi.fn().mockReturnValue(true),
      runAllowlistedOperation: vi.fn().mockImplementation(async (_session, operationId: string) => {
        if (operationId === 'op-2') throw new Error('simulated infrastructure failure');
        if (operationId === 'op-3') return { stdout: 'not-ok', stderr: '', exitCode: 0 };
        return { stdout: 'ok', stderr: '', exitCode: 0 };
      }),
    };

    const controls = [
      control('C1', 'op-1'), // PASS
      control('C2', 'op-2'), // ERROR (collection throws)
      control('C3', 'op-3'), // FAIL (rule doesn't match)
      control('C4', 'op-4'), // PASS
    ];

    const engine = new LinuxAssessmentEngine(provider, createLogger('test', 'error'));
    const results = await engine.assess(makeContext(), controls);

    expect(results).toHaveLength(4);
    expect(results.map((r) => r.status)).toEqual(['PASS', 'ERROR', 'FAIL', 'PASS']);
    // Connection is still cleanly closed even though one control errored.
    expect(provider.disconnect).toHaveBeenCalledOnce();
  });

  it('marks every requested control as ERROR (not silently dropped) when the initial connection fails, without crashing the assessment', async () => {
    const provider: LinuxConnectionProvider = {
      connect: vi.fn().mockRejectedValue(new Error('unreachable host')),
      disconnect: vi.fn(),
      isConnected: vi.fn().mockReturnValue(false),
      runAllowlistedOperation: vi.fn(),
    };
    const controls = [control('C1', 'op-1'), control('C2', 'op-2')];
    const engine = new LinuxAssessmentEngine(provider, createLogger('test', 'error'));
    const results = await engine.assess(makeContext(), controls);

    expect(results).toHaveLength(2);
    expect(results.every((r) => r.status === 'ERROR')).toBe(true);
    expect(provider.disconnect).not.toHaveBeenCalled();
  });

  it('disconnects the session even if a control throws an unexpected synchronous-looking error', async () => {
    const provider: LinuxConnectionProvider = {
      connect: vi.fn().mockResolvedValue({ sessionId: 's1', assetId: 'asset-1', connectedAt: '' } as LinuxSession),
      disconnect: vi.fn().mockResolvedValue(undefined),
      isConnected: vi.fn().mockReturnValue(true),
      runAllowlistedOperation: vi.fn().mockRejectedValue(new Error('boom')),
    };
    const engine = new LinuxAssessmentEngine(provider, createLogger('test', 'error'));
    const results = await engine.assess(makeContext(), [control('C1', 'op-1')]);
    expect(results[0].status).toBe('ERROR');
    expect(provider.disconnect).toHaveBeenCalledOnce();
  });
});
