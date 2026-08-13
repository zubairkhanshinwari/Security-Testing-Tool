import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import path from 'path';
import { ComplianceAssessmentEngine } from '../../src/compliance/core/ComplianceAssessmentEngine';
import { CISBenchmarkManager } from '../../src/compliance/cis/CISBenchmarkManager';
import { LinuxAssessmentEngine } from '../../src/compliance/linux/LinuxAssessmentEngine';
import { CompliancePlanner } from '../../src/compliance/planning/CompliancePlanner';
import { createLogger } from '../../src/platform/core/logging/logger';
import type { LinuxConnectionProvider, LinuxSession } from '../../src/compliance/linux/connection/LinuxConnectionProvider';
import type { EvidenceRepository } from '../../src/compliance/core/ComplianceContext';

const BENCHMARKS_DIR = path.join(__dirname, '..', '..', 'src', 'benchmarks');

function inMemoryEvidenceRepo(): EvidenceRepository {
  const items: any[] = [];
  return {
    add: (e) => items.push(e),
    list: (controlId) => (controlId ? items.filter((i) => i.controlId === controlId) : [...items]),
  };
}

describe('ComplianceAssessmentEngine end-to-end (mocked connection, real benchmark fixture)', () => {
  beforeEach(() => {
    process.env.SECUREASSESS_LINUX_ALLOWLIST = 'test-host.example';
  });
  afterEach(() => {
    delete process.env.SECUREASSESS_LINUX_ALLOWLIST;
  });

  it('runs a full assessment against the shipped example benchmark and returns a well-formed ComplianceAssessment', async () => {
    const provider: LinuxConnectionProvider = {
      connect: vi.fn().mockResolvedValue({ sessionId: 's1', assetId: 'a', connectedAt: '' } as LinuxSession),
      disconnect: vi.fn().mockResolvedValue(undefined),
      isConnected: vi.fn().mockReturnValue(true),
      runAllowlistedOperation: vi.fn().mockImplementation(async (_session, operationId: string) => {
        if (operationId.startsWith('read-file:/etc/ssh/sshd_config')) {
          return { stdout: 'PermitRootLogin no\n', stderr: '', exitCode: 0 };
        }
        if (operationId.startsWith('stat-file')) {
          return { stdout: '644 root root\n', stderr: '', exitCode: 0 };
        }
        if (operationId.startsWith('service-status')) {
          return { stdout: 'active\n', stderr: '', exitCode: 0 };
        }
        if (operationId.startsWith('package-installed')) {
          return { stdout: 'unknown ok not-installed\n', stderr: '', exitCode: 1 };
        }
        if (operationId.startsWith('sysctl-get')) {
          return { stdout: '0\n', stderr: '', exitCode: 0 };
        }
        return { stdout: '', stderr: '', exitCode: 0 };
      }),
    };

    const benchmarkManager = new CISBenchmarkManager(BENCHMARKS_DIR, createLogger('test', 'error'));
    const linuxAssessmentEngine = new LinuxAssessmentEngine(provider, createLogger('test', 'error'));
    const engine = new ComplianceAssessmentEngine(
      benchmarkManager,
      linuxAssessmentEngine,
      new CompliancePlanner(),
      () => inMemoryEvidenceRepo(),
      createLogger('test', 'error'),
    );

    const assessment = await engine.run({
      target: { hostname: 'test-host.example', port: 22, osFamily: 'ubuntu' },
      benchmarkId: 'cis-ubuntu-linux',
      benchmarkVersion: '1.0.0',
      profile: 'all',
      credentialRef: { type: 'env', ref: 'TEST_KEY' },
      authorized: true,
    });

    expect(assessment.status).toBe('completed');
    expect(assessment.controlResults.length).toBeGreaterThan(0);
    expect(assessment.metrics).toBeDefined();
    expect(assessment.metrics!.totalControls).toBe(assessment.controlResults.length);

    // At least the manual control (EX-2.2) should surface as MANUAL_REVIEW, never hidden/dropped.
    const manual = assessment.controlResults.find((r) => r.controlId === 'EX-2.2');
    expect(manual?.status).toBe('MANUAL_REVIEW');

    // The SSH root-login control should PASS given the mocked "PermitRootLogin no" evidence.
    const sshRoot = assessment.controlResults.find((r) => r.controlId === 'EX-1.1');
    expect(sshRoot?.status).toBe('PASS');
  });

  it('throws before starting when authorized is false', async () => {
    const provider: LinuxConnectionProvider = {
      connect: vi.fn(),
      disconnect: vi.fn(),
      isConnected: vi.fn(),
      runAllowlistedOperation: vi.fn(),
    };
    const benchmarkManager = new CISBenchmarkManager(BENCHMARKS_DIR, createLogger('test', 'error'));
    const engine = new ComplianceAssessmentEngine(
      benchmarkManager,
      new LinuxAssessmentEngine(provider, createLogger('test', 'error')),
      new CompliancePlanner(),
      () => inMemoryEvidenceRepo(),
      createLogger('test', 'error'),
    );

    await expect(
      engine.run({
        target: { hostname: 'test-host.example', port: 22, osFamily: 'ubuntu' },
        benchmarkId: 'cis-ubuntu-linux',
        benchmarkVersion: '1.0.0',
        profile: 'all',
        credentialRef: { type: 'env', ref: 'TEST_KEY' },
        authorized: false,
      }),
    ).rejects.toThrow(/authorization/i);
    expect(provider.connect).not.toHaveBeenCalled();
  });

  it('throws when the target host is not on the authorized allowlist', async () => {
    delete process.env.SECUREASSESS_LINUX_ALLOWLIST;
    const provider: LinuxConnectionProvider = {
      connect: vi.fn(),
      disconnect: vi.fn(),
      isConnected: vi.fn(),
      runAllowlistedOperation: vi.fn(),
    };
    const benchmarkManager = new CISBenchmarkManager(BENCHMARKS_DIR, createLogger('test', 'error'));
    const engine = new ComplianceAssessmentEngine(
      benchmarkManager,
      new LinuxAssessmentEngine(provider, createLogger('test', 'error')),
      new CompliancePlanner(),
      () => inMemoryEvidenceRepo(),
      createLogger('test', 'error'),
    );

    await expect(
      engine.run({
        target: { hostname: 'not-allowlisted.example', port: 22, osFamily: 'ubuntu' },
        benchmarkId: 'cis-ubuntu-linux',
        benchmarkVersion: '1.0.0',
        profile: 'all',
        credentialRef: { type: 'env', ref: 'TEST_KEY' },
        authorized: true,
      }),
    ).rejects.toThrow();
    expect(provider.connect).not.toHaveBeenCalled();
  });
});
