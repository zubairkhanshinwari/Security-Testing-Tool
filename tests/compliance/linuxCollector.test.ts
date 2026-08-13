import { describe, it, expect, vi } from 'vitest';
import { LinuxCollector } from '../../src/compliance/linux/LinuxCollector';
import { createLogger } from '../../src/platform/core/logging/logger';
import type { LinuxConnectionProvider, LinuxSession } from '../../src/compliance/linux/connection/LinuxConnectionProvider';
import type { EvidenceRequirement } from '../../src/compliance/models/ComplianceControl';

const session: LinuxSession = { sessionId: 's1', assetId: 'asset-1', connectedAt: new Date().toISOString() };

function fakeProvider(runner: LinuxConnectionProvider['runAllowlistedOperation']): LinuxConnectionProvider {
  return {
    connect: vi.fn(),
    disconnect: vi.fn(),
    isConnected: vi.fn().mockReturnValue(true),
    runAllowlistedOperation: runner,
  };
}

describe('LinuxCollector', () => {
  it('collects file-content evidence and parses it into a content field', async () => {
    const provider = fakeProvider(async () => ({ stdout: 'PermitRootLogin no\n', stderr: '', exitCode: 0 }));
    const collector = new LinuxCollector(provider, createLogger('test', 'error'));

    const req: EvidenceRequirement = {
      evidenceType: 'file-content',
      target: '/etc/ssh/sshd_config',
      collectionMethod: 'read-file:/etc/ssh/sshd_config',
    };
    const evidence = await collector.collectEvidence(session, [req], {
      assessmentId: 'a1',
      controlId: 'EX-1.1',
      assetId: 'asset-1',
    });

    expect(evidence).toHaveLength(1);
    expect(evidence[0].sanitized).toBe(true);
    expect((evidence[0].data as any).content).toContain('PermitRootLogin no');
    expect(evidence[0].error).toBeUndefined();
  });

  it('parses service-state evidence into an active boolean', async () => {
    const provider = fakeProvider(async () => ({ stdout: 'active\n', stderr: '', exitCode: 0 }));
    const collector = new LinuxCollector(provider, createLogger('test', 'error'));
    const [evidence] = await collector.collectEvidence(
      session,
      [{ evidenceType: 'service-state', target: 'ssh', collectionMethod: 'service-status:ssh' }],
      { assessmentId: 'a1', controlId: 'EX-3.2', assetId: 'asset-1' },
    );
    expect((evidence.data as any).active).toBe(true);
  });

  it('parses permission-metadata evidence into mode/owner/group', async () => {
    const provider = fakeProvider(async () => ({ stdout: '644 root root\n', stderr: '', exitCode: 0 }));
    const collector = new LinuxCollector(provider, createLogger('test', 'error'));
    const [evidence] = await collector.collectEvidence(
      session,
      [{ evidenceType: 'permission-metadata', target: '/etc/passwd', collectionMethod: 'stat-file:/etc/passwd' }],
      { assessmentId: 'a1', controlId: 'EX-2.1', assetId: 'asset-1' },
    );
    expect(evidence.data).toEqual(expect.objectContaining({ mode: '644', owner: 'root', group: 'root' }));
  });

  it('records a collection error on the evidence item instead of throwing', async () => {
    const provider = fakeProvider(async () => {
      throw new Error('ssh channel closed unexpectedly');
    });
    const collector = new LinuxCollector(provider, createLogger('test', 'error'));
    const [evidence] = await collector.collectEvidence(
      session,
      [{ evidenceType: 'command-output', target: '/tmp', collectionMethod: 'mount-info:/tmp' }],
      { assessmentId: 'a1', controlId: 'EX-2.2', assetId: 'asset-1' },
    );
    expect(evidence.error).toMatch(/ssh channel closed/);
    expect(evidence.data).toBeNull();
    expect(evidence.sanitized).toBe(true);
  });
});
