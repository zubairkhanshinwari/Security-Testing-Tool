import { describe, it, expect, vi } from 'vitest';
import { LinuxCollector } from '../../src/compliance/linux/LinuxCollector';
import { createLogger } from '../../src/platform/core/logging/logger';
import type { LinuxConnectionProvider, LinuxSession } from '../../src/compliance/linux/connection/LinuxConnectionProvider';
import { redactSecrets, redactString } from '../../src/platform/core/safety/redact';

const session: LinuxSession = { sessionId: 's1', assetId: 'asset-1', connectedAt: new Date().toISOString() };

describe('Compliance evidence sanitization', () => {
  it('redacts a Bearer token embedded in collected file content', async () => {
    const provider: LinuxConnectionProvider = {
      connect: vi.fn(),
      disconnect: vi.fn(),
      isConnected: vi.fn().mockReturnValue(true),
      runAllowlistedOperation: async () => ({
        stdout: 'AUTH_TOKEN=Bearer sk_live_abcdef1234567890\n',
        stderr: '',
        exitCode: 0,
      }),
    };
    const collector = new LinuxCollector(provider, createLogger('test', 'error'));
    const [evidence] = await collector.collectEvidence(
      session,
      [{ evidenceType: 'file-content', target: '/etc/app/env', collectionMethod: 'read-file:/etc/app/env' }],
      { assessmentId: 'a1', controlId: 'EX-1.1', assetId: 'asset-1' },
    );
    const content = String((evidence.data as any).content);
    expect(content).not.toContain('sk_live_abcdef1234567890');
    expect(content).toContain('[REDACTED]');
  });

  it('redacts object keys matching sensitive patterns (password/secret/api-key) via redactSecrets reuse', () => {
    const raw = { password: 'hunter2', apiKey: 'abc123', normalField: 'keep-me' };
    const sanitized = redactSecrets(raw) as typeof raw;
    expect(sanitized.password).toBe('[REDACTED]');
    expect(sanitized.apiKey).toBe('[REDACTED]');
    expect(sanitized.normalField).toBe('keep-me');
  });

  it('redacts JWT-shaped strings via redactString reuse', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    expect(redactString(`token: ${jwt}`)).toContain('[REDACTED_JWT]');
    expect(redactString(`token: ${jwt}`)).not.toContain(jwt);
  });

  it('never sanitizes credential material into ComplianceEvidence in the first place (no key fields collected)', async () => {
    const provider: LinuxConnectionProvider = {
      connect: vi.fn(),
      disconnect: vi.fn(),
      isConnected: vi.fn().mockReturnValue(true),
      runAllowlistedOperation: async () => ({ stdout: 'active\n', stderr: '', exitCode: 0 }),
    };
    const collector = new LinuxCollector(provider, createLogger('test', 'error'));
    const [evidence] = await collector.collectEvidence(
      session,
      [{ evidenceType: 'service-state', target: 'ssh', collectionMethod: 'service-status:ssh' }],
      { assessmentId: 'a1', controlId: 'EX-3.2', assetId: 'asset-1' },
    );
    const serialized = JSON.stringify(evidence);
    expect(serialized).not.toMatch(/BEGIN (OPENSSH|RSA) PRIVATE KEY/);
  });
});
