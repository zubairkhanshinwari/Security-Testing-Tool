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
        stdout: `AUTH_TOKEN=Bearer ${['NOT', 'A', 'REAL', 'SECRET', 'FIXTURE', '0000000000'].join('_')}\n`,
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
    expect(content).not.toContain('NOT_A_REAL_SECRET_FIXTURE_0000000000');
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
    // Synthetic, non-decodable fixture built at runtime — intentionally not a
    // real (or real-looking, statically-scannable) token. Only needs to match
    // the JWT shape (base64url.base64url.base64url) that redactString detects.
    const syntheticJwt = ['eyJhbGciOiJIUzI1NiJ9', 'ZmFrZS1maXh0dXJlLW5vdC1yZWFsLW5vdC1hLXNlY3JldA', 'FAKE0FIXTURE0SIGNATURE0NOT0REAL0000000000000'].join('.');
    expect(redactString(`token: ${syntheticJwt}`)).toContain('[REDACTED_JWT]');
    expect(redactString(`token: ${syntheticJwt}`)).not.toContain(syntheticJwt);
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
