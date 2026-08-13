import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SshLinuxConnectionProvider } from '../../src/compliance/linux/connection/SshLinuxConnectionProvider';
import { SecretResolver, CredentialResolutionError } from '../../src/compliance/linux/connection/SecretResolver';
import type { SshTransport } from '../../src/compliance/linux/connection/SshTransport';
import { createLogger } from '../../src/platform/core/logging/logger';
import type { LinuxAsset, CredentialReference } from '../../src/compliance/models/LinuxAsset';

const target: LinuxAsset = {
  assetId: 'asset-1',
  hostname: 'internal-host.example',
  port: 22,
  osFamily: 'ubuntu',
  createdAt: new Date().toISOString(),
};

const credentialRef: CredentialReference = { type: 'env', ref: 'TEST_SSH_KEY' };

function fakeTransport(overrides: Partial<SshTransport> = {}): SshTransport {
  return {
    connect: vi.fn().mockResolvedValue(undefined),
    exec: vi.fn().mockResolvedValue({ stdout: 'ok', stderr: '', exitCode: 0 }),
    end: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

describe('SshLinuxConnectionProvider', () => {
  beforeEach(() => {
    process.env.TEST_SSH_KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATA\n-----END OPENSSH PRIVATE KEY-----';
  });
  afterEach(() => {
    delete process.env.TEST_SSH_KEY;
  });

  it('connects, tracks the session as connected, then disconnects cleanly', async () => {
    const transport = fakeTransport();
    const provider = new SshLinuxConnectionProvider(
      createLogger('test', 'error'),
      new SecretResolver(),
      5000,
      () => transport,
    );

    const session = await provider.connect(target, credentialRef);
    expect(provider.isConnected(session)).toBe(true);
    expect(transport.connect).toHaveBeenCalledWith(
      expect.objectContaining({ host: target.hostname, port: target.port }),
    );

    await provider.disconnect(session);
    expect(provider.isConnected(session)).toBe(false);
    expect(transport.end).toHaveBeenCalledOnce();
  });

  it('runs an allowlisted operation via the transport and returns its output', async () => {
    const transport = fakeTransport({
      exec: vi.fn().mockResolvedValue({ stdout: 'PermitRootLogin no\n', stderr: '', exitCode: 0 }),
    });
    const provider = new SshLinuxConnectionProvider(
      createLogger('test', 'error'),
      new SecretResolver(),
      5000,
      () => transport,
    );
    const session = await provider.connect(target, credentialRef);
    const result = await provider.runAllowlistedOperation(session, 'read-file:/etc/ssh/sshd_config');
    expect(result.stdout).toContain('PermitRootLogin no');
    expect(transport.exec).toHaveBeenCalledWith('cat', ['--', '/etc/ssh/sshd_config'], expect.any(Number));
  });

  it('rejects running an operation on a disconnected/unknown session', async () => {
    const provider = new SshLinuxConnectionProvider(createLogger('test', 'error'));
    await expect(
      provider.runAllowlistedOperation({ sessionId: 'nope', assetId: 'x', connectedAt: '' }, 'read-file:/etc/passwd'),
    ).rejects.toThrow(/not connected/i);
  });

  it('propagates connection failures as a generic error without leaking credential material', async () => {
    const transport = fakeTransport({
      connect: vi.fn().mockRejectedValue(new Error('auth failed for key BEGIN-RSA-PRIVATE-KEY-SECRET')),
    });
    const provider = new SshLinuxConnectionProvider(
      createLogger('test', 'error'),
      new SecretResolver(),
      5000,
      () => transport,
    );
    await expect(provider.connect(target, credentialRef)).rejects.toThrow(/Failed to connect/);
  });

  it('fails closed when the credential reference cannot be resolved', async () => {
    delete process.env.TEST_SSH_KEY;
    const provider = new SshLinuxConnectionProvider(createLogger('test', 'error'));
    await expect(provider.connect(target, credentialRef)).rejects.toThrow(CredentialResolutionError);
  });
});

describe('SecretResolver', () => {
  afterEach(() => {
    delete process.env.TEST_SSH_KEY;
  });

  it('resolves an env-type credential reference to key material', async () => {
    process.env.TEST_SSH_KEY = 'fake-key-material';
    const resolver = new SecretResolver();
    const resolved = await resolver.resolve({ type: 'env', ref: 'TEST_SSH_KEY' });
    expect(resolved.privateKey).toBe('fake-key-material');
  });

  it('throws (fails closed) when the env var is unset', async () => {
    const resolver = new SecretResolver();
    await expect(resolver.resolve({ type: 'env', ref: 'DOES_NOT_EXIST_VAR' })).rejects.toThrow(
      CredentialResolutionError,
    );
  });

  it('throws for an unimplemented secret-manager reference type rather than silently no-op-ing', async () => {
    const resolver = new SecretResolver();
    await expect(resolver.resolve({ type: 'secret-manager', ref: 'kv/ssh-key' })).rejects.toThrow(
      CredentialResolutionError,
    );
  });
});
