import { describe, it, expect } from 'vitest';
import { resolveAllowlistedCommand, UnsafeOperationError } from '../../src/compliance/linux/connection/commandAllowlist';

describe('commandAllowlist', () => {
  it('resolves read-file into a non-interpolated cat argv', () => {
    const cmd = resolveAllowlistedCommand('read-file:/etc/ssh/sshd_config');
    expect(cmd).toEqual({ program: 'cat', args: ['--', '/etc/ssh/sshd_config'] });
  });

  it('resolves service-status into systemctl is-active', () => {
    const cmd = resolveAllowlistedCommand('service-status:ssh');
    expect(cmd).toEqual({ program: 'systemctl', args: ['is-active', 'ssh'] });
  });

  it('resolves sysctl-get into sysctl -n', () => {
    const cmd = resolveAllowlistedCommand('sysctl-get:net.ipv4.ip_forward');
    expect(cmd).toEqual({ program: 'sysctl', args: ['-n', 'net.ipv4.ip_forward'] });
  });

  it('rejects an operation not on the allowlist', () => {
    expect(() => resolveAllowlistedCommand('rm-rf:/')).toThrow(UnsafeOperationError);
  });

  it('rejects shell metacharacters in the target argument', () => {
    expect(() => resolveAllowlistedCommand('read-file:/etc/passwd; rm -rf /')).toThrow(UnsafeOperationError);
    expect(() => resolveAllowlistedCommand('read-file:$(whoami)')).toThrow(UnsafeOperationError);
    expect(() => resolveAllowlistedCommand('service-status:ssh && reboot')).toThrow(UnsafeOperationError);
  });

  it('rejects an empty target argument', () => {
    expect(() => resolveAllowlistedCommand('read-file:')).toThrow(UnsafeOperationError);
  });
});
