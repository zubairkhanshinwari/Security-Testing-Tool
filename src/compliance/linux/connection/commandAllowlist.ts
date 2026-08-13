/**
 * Fixed, read-only command allowlist. CISControlEvaluator / LinuxCollector
 * request evidence by `collectionMethod` (e.g. "read-file:/etc/ssh/sshd_config"),
 * which is parsed here into a non-interpolated argv array — never a
 * string-concatenated shell command. This is the single choke point that
 * guarantees "no evaluator ever constructs a raw shell string."
 *
 * Every entry here must be read-only and safe to run repeatedly with no
 * side effects (no writes, no service restarts, no destructive flags).
 */

export interface AllowlistedCommand {
  /** Program to execute — no shell, no interpolation, argv passed directly. */
  program: string;
  args: string[];
}

const FILE_PATH_SAFE = /^[A-Za-z0-9._/-]+$/;
const SERVICE_NAME_SAFE = /^[A-Za-z0-9@._-]+$/;
const PACKAGE_NAME_SAFE = /^[A-Za-z0-9.+-]+$/;
const SYSCTL_KEY_SAFE = /^[A-Za-z0-9._-]+$/;

export class UnsafeOperationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeOperationError';
  }
}

/**
 * Resolves a `collectionMethod` string (e.g. "read-file:/etc/passwd") into a
 * fixed argv command. Throws UnsafeOperationError if the operation is not on
 * the allowlist or the target argument fails a strict character check.
 */
export function resolveAllowlistedCommand(operationId: string): AllowlistedCommand {
  const [op, ...rest] = operationId.split(':');
  const arg = rest.join(':');

  switch (op) {
    case 'read-file':
      assertSafe(arg, FILE_PATH_SAFE, 'file path');
      return { program: 'cat', args: ['--', arg] };

    case 'stat-file':
      assertSafe(arg, FILE_PATH_SAFE, 'file path');
      return { program: 'stat', args: ['--format=%a %U %G', '--', arg] };

    case 'service-status':
      assertSafe(arg, SERVICE_NAME_SAFE, 'service name');
      return { program: 'systemctl', args: ['is-active', arg] };

    case 'package-installed':
      assertSafe(arg, PACKAGE_NAME_SAFE, 'package name');
      return { program: 'dpkg-query', args: ['-W', '-f=${Status}', arg] };

    case 'sysctl-get':
      assertSafe(arg, SYSCTL_KEY_SAFE, 'sysctl key');
      return { program: 'sysctl', args: ['-n', arg] };

    case 'mount-info':
      assertSafe(arg, FILE_PATH_SAFE, 'mount path');
      return { program: 'findmnt', args: ['--noheadings', '--output=TARGET,SOURCE,FSTYPE,OPTIONS', arg] };

    default:
      throw new UnsafeOperationError(`Operation "${operationId}" is not on the read-only allowlist.`);
  }
}

function assertSafe(value: string, pattern: RegExp, kind: string): void {
  if (!value || !pattern.test(value)) {
    throw new UnsafeOperationError(`Refusing unsafe ${kind} in operation argument: ${JSON.stringify(value)}`);
  }
}
