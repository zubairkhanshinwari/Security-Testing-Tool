import { randomUUID } from 'crypto';
import type { Logger } from '../../../platform/core/logging/logger';
import type { LinuxAsset, CredentialReference } from '../../models/LinuxAsset';
import type {
  LinuxConnectionProvider,
  LinuxSession,
  CommandExecutionResult,
} from './LinuxConnectionProvider';
import { SecretResolver } from './SecretResolver';
import { resolveAllowlistedCommand } from './commandAllowlist';
import { NodeSshTransport, type SshTransport } from './SshTransport';

interface InternalSession extends LinuxSession {
  transport: SshTransport;
  connected: boolean;
}

/**
 * Phase-1 LinuxConnectionProvider implementation: key-based SSH auth only
 * (no password auth path — simplest way to guarantee no plaintext password
 * ever needs to be handled), one session per assessment, allowlisted
 * read-only commands only.
 *
 * Credential material is resolved by SecretResolver at connect() time and is
 * held only inside the SshTransport's connection call — it is never assigned
 * to a field on this class, never returned to callers, and never logged.
 */
export class SshLinuxConnectionProvider implements LinuxConnectionProvider {
  private readonly sessions = new Map<string, InternalSession>();

  constructor(
    private readonly logger: Logger,
    private readonly secretResolver: SecretResolver = new SecretResolver(),
    private readonly commandTimeoutMs = 10_000,
    private readonly transportFactory: () => SshTransport = () => new NodeSshTransport(),
  ) {}

  async connect(target: LinuxAsset, credentialRef: CredentialReference): Promise<LinuxSession> {
    const credential = await this.secretResolver.resolve(credentialRef);
    const transport = this.transportFactory();

    try {
      await transport.connect({
        host: target.hostname,
        port: target.port,
        username: usernameFor(credentialRef),
        privateKey: credential.privateKey,
        passphrase: credential.passphrase,
        readyTimeoutMs: this.commandTimeoutMs,
      });
    } catch (err) {
      this.logger.warn('Linux SSH connection failed', {
        assetId: target.assetId,
        // hostname only — never credential material, never a stack trace that could embed it
        hostname: target.hostname,
        error: err instanceof Error ? err.message : 'connection error',
      });
      throw new Error(`Failed to connect to Linux target (assetId=${target.assetId}).`);
    }

    const session: InternalSession = {
      sessionId: randomUUID(),
      assetId: target.assetId,
      connectedAt: new Date().toISOString(),
      transport,
      connected: true,
    };
    this.sessions.set(session.sessionId, session);
    this.logger.info('Linux SSH connection established', {
      assetId: target.assetId,
      sessionId: session.sessionId,
    });
    return session;
  }

  async disconnect(session: LinuxSession): Promise<void> {
    const internal = this.sessions.get(session.sessionId);
    if (!internal) return;
    await internal.transport.end();
    internal.connected = false;
    this.sessions.delete(session.sessionId);
  }

  isConnected(session: LinuxSession): boolean {
    return Boolean(this.sessions.get(session.sessionId)?.connected);
  }

  async runAllowlistedOperation(session: LinuxSession, operationId: string): Promise<CommandExecutionResult> {
    const internal = this.sessions.get(session.sessionId);
    if (!internal || !internal.connected) {
      throw new Error('Cannot run operation: session is not connected.');
    }
    const command = resolveAllowlistedCommand(operationId);
    return internal.transport.exec(command.program, command.args, this.commandTimeoutMs);
  }
}

/**
 * SSH username for the connection. Kept as a small seam (env-configurable,
 * defaulting to a conventional read-only auditor account name) rather than
 * baked into CredentialReference, since the same key may be used with
 * different remote usernames across hosts.
 */
function usernameFor(_credentialRef: CredentialReference): string {
  return process.env.SECUREASSESS_LINUX_SSH_USER || 'secureassess-audit';
}
