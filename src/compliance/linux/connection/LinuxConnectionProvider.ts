import type { LinuxAsset, CredentialReference } from '../../models/LinuxAsset';

/**
 * Opaque session handle. Concrete providers may attach private fields, but
 * callers (LinuxCollector, LinuxAssessmentEngine) only ever see this shape —
 * never raw credential material and never the underlying transport client.
 */
export interface LinuxSession {
  sessionId: string;
  assetId: string;
  connectedAt: string;
}

export interface CommandExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

/**
 * Abstraction over "how we reach the Linux host." SSH is the Phase-1
 * implementation; Agent-based, local-collector, and management-API
 * implementations can be added later purely by implementing this interface —
 * LinuxCollector and CISControlEvaluator never depend on a concrete provider.
 */
export interface LinuxConnectionProvider {
  connect(target: LinuxAsset, credentialRef: CredentialReference): Promise<LinuxSession>;
  disconnect(session: LinuxSession): Promise<void>;
  isConnected(session: LinuxSession): boolean;

  /**
   * Execute one allowlisted, read-only operation. `operationId` must be a key
   * from commandAllowlist.ts — providers must never accept raw shell strings
   * from callers, which is what keeps CISControlEvaluator from being able to
   * (accidentally or otherwise) run arbitrary commands.
   */
  runAllowlistedOperation(session: LinuxSession, operationId: string): Promise<CommandExecutionResult>;
}
