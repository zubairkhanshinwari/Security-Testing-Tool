import fs from 'fs';
import type { CredentialReference } from '../../models/LinuxAsset';

/**
 * Resolved credential material, held only in memory for the duration of a
 * connection attempt. This type is intentionally NOT exported alongside
 * anything that flows into logger.*() calls, ComplianceEvidence, or
 * ComplianceResult — callers must not persist or log it.
 */
export interface ResolvedCredential {
  privateKey: string;
  passphrase?: string;
}

export class CredentialResolutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredentialResolutionError';
  }
}

/**
 * Resolves a CredentialReference (a pointer) into actual key material at
 * connect-time only. Never stores plaintext credentials at rest itself —
 * it reads from environment variables / operator-controlled key files that
 * are themselves outside this repository's persistence layer.
 *
 * Fails closed: an unresolvable reference throws rather than allowing the
 * assessment to silently proceed without authentication.
 */
export class SecretResolver {
  async resolve(ref: CredentialReference): Promise<ResolvedCredential> {
    const passphrase = ref.passphraseEnvVar ? process.env[ref.passphraseEnvVar] : undefined;

    switch (ref.type) {
      case 'env': {
        const value = process.env[ref.ref];
        if (!value) {
          throw new CredentialResolutionError(
            `Credential env var "${ref.ref}" is not set.`,
          );
        }
        return { privateKey: value, passphrase };
      }

      case 'ssh-key': {
        if (!fs.existsSync(ref.ref)) {
          throw new CredentialResolutionError(`SSH key file not found at configured path.`);
        }
        const privateKey = fs.readFileSync(ref.ref, 'utf8');
        return { privateKey, passphrase };
      }

      case 'secret-manager':
        // Extension point for a future secret-manager integration. Intentionally
        // unimplemented in Phase 1 rather than half-implemented against no real backend.
        throw new CredentialResolutionError(
          'secret-manager credential references are not yet supported.',
        );

      default:
        throw new CredentialResolutionError(`Unknown credential reference type.`);
    }
  }
}
