export interface LinuxAsset {
  assetId: string;
  hostname: string;
  port: number;
  osFamily: 'ubuntu';
  osVersion?: string;
  label?: string;
  projectId?: string;
  createdAt: string;
}

export type CredentialReferenceType = 'ssh-key' | 'env' | 'secret-manager';

/**
 * A pointer to a credential, never the credential itself.
 * `ref` is interpreted by SecretResolver based on `type`:
 *  - "env"            -> ref is an environment variable name holding a private key path or key material
 *  - "ssh-key"        -> ref is a filesystem path to a private key (operator-controlled, not uploaded)
 *  - "secret-manager"  -> ref is an opaque secret-manager lookup path (future extension point)
 */
export interface CredentialReference {
  type: CredentialReferenceType;
  ref: string;
  passphraseEnvVar?: string;
}
