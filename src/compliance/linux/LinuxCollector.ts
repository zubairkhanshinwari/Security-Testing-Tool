import { randomUUID } from 'crypto';
import type { Logger } from '../../platform/core/logging/logger';
import { redactSecrets, redactString } from '../../platform/core/safety/redact';
import type { EvidenceRequirement } from '../models/ComplianceControl';
import type { ComplianceEvidence } from '../models/ComplianceEvidence';
import type { LinuxConnectionProvider, LinuxSession } from './connection/LinuxConnectionProvider';

export interface CollectContext {
  assessmentId: string;
  controlId: string;
  assetId: string;
}

/**
 * Collects only the evidence a control's evidenceRequirements ask for — never
 * a broad system dump. Depends only on the LinuxConnectionProvider interface,
 * so swapping SSH for a future Agent/local-collector provider requires no
 * change here.
 *
 * Every returned ComplianceEvidence item has already been sanitized
 * (redactSecrets/redactString reused directly from the DAST safety module —
 * genuinely shared, zero-modification infra) before it leaves this class.
 */
export class LinuxCollector {
  constructor(
    private readonly connectionProvider: LinuxConnectionProvider,
    private readonly logger: Logger,
  ) {}

  async collectEvidence(
    session: LinuxSession,
    requirements: EvidenceRequirement[],
    ctx: CollectContext,
  ): Promise<ComplianceEvidence[]> {
    const results: ComplianceEvidence[] = [];
    for (const requirement of requirements) {
      results.push(await this.collectOne(session, requirement, ctx));
    }
    return results;
  }

  private async collectOne(
    session: LinuxSession,
    requirement: EvidenceRequirement,
    ctx: CollectContext,
  ): Promise<ComplianceEvidence> {
    const base = {
      evidenceId: randomUUID(),
      assessmentId: ctx.assessmentId,
      controlId: ctx.controlId,
      assetId: ctx.assetId,
      timestamp: new Date().toISOString(),
      source: 'ssh-collector',
      evidenceType: requirement.evidenceType,
      collectionMethod: requirement.collectionMethod,
    };

    try {
      const raw = await this.connectionProvider.runAllowlistedOperation(
        session,
        requirement.collectionMethod,
      );
      const parsed = parseByEvidenceType(requirement.evidenceType, raw);
      const sanitized = sanitize(parsed);

      return { ...base, data: sanitized, sanitized: true };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Evidence collection failed';
      this.logger.warn('Evidence collection error', {
        controlId: ctx.controlId,
        collectionMethod: requirement.collectionMethod,
        error: redactString(message),
      });
      return { ...base, data: null, sanitized: true, error: redactString(message) };
    }
  }
}

function parseByEvidenceType(
  evidenceType: EvidenceRequirement['evidenceType'],
  raw: { stdout: string; stderr: string; exitCode: number | null },
): Record<string, unknown> {
  const stdout = raw.stdout.trim();
  switch (evidenceType) {
    case 'file-content':
      return { content: raw.stdout, exitCode: raw.exitCode };

    case 'permission-metadata': {
      const [mode, owner, group] = stdout.split(/\s+/);
      return { mode, owner, group, exitCode: raw.exitCode };
    }

    case 'service-state':
      return { active: stdout === 'active', rawState: stdout, exitCode: raw.exitCode };

    case 'package-state': {
      const installed = /install ok installed/i.test(stdout);
      return { installed, rawStatus: stdout, exitCode: raw.exitCode };
    }

    case 'sysctl-value':
      return { value: stdout, exitCode: raw.exitCode };

    case 'command-output':
    default:
      return { stdout: raw.stdout, stderr: raw.stderr, exitCode: raw.exitCode };
  }
}

function sanitize(data: Record<string, unknown>): Record<string, unknown> {
  const redacted = redactSecrets(data);
  for (const [key, value] of Object.entries(redacted)) {
    if (typeof value === 'string') {
      (redacted as Record<string, unknown>)[key] = redactString(value);
    }
  }
  return redacted;
}
