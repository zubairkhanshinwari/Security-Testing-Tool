import type { CISBenchmark } from '../models/CISBenchmark';
import type { ComplianceControl, EvidenceRequirement } from '../models/ComplianceControl';

export interface CompliancePlan {
  selectedControls: ComplianceControl[];
  evidenceRequirementsByControl: Map<string, EvidenceRequirement[]>;
}

export interface ComplianceAssessmentRequestLike {
  profile?: string;
  selectedControls?: string[];
}

/**
 * Determines which controls need to be evaluated and what evidence each
 * requires. Pure function of (benchmark, profile, request) — no I/O, no
 * connection/evaluator dependencies — which keeps it trivially unit-testable.
 */
export class CompliancePlanner {
  plan(benchmark: CISBenchmark, profile: string, request: ComplianceAssessmentRequestLike): CompliancePlan {
    const explicit = request.selectedControls?.length ? new Set(request.selectedControls) : undefined;

    const selectedControls = benchmark.controls.filter((control) => {
      if (explicit) return explicit.has(control.controlId);
      return matchesProfile(control, profile);
    });

    const evidenceRequirementsByControl = new Map<string, EvidenceRequirement[]>();
    for (const control of selectedControls) {
      evidenceRequirementsByControl.set(control.controlId, control.evidenceRequirements);
    }

    return { selectedControls, evidenceRequirementsByControl };
  }
}

function matchesProfile(control: ComplianceControl, profile: string): boolean {
  if (!profile || profile === 'all') return true;
  // Profile naming convention: "<target>-level-<n>", e.g. "server-level-1".
  const match = profile.match(/level-(\d+)/i);
  if (!match) return true;
  return Number(control.level) <= Number(match[1]);
}
