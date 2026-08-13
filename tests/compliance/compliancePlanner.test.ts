import { describe, it, expect } from 'vitest';
import { CompliancePlanner } from '../../src/compliance/planning/CompliancePlanner';
import type { CISBenchmark } from '../../src/compliance/models/CISBenchmark';
import type { ComplianceControl } from '../../src/compliance/models/ComplianceControl';

function control(id: string, level: '1' | '2'): ComplianceControl {
  return {
    controlId: id,
    title: `Control ${id}`,
    level,
    automated: true,
    evidenceRequirements: [],
    remediationMetadata: { summary: 'fix it' },
  };
}

const benchmark: CISBenchmark = {
  benchmarkId: 'b',
  name: 'B',
  version: '1.0.0',
  platform: 'ubuntu-linux',
  profile: 'server-level-1',
  controls: [control('L1-A', '1'), control('L1-B', '1'), control('L2-A', '2')],
};

describe('CompliancePlanner', () => {
  it('selects only level-1 controls for a server-level-1 profile', () => {
    const plan = new CompliancePlanner().plan(benchmark, 'server-level-1', {});
    expect(plan.selectedControls.map((c) => c.controlId).sort()).toEqual(['L1-A', 'L1-B']);
  });

  it('selects level-1 and level-2 controls for a server-level-2 profile', () => {
    const plan = new CompliancePlanner().plan(benchmark, 'server-level-2', {});
    expect(plan.selectedControls).toHaveLength(3);
  });

  it('selects all controls when profile is "all"', () => {
    const plan = new CompliancePlanner().plan(benchmark, 'all', {});
    expect(plan.selectedControls).toHaveLength(3);
  });

  it('honors an explicit selectedControls list over the profile', () => {
    const plan = new CompliancePlanner().plan(benchmark, 'server-level-1', {
      selectedControls: ['L2-A'],
    });
    expect(plan.selectedControls.map((c) => c.controlId)).toEqual(['L2-A']);
  });

  it('builds an evidenceRequirementsByControl map for every selected control', () => {
    const plan = new CompliancePlanner().plan(benchmark, 'server-level-1', {});
    expect(plan.evidenceRequirementsByControl.has('L1-A')).toBe(true);
    expect(plan.evidenceRequirementsByControl.has('L1-B')).toBe(true);
  });
});
