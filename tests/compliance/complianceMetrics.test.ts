import { describe, it, expect } from 'vitest';
import { calculateComplianceMetrics } from '../../src/compliance/core/complianceMetrics';
import type { ComplianceResult, ControlStatus } from '../../src/compliance/models/ComplianceResult';

function result(status: ControlStatus, controlId = 'c'): ComplianceResult {
  return {
    controlId,
    assessmentId: 'a1',
    status,
    reason: 'r',
    confidence: 'high',
    evidenceRefs: [],
    evaluatedAt: new Date().toISOString(),
  };
}

describe('calculateComplianceMetrics', () => {
  it('computes compliancePercentage as passed / applicable (total - notApplicable) * 100', () => {
    const results = [
      result('PASS'), result('PASS'), result('PASS'),
      result('FAIL'),
      result('NOT_APPLICABLE'),
    ];
    const m = calculateComplianceMetrics(results);
    expect(m.totalControls).toBe(5);
    expect(m.applicableControls).toBe(4);
    expect(m.passed).toBe(3);
    expect(m.failed).toBe(1);
    expect(m.notApplicable).toBe(1);
    // 3 / 4 * 100 = 75
    expect(m.compliancePercentage).toBe(75);
  });

  it('counts MANUAL_REVIEW against the denominator but never as passed', () => {
    const results = [result('PASS'), result('MANUAL_REVIEW'), result('MANUAL_REVIEW')];
    const m = calculateComplianceMetrics(results);
    expect(m.applicableControls).toBe(3);
    expect(m.manualReview).toBe(2);
    // 1 / 3 * 100 = 33.3
    expect(m.compliancePercentage).toBe(33.3);
  });

  it('counts ERROR against the denominator but never as passed', () => {
    const results = [result('PASS'), result('ERROR')];
    const m = calculateComplianceMetrics(results);
    expect(m.errors).toBe(1);
    expect(m.compliancePercentage).toBe(50);
  });

  it('returns 0% (not NaN/Infinity) when every control is NOT_APPLICABLE', () => {
    const results = [result('NOT_APPLICABLE'), result('NOT_APPLICABLE')];
    const m = calculateComplianceMetrics(results);
    expect(m.applicableControls).toBe(0);
    expect(m.compliancePercentage).toBe(0);
    expect(Number.isFinite(m.compliancePercentage)).toBe(true);
  });

  it('returns 0% for an empty result set', () => {
    const m = calculateComplianceMetrics([]);
    expect(m.totalControls).toBe(0);
    expect(m.compliancePercentage).toBe(0);
  });

  it('never reports 100% when any MANUAL_REVIEW or ERROR controls are present alongside all-pass automated ones', () => {
    const results = [result('PASS'), result('PASS'), result('MANUAL_REVIEW')];
    const m = calculateComplianceMetrics(results);
    expect(m.compliancePercentage).toBeLessThan(100);
  });
});
