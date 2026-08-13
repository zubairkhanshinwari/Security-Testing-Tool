import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ComplianceAssessmentStore } from '../../src/compliance/persistence/ComplianceAssessmentStore';
import { createLogger } from '../../src/platform/core/logging/logger';
import type { ComplianceAssessment } from '../../src/compliance/models/ComplianceAssessment';

let tmpRoot: string;

afterEach(() => {
  if (tmpRoot && fs.existsSync(tmpRoot)) fs.rmSync(tmpRoot, { recursive: true, force: true });
});

function makeStore() {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-store-'));
  return new ComplianceAssessmentStore(
    path.join(tmpRoot, 'assessments'),
    path.join(tmpRoot, 'evidence'),
    createLogger('test', 'error'),
  );
}

function makeAssessment(overrides: Partial<ComplianceAssessment> = {}): ComplianceAssessment {
  return {
    assessmentId: 'a1',
    projectId: 'p1',
    assetId: 'asset-1',
    benchmarkId: 'cis-ubuntu-linux',
    benchmarkVersion: '1.0.0',
    profile: 'server-level-1',
    status: 'completed',
    startedAt: new Date().toISOString(),
    authorized: true,
    controlResults: [],
    ...overrides,
  };
}

describe('ComplianceAssessmentStore', () => {
  it('saves and retrieves an assessment by id', () => {
    const store = makeStore();
    const assessment = makeAssessment();
    store.saveAssessment(assessment);
    const loaded = store.getAssessment('a1');
    expect(loaded?.assessmentId).toBe('a1');
    expect(loaded?.benchmarkId).toBe('cis-ubuntu-linux');
  });

  it('returns null for an unknown assessment id', () => {
    const store = makeStore();
    expect(store.getAssessment('does-not-exist')).toBeNull();
  });

  it('lists assessments filtered by projectId', () => {
    const store = makeStore();
    store.saveAssessment(makeAssessment({ assessmentId: 'a1', projectId: 'p1' }));
    store.saveAssessment(makeAssessment({ assessmentId: 'a2', projectId: 'p2' }));
    expect(store.listAssessments('p1').map((a) => a.assessmentId)).toEqual(['a1']);
    expect(store.listAssessments()).toHaveLength(2);
  });

  it('redacts sensitive fields before persisting an assessment', () => {
    const store = makeStore();
    const assessment = makeAssessment({
      // Simulate an accidental sensitive field ending up on the assessment object.
      error: undefined,
    });
    (assessment as any).password = 'should-not-persist-plaintext';
    store.saveAssessment(assessment);
    const raw = fs.readFileSync(path.join(tmpRoot, 'assessments', 'a1.json'), 'utf8');
    expect(raw).not.toContain('should-not-persist-plaintext');
    expect(raw).toContain('[REDACTED]');
  });

  it('persists evidence via evidenceRepositoryFor and reloads it across instances', () => {
    const store = makeStore();
    const repo = store.evidenceRepositoryFor('a1');
    repo.add({
      evidenceId: 'e1',
      assessmentId: 'a1',
      controlId: 'EX-1.1',
      assetId: 'asset-1',
      timestamp: new Date().toISOString(),
      source: 'ssh-collector',
      data: { content: 'PermitRootLogin no' },
      sanitized: true,
    });

    const reloaded = new ComplianceAssessmentStore(
      path.join(tmpRoot, 'assessments'),
      path.join(tmpRoot, 'evidence'),
      createLogger('test', 'error'),
    ).evidenceRepositoryFor('a1');
    expect(reloaded.list()).toHaveLength(1);
    expect(reloaded.list('EX-1.1')).toHaveLength(1);
    expect(reloaded.list('EX-9.9')).toHaveLength(0);
  });
});
