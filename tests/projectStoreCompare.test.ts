import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ProjectStore } from '../src/platform/dashboard/ProjectStore';
import type { Logger } from '../src/platform/core/logging/logger';

const silentLogger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  debug: () => undefined,
} as unknown as Logger;

describe('ProjectStore.compareScans regression aliases', () => {
  let root: string;
  let store: ProjectStore;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sa-compare-'));
    store = new ProjectStore(path.join(root, 'projects'), path.join(root, 'scans'), silentLogger);
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('classifies New / Fixed / Unchanged', () => {
    const project = store.createProject({ name: 'Demo', targetUrl: 'https://example.com' });

    const mkResult = (findings: any[]) => ({
      findings,
      risk: { overallScore: 80, overallRisk: 'Medium' },
      stats: { totalFindings: findings.filter((f) => f.issueFound).length },
      meta: {},
    });

    const shared = {
      pluginId: 'sqli',
      title: 'SQL injection on /api/search',
      severity: 'High',
      confidence: 'Confirmed',
      issueFound: true,
      affectedEndpoint: 'https://example.com/api/search',
      mappings: { cwe: ['CWE-89'] },
    };

    const baseline = store.saveScan({
      projectId: project.id,
      targetUrl: 'https://example.com',
      score: 70,
      risk: 'High',
      findings: 2,
      result: mkResult([
        { ...shared, id: 'a' },
        {
          id: 'b',
          pluginId: 'xss',
          title: 'Reflected XSS on /q',
          severity: 'Medium',
          confidence: 'Likely',
          issueFound: true,
          affectedEndpoint: 'https://example.com/q',
          mappings: { cwe: ['CWE-79'] },
        },
      ]),
    });

    const current = store.saveScan({
      projectId: project.id,
      targetUrl: 'https://example.com',
      score: 85,
      risk: 'Medium',
      findings: 2,
      result: mkResult([
        { ...shared, id: 'a2' },
        {
          id: 'c',
          pluginId: 'idor',
          title: 'IDOR / BOLA on /api/users/1 (cross-user Account B)',
          severity: 'High',
          confidence: 'Confirmed',
          issueFound: true,
          affectedEndpoint: 'https://example.com/api/users/1',
          mappings: { cwe: ['CWE-639'] },
        },
      ]),
    });

    const cmp = store.compareScans(baseline.id, current.id);
    expect(cmp.ok).toBe(true);
    if (!cmp.ok) return;

    expect(cmp.summary.newCount).toBe(1);
    expect(cmp.summary.fixedCount).toBe(1);
    expect(cmp.summary.unchangedCount).toBe(1);
    expect(cmp.fixed).toHaveLength(1);
    expect(cmp.unchanged).toHaveLength(1);
    expect(cmp.newFindings[0].title).toMatch(/IDOR/);
    expect(cmp.resolved).toEqual(cmp.fixed);
    expect(cmp.persistent).toEqual(cmp.unchanged);
    expect(cmp.rows.some((r) => r.delta === 'New')).toBe(true);
    expect(cmp.rows.some((r) => r.delta === 'Fixed')).toBe(true);
    expect(cmp.rows.some((r) => r.delta === 'Unchanged')).toBe(true);
  });
});
