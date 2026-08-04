import { describe, expect, it, vi } from 'vitest';
import {
  KnowledgeRepository,
  ScanEventBus,
  createScanId,
} from '../src/platform/core/knowledge';
import { createLogger } from '../src/platform/core/logging/logger';

describe('ScanEventBus', () => {
  it('delivers typed and wildcard events', () => {
    const bus = new ScanEventBus();
    const typed: string[] = [];
    const all: string[] = [];
    bus.on('page.found', (e) => typed.push(e.type));
    bus.on('*', (e) => all.push(e.type));
    bus.emit('page.found', 'scan-1', { url: 'https://example.com' });
    bus.emit('stage.start', 'scan-1', { stage: 'recon' });
    expect(typed).toEqual(['page.found']);
    expect(all).toEqual(['page.found', 'stage.start']);
  });
});

describe('KnowledgeRepository', () => {
  const logger = createLogger('test', 'error', false);

  it('stores discovery / session / surface and builds ScanResult', () => {
    const events: string[] = [];
    const bus = new ScanEventBus();
    bus.on('*', (e) => events.push(e.type));

    const repo = new KnowledgeRepository(
      {
        scanId: createScanId(),
        request: {
          targetUrl: 'https://example.com',
          authorized: true,
          projectName: 'Repo Test',
        },
        mode: 'active-safe',
        requestedTypes: ['sqli'],
        selectedTypes: ['sqli'],
        catalogSize: 10,
        startedAt: new Date(),
        platformVersion: '2.0.0',
      },
      logger,
      bus,
    );

    repo.setDiscovery({
      pageInfo: { title: 'Demo', forms: [{ action: '/login' }] },
      visitedUrls: ['https://example.com/', 'https://example.com/login'],
      apis: [{ url: 'https://example.com/api/users', method: 'GET' }],
      querySurfaces: [],
      apiBases: ['https://example.com/api'],
      bundleRoutes: [],
      robots: null,
      openapiCandidates: [],
    });

    repo.setFingerprint({ server: 'nginx' });
    repo.setSession({ ok: true, type: 'password', token: 't', message: 'ok' });
    repo.setAttackSurface({
      hosts: ['example.com'],
      subdomains: [],
      pages: ['https://example.com/'],
      endpoints: [{ url: 'https://example.com/api/users', method: 'GET' }],
      parameters: [],
      forms: [],
      cookies: [],
      headers: {},
      frameworks: [],
      libraries: [],
      authEndpoints: [],
      apiBases: ['https://example.com/api'],
      websockets: [],
      graphql: [],
      openapi: [],
      storageKeys: [],
    });
    repo.setPlugins(['sql-injection']);
    repo.addFindings(
      [
        {
          id: 'FIND-001',
          pluginId: 'sql-injection',
          title: 'Test',
          description: 'd',
          severity: 'High',
          confidence: 'Likely',
          mappings: { cwe: ['CWE-89'] },
          affectedUrl: 'https://example.com/api',
          affectedEndpoint: 'https://example.com/api',
          evidence: [],
          impact: 'i',
          remediation: 'r',
          references: [],
          status: 'Confirmed',
          issueFound: true,
          testMode: 'active-safe',
        },
      ],
      'draft',
    );
    repo.setRisk({
      overallScore: 82,
      overallRisk: 'High',
      severityCounts: {
        Critical: 0,
        High: 1,
        Medium: 0,
        Low: 0,
        Informational: 0,
      },
      owaspCoverage: {},
      riskPriority: [],
    });
    repo.setAssessmentSummary([{ module: 'SQLi', findings: 1 }]);

    const result = repo.toScanResult();
    expect(result.meta.knowledgeRepository).toBe(true);
    expect(result.meta.scanId).toBe(repo.scanId);
    expect(result.findings).toHaveLength(1);
    expect(result.recon?.linksVisited).toBe(2);
    expect(result.stats.totalFindings).toBe(1);
    expect(events).toContain('page.found');
    expect(events).toContain('endpoint.found');
    expect(events).toContain('finding.draft');

    repo.dispose();
    expect(events).toContain('scan.done');
  });

  it('isolates subscriber failures', () => {
    const bus = new ScanEventBus();
    const spy = vi.fn();
    bus.on('stage.start', () => {
      throw new Error('boom');
    });
    bus.on('stage.start', spy);
    expect(() => bus.emit('stage.start', 's1', { stage: 'x' })).not.toThrow();
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('merges authenticated discovery pass', () => {
    const repo = new KnowledgeRepository(
      {
        scanId: createScanId(),
        request: {
          targetUrl: 'https://example.com',
          authorized: true,
          projectName: 'Merge',
        },
        mode: 'active-safe',
        requestedTypes: [],
        selectedTypes: [],
        catalogSize: 1,
        startedAt: new Date(),
      },
      logger,
    );

    repo.setDiscovery({
      pageInfo: {
        title: 'Home',
        forms: [{ method: 'GET', action: '/search', fields: [{ name: 'q' }] }],
        tokens: {},
      },
      visitedUrls: ['https://example.com/'],
      apis: [{ url: 'https://example.com/api/public', method: 'GET' }],
      querySurfaces: [{ baseUrl: 'https://example.com/', parameters: ['ref'] }],
      apiBases: ['https://example.com/api'],
      openapiCandidates: [],
      sitemapUrls: [],
    });

    repo.mergeDiscovery({
      pageInfo: {
        title: 'Dashboard',
        forms: [
          { method: 'POST', action: '/account', fields: [{ name: 'email' }] },
          { method: 'GET', action: '/search', fields: [{ name: 'q' }] },
        ],
        tokens: { accessToken: 'abc' },
      },
      visitedUrls: ['https://example.com/dashboard'],
      apis: [
        { url: 'https://example.com/api/me', method: 'GET' },
        { url: 'https://example.com/api/public', method: 'GET' },
      ],
      querySurfaces: [{ baseUrl: 'https://example.com/dashboard', parameters: ['tab'] }],
      apiBases: ['https://example.com/api'],
      openapiCandidates: [],
      sitemapUrls: [],
      discoveredToken: 'abc',
    });

    const d = repo.getDiscovery();
    expect(d.visitedUrls).toEqual(
      expect.arrayContaining(['https://example.com/', 'https://example.com/dashboard']),
    );
    expect(d.apis).toHaveLength(2);
    expect(d.pageInfo.forms).toHaveLength(2);
    expect(d.discoveredToken).toBe('abc');
    expect(d.pageInfo.tokens.accessToken).toBe('abc');
  });
});
