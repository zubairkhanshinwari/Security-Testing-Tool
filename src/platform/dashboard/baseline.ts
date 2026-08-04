import type { AttackSurface, Finding, ScanResult } from '../core/types/finding';

export interface BaselineFinding {
  key: string;
  title: string;
  severity: string;
  endpoint: string;
  pluginId: string;
  cwe: string[];
}

export interface ScanBaseline {
  version: 1;
  projectId: string;
  scanId: string;
  targetUrl: string;
  createdAt: string;
  technology: Record<string, unknown>;
  endpoints: Array<{ url: string; method: string }>;
  pages: string[];
  apiBases: string[];
  confirmedFindings: BaselineFinding[];
  score: number;
  risk: string;
}

export interface BaselineDiff {
  available: boolean;
  baselineScanId?: string;
  newEndpoints: string[];
  removedEndpoints: string[];
  unchangedEndpoints: string[];
  priorConfirmed: BaselineFinding[];
  /** Endpoints to prioritize: new surface + prior confirmed issue URLs */
  focusEndpoints: string[];
  /** Plugin ids that previously found issues — retest first */
  retestPluginIds: string[];
}

export function findingKey(f: {
  mappings?: { cwe?: string[] };
  cwe?: string[];
  title?: string;
  affectedEndpoint?: string;
  endpoint?: string;
}): string {
  return `${(f.mappings?.cwe || f.cwe || []).join(',')}|${(f.title || '')
    .replace(/via.*/i, '')
    .trim()
    .toLowerCase()}|${f.affectedEndpoint || f.endpoint || ''}`;
}

export function endpointKey(url: string, method = 'GET'): string {
  const clean = String(url || '').split('?')[0].replace(/\/$/, '') || String(url || '');
  return `${String(method || 'GET').toUpperCase()} ${clean}`;
}

export function buildBaselineFromResult(
  projectId: string,
  scanId: string,
  result: ScanResult,
): ScanBaseline {
  const surface = result.attackSurface || ({} as AttackSurface);
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const confirmedFindings: BaselineFinding[] = findings
    .filter((f: Finding) => f.issueFound)
    .map((f) => ({
      key: findingKey(f),
      title: f.title,
      severity: f.severity,
      endpoint: f.affectedEndpoint || f.affectedUrl || '',
      pluginId: f.pluginId || '',
      cwe: f.mappings?.cwe || f.cwe || [],
    }));

  return {
    version: 1,
    projectId,
    scanId,
    targetUrl: String(result.meta?.targetUrl || ''),
    createdAt: new Date().toISOString(),
    technology: (result.meta?.technology || result.recon?.technology || {}) as Record<
      string,
      unknown
    >,
    endpoints: (surface.endpoints || []).map((e) => ({
      url: e.url,
      method: e.method || 'GET',
    })),
    pages: surface.pages || [],
    apiBases: surface.apiBases || [],
    confirmedFindings,
    score: Number(result.risk?.overallScore ?? result.stats?.securityScore ?? 0),
    risk: String(result.risk?.overallRisk ?? result.stats?.overallRisk ?? 'Informational'),
  };
}

export function diffBaseline(
  baseline: ScanBaseline | null,
  surface: AttackSurface,
): BaselineDiff {
  if (!baseline) {
    return {
      available: false,
      newEndpoints: [],
      removedEndpoints: [],
      unchangedEndpoints: [],
      priorConfirmed: [],
      focusEndpoints: [],
      retestPluginIds: [],
    };
  }

  const currentKeys = new Set(
    (surface.endpoints || []).map((e) => endpointKey(e.url, e.method)),
  );
  const baseKeys = new Set(
    (baseline.endpoints || []).map((e) => endpointKey(e.url, e.method)),
  );

  const newEndpoints: string[] = [];
  const unchangedEndpoints: string[] = [];
  const removedEndpoints: string[] = [];

  for (const e of surface.endpoints || []) {
    const k = endpointKey(e.url, e.method);
    if (baseKeys.has(k)) unchangedEndpoints.push(e.url);
    else newEndpoints.push(e.url);
  }
  for (const e of baseline.endpoints || []) {
    const k = endpointKey(e.url, e.method);
    if (!currentKeys.has(k)) removedEndpoints.push(e.url);
  }

  const priorConfirmed = baseline.confirmedFindings || [];
  const focusSet = new Set<string>([
    ...newEndpoints,
    ...priorConfirmed.map((f) => f.endpoint).filter(Boolean),
  ]);

  const retestPluginIds = [
    ...new Set(priorConfirmed.map((f) => f.pluginId).filter(Boolean)),
  ];

  return {
    available: true,
    baselineScanId: baseline.scanId,
    newEndpoints,
    removedEndpoints,
    unchangedEndpoints,
    priorConfirmed,
    focusEndpoints: [...focusSet],
    retestPluginIds,
  };
}
