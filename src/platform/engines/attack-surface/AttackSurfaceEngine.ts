import type { AttackSurface } from '../../core/types/finding';
import type { Logger } from '../../core/logging/logger';

/**
 * Attack Surface Engine — normalizes recon into a durable inventory.
 */
export class AttackSurfaceEngine {
  constructor(private readonly logger: Logger) {}

  build(targetUrl: string, recon: any): AttackSurface {
    const origin = new URL(targetUrl).origin;
    const hosts = new Set<string>([origin.replace(/^https?:\/\//, '')]);
    const endpoints: AttackSurface['endpoints'] = [];
    const parameters: AttackSurface['parameters'] = [];

    for (const api of recon.apis || []) {
      try {
        const u = new URL(api.url);
        hosts.add(u.host);
        endpoints.push({
          url: api.url.split('?')[0],
          method: api.method || 'GET',
          source: api.source,
          // Never persist raw tokens on the attack surface inventory
          authHeader: api.authHeader ? '[PRESENT]' : null,
        });
        for (const key of u.searchParams.keys()) {
          parameters.push({ endpoint: `${u.origin}${u.pathname}`, name: key, location: 'query' });
        }
      } catch {
        /* ignore */
      }
    }

    for (const base of recon.apiBases || []) {
      try {
        hosts.add(new URL(base.includes('://') ? base : `https://${base}`).host);
      } catch {
        /* ignore */
      }
    }

    const visited = Array.isArray(recon.visitedUrls)
      ? (recon.visitedUrls as string[])
      : [];
    const pages: string[] = [...new Set<string>([...visited, targetUrl])];
    const frameworks = new Set<string>(
      Array.isArray(recon.frameworks) ? (recon.frameworks as string[]) : [],
    );
    const title = String(recon.pageInfo?.title || '');
    if (/angular/i.test(title) || (recon.bundleRoutes || []).length) frameworks.add('SPA');

    const hostList = [...hosts];
    const surface: AttackSurface = {
      hosts: hostList,
      subdomains: hostList.filter((h) => h.split('.').length > 2),
      pages,
      endpoints: dedupeEndpoints(endpoints).slice(0, 100),
      parameters: parameters.slice(0, 120),
      forms: recon.pageInfo?.forms || [],
      cookies: [],
      headers: {},
      frameworks: [...frameworks],
      libraries: [],
      authEndpoints: (recon.apis || [])
        .map((a: any) => a.url)
        .filter((u: string) => /auth|login|signin/i.test(u))
        .slice(0, 20),
      apiBases: recon.apiBases || [],
      websockets: [],
      graphql: (recon.apis || [])
        .map((a: any) => a.url)
        .filter((u: string) => /graphql/i.test(u)),
      openapi: recon.openapiCandidates || [],
      storageKeys: [],
      robots: recon.robots || null,
      sitemapUrls: recon.sitemapUrls || [],
      raw: {
        pageTitle: recon.pageInfo?.title,
        apisObserved: (recon.apis || []).length,
        openapiParsed: (recon.openapiEndpoints || []).length,
        bundleRoutes: (recon.bundleRoutes || []).slice(0, 40),
        pagesCrawled: (recon.visitedUrls || []).length,
        formsFound: (recon.pageInfo?.forms || []).length,
      },
    };

    this.logger.info('Attack surface built', {
      hosts: surface.hosts.length,
      endpoints: surface.endpoints.length,
      parameters: surface.parameters.length,
    });
    return surface;
  }
}

function dedupeEndpoints(
  endpoints: AttackSurface['endpoints'],
): AttackSurface['endpoints'] {
  const seen = new Set<string>();
  const out: AttackSurface['endpoints'] = [];
  for (const e of endpoints) {
    const key = `${e.method}|${e.url}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(e);
  }
  return out;
}
