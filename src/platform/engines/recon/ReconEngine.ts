import path from 'path';
import { createRequire } from 'module';
import type { Logger } from '../../core/logging/logger';
import { parseOpenApiDocument } from '../discovery/openapiParse';

const nodeRequire = createRequire(__filename);

export interface ReconDiscoverOptions {
  maxLinks?: number;
  extraSeedLinks?: string[];
  collectFormsOnCrawl?: boolean;
  parseOpenApi?: boolean;
  maxOpenApiPaths?: number;
  maxSitemapUrls?: number;
  pageSettleMs?: number;
  homeSettleMs?: number;
  scriptScanLimit?: number;
}

/**
 * Recon Engine — discovers pages, APIs, forms, docs, and framework signals.
 * Wraps the proven Playwright recon module and extends with passive document discovery.
 * Phase A: sitemap seeds → crawl, OpenAPI parse → endpoint inventory.
 */
export class ReconEngine {
  constructor(private readonly logger: Logger) {}

  async discover(page: any, targetUrl: string, options: ReconDiscoverOptions = {}) {
    this.logger.info('Starting reconnaissance', { targetUrl });
    const { discoverSurfaces } = nodeRequire(path.join(
      process.cwd(),
      'src',
      'scanner',
      'recon.js',
    ));

    const request = page.context().request;
    const origin = new URL(targetUrl).origin;
    const maxSitemap = options.maxSitemapUrls ?? 50;
    const extras = await this.discoverPassiveDocs(request, origin, maxSitemap);

    const sameOriginSeeds = (extras.sitemapUrls || []).filter((u) => {
      try {
        return new URL(u).origin === origin;
      } catch {
        return false;
      }
    });

    const base = await discoverSurfaces(page, targetUrl, {
      maxLinks: options.maxLinks ?? 8,
      extraSeedLinks: [...sameOriginSeeds.slice(0, options.maxSitemapUrls ?? 15), ...(options.extraSeedLinks || [])],
      collectFormsOnCrawl: options.collectFormsOnCrawl !== false,
      pageSettleMs: options.pageSettleMs ?? 350,
      homeSettleMs: options.homeSettleMs ?? 700,
      scriptScanLimit: options.scriptScanLimit ?? 6,
    });

    let openapiEndpoints: ReturnType<typeof parseOpenApiDocument> = [];
    if (options.parseOpenApi !== false && extras.openapiCandidates?.length) {
      openapiEndpoints = await this.parseOpenApiCandidates(
        request,
        origin,
        extras.openapiCandidates,
        options.maxOpenApiPaths ?? 30,
      );
    }

    const apis = mergeApis(base.apis || [], openapiEndpoints);

    this.logger.info('Reconnaissance complete', {
      pages: (base.visitedUrls || []).length,
      forms: base.pageInfo?.forms?.length || 0,
      apis: apis.length,
      sitemapSeeds: sameOriginSeeds.length,
      openapiEndpoints: openapiEndpoints.length,
    });

    return {
      ...base,
      apis,
      robots: extras.robots,
      sitemapUrls: extras.sitemapUrls,
      openapiCandidates: extras.openapiCandidates,
      openapiEndpoints,
      securityTxt: extras.securityTxt,
      frameworks: extras.frameworks,
      serviceWorkerHints: extras.serviceWorkerHints,
    };
  }

  private async parseOpenApiCandidates(
    request: any,
    origin: string,
    candidates: string[],
    maxPaths: number,
  ) {
    const all: ReturnType<typeof parseOpenApiDocument> = [];
    for (const url of candidates.slice(0, 4)) {
      try {
        const res = await request.fetch(url, { failOnStatusCode: false, timeout: 8000 });
        if (res.status() < 200 || res.status() >= 400) continue;
        const text = await res.text();
        // Skip giant OpenAPI docs that explode scan time
        if (text.length > 1_500_000) {
          this.logger.warn('Skipping oversized OpenAPI document', { url, bytes: text.length });
          continue;
        }
        let doc: unknown;
        try {
          doc = JSON.parse(text);
        } catch {
          continue;
        }
        const parsed = parseOpenApiDocument(doc, origin, maxPaths - all.length);
        all.push(...parsed);
        this.logger.info('Parsed OpenAPI document', { url, endpoints: parsed.length });
        if (all.length >= maxPaths) break;
      } catch {
        /* ignore */
      }
    }
    return all.slice(0, maxPaths);
  }

  private async discoverPassiveDocs(request: any, origin: string, maxSitemapUrls: number) {
    const getText = async (url: string) => {
      try {
        const res = await request.fetch(url, { failOnStatusCode: false, timeout: 10000 });
        if (res.status() >= 200 && res.status() < 400) return await res.text();
      } catch {
        /* ignore */
      }
      return null;
    };

    const robots = await getText(`${origin}/robots.txt`);
    const sitemapXml = await getText(`${origin}/sitemap.xml`);
    const securityTxt =
      (await getText(`${origin}/.well-known/security.txt`)) ||
      (await getText(`${origin}/security.txt`));

    const openapiCandidates: string[] = [];
    for (const p of [
      '/openapi.json',
      '/swagger.json',
      '/v3/api-docs',
      '/api-docs',
      '/swagger/v1/swagger.json',
      '/api/openapi.json',
      '/api/swagger.json',
    ]) {
      const body = await getText(`${origin}${p}`);
      if (body && (/openapi|swagger/i.test(body) || body.trim().startsWith('{'))) {
        openapiCandidates.push(`${origin}${p}`);
      }
    }

    const sitemapUrls: string[] = [];
    if (sitemapXml) {
      const locs = [...sitemapXml.matchAll(/<loc>([^<]+)<\/loc>/gi)].map((m) => m[1]);
      sitemapUrls.push(...locs.slice(0, maxSitemapUrls));
    }
    // robots.txt Sitemap: directives
    if (robots) {
      for (const m of robots.matchAll(/Sitemap:\s*(\S+)/gi)) {
        const smUrl = m[1];
        try {
          const smBody = await getText(smUrl);
          if (smBody) {
            const locs = [...smBody.matchAll(/<loc>([^<]+)<\/loc>/gi)].map((x) => x[1]);
            for (const loc of locs) {
              if (sitemapUrls.length >= maxSitemapUrls) break;
              if (!sitemapUrls.includes(loc)) sitemapUrls.push(loc);
            }
          }
        } catch {
          /* ignore */
        }
      }
    }

    const frameworks: string[] = [];
    if (robots || sitemapXml) frameworks.push('web');

    return {
      robots,
      sitemapUrls,
      openapiCandidates,
      securityTxt,
      frameworks,
      serviceWorkerHints: [] as string[],
    };
  }
}

function mergeApis(existing: any[], openapi: any[]): any[] {
  const seen = new Set<string>();
  const out: any[] = [];
  for (const hit of [...existing, ...openapi]) {
    const key = `${hit.method || 'GET'} ${(hit.url || '').split('?')[0]}`;
    if (!hit.url || seen.has(key)) continue;
    seen.add(key);
    out.push(hit);
  }
  return out;
}
