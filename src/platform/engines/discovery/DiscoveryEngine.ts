import type { Logger } from '../../core/logging/logger';
import type { ReconEngine, ReconDiscoverOptions } from '../recon/ReconEngine';
import type { BrowserEngine } from '../browser/BrowserEngine';
import type { KnowledgeRepository } from '../../core/knowledge';

export interface DiscoveryOptions extends ReconDiscoverOptions {
  /** When provided, discovery results are written to the shared knowledge store. */
  repo?: KnowledgeRepository;
  /** Merge into existing discovery instead of replacing (auth recrawl). */
  merge?: boolean;
}

/**
 * Discovery Engine — finds pages, forms, APIs, docs. Never runs vulnerability probes.
 * Writes through KnowledgeRepository when a scan context is supplied (Phase 2).
 * Phase A: supports authenticated re-discovery with merge.
 */
export class DiscoveryEngine {
  constructor(
    private readonly logger: Logger,
    private readonly recon: ReconEngine,
    private readonly browser: BrowserEngine,
  ) {}

  async discover(targetUrl: string, options: DiscoveryOptions = {}) {
    this.logger.info('Discovery starting', {
      targetUrl,
      maxLinks: options.maxLinks,
      merge: Boolean(options.merge),
    });
    const { page } = this.browser.getSession();
    const result = await this.recon.discover(page, targetUrl, {
      maxLinks: options.maxLinks ?? 8,
      extraSeedLinks: options.extraSeedLinks,
      collectFormsOnCrawl: options.collectFormsOnCrawl,
      parseOpenApi: options.parseOpenApi,
      maxOpenApiPaths: options.maxOpenApiPaths,
      maxSitemapUrls: options.maxSitemapUrls,
      pageSettleMs: options.pageSettleMs,
      homeSettleMs: options.homeSettleMs,
      scriptScanLimit: options.scriptScanLimit,
    });
    if (options.repo) {
      if (options.merge && options.repo.hasDiscovery()) {
        options.repo.mergeDiscovery(result);
      } else {
        options.repo.setDiscovery(result);
      }
    }
    return result;
  }
}
