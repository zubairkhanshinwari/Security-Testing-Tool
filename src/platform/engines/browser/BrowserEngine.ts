import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';
import type { Logger } from '../../core/logging/logger';

export interface BrowserSession {
  browser: Browser;
  context: BrowserContext;
  page: Page;
}

/**
 * Browser Engine — owns Playwright lifecycle only.
 * Does not crawl, authenticate, or probe vulnerabilities.
 */
export class BrowserEngine {
  private session: BrowserSession | null = null;

  constructor(
    private readonly logger: Logger,
    private readonly config: Record<string, any> = {},
  ) {}

  async launch(options: { headless?: boolean; userAgent?: string } = {}): Promise<BrowserSession> {
    if (this.session) {
      this.logger.warn('Browser already launched; returning existing session');
      return this.session;
    }

    const headless = options.headless !== false;
    const userAgent =
      options.userAgent ||
      this.config.browser?.userAgent ||
      'SecureAssess/2.0 (+authorized-testing; non-destructive)';

    this.logger.info('Launching browser', { headless });
    const browser = await chromium.launch({ headless });
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      userAgent,
    });
    const page = await context.newPage();
    this.session = { browser, context, page };
    return this.session;
  }

  getSession(): BrowserSession {
    if (!this.session) throw new Error('BrowserEngine: launch() required before getSession()');
    return this.session;
  }

  async setExtraHTTPHeaders(headers: Record<string, string>): Promise<void> {
    const { context } = this.getSession();
    await context.setExtraHTTPHeaders(headers);
  }

  async newPage(): Promise<Page> {
    const { context } = this.getSession();
    return context.newPage();
  }

  async close(): Promise<void> {
    if (!this.session) return;
    try {
      await this.session.browser.close();
    } catch (err: any) {
      this.logger.warn('Browser close failed', { error: err?.message || String(err) });
    } finally {
      this.session = null;
    }
  }
}
