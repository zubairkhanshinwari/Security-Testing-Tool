import type { AuthSession, ScanRequest } from '../../core/types/finding';
import type { Logger } from '../../core/logging/logger';
import type { AuthEngine } from '../auth/AuthEngine';
import type { BrowserEngine } from '../browser/BrowserEngine';
import type { KnowledgeRepository } from '../../core/knowledge';

/**
 * Session Engine — adaptive login, token recovery, header injection.
 * Blocks auth-recrawl until session.ready is true.
 */
export class SessionEngine {
  constructor(
    private readonly logger: Logger,
    private readonly auth: AuthEngine,
    private readonly browser: BrowserEngine,
  ) {}

  async establish(
    request: ScanRequest,
    reconOrRepo:
      | KnowledgeRepository
      | { apiBases?: string[]; apis?: any[]; discoveredToken?: string | null },
  ): Promise<AuthSession> {
    const repo = isKnowledgeRepo(reconOrRepo) ? reconOrRepo : null;
    const recon = repo
      ? repo.getDiscovery()
      : (reconOrRepo as { apiBases?: string[]; apis?: any[]; discoveredToken?: string | null });

    const { page } = this.browser.getSession();
    let session = await this.auth.authenticate(page, request, recon.apiBases || []);

    if (!session.ok) {
      const recovered = this.recoverFromTraffic(recon);
      if (recovered) {
        this.logger.info('Recovered session token from discovery traffic/storage');
        session = recovered;
      }
    }

    // Final browser settle before callers start authenticated discovery
    if (session.ok) {
      await this.stabilizeBrowser(page);
      if (session.headers && Object.keys(session.headers).length) {
        await this.browser.setExtraHTTPHeaders(session.headers);
      }
      session = { ...session, ready: session.ready !== false };
      this.logger.info('Session established', {
        type: session.type,
        adapter: session.adapter,
        ready: session.ready,
        endpoint: session.endpoint,
      });
    }

    if (repo) repo.setSession(session);

    return session;
  }

  private async stabilizeBrowser(page: any) {
    try {
      await page.waitForLoadState('domcontentloaded', { timeout: 10000 });
    } catch {
      /* ignore */
    }
    try {
      await page.waitForLoadState('networkidle', { timeout: 5000 });
    } catch {
      /* ignore */
    }
    try {
      await page.waitForTimeout(500);
    } catch {
      /* ignore */
    }
  }

  private recoverFromTraffic(recon: {
    apis?: any[];
    discoveredToken?: string | null;
  }): AuthSession | null {
    const fromTraffic = (recon.apis || []).find((a: any) => a.authHeader)?.authHeader;
    const discovered = recon.discoveredToken;
    if (!fromTraffic && !discovered) return null;

    const raw = String(fromTraffic || discovered);
    return {
      ok: true,
      type: 'discovered',
      token: raw.replace(/^Bearer\s+/i, ''),
      headers: { authorization: raw.startsWith('Bearer') ? raw : `Bearer ${raw}` },
      message: 'Token discovered from application traffic/storage',
      adapter: 'traffic-recovery',
      ready: true,
    };
  }
}

function isKnowledgeRepo(value: unknown): value is KnowledgeRepository {
  return (
    !!value &&
    typeof value === 'object' &&
    typeof (value as KnowledgeRepository).getDiscovery === 'function' &&
    typeof (value as KnowledgeRepository).setSession === 'function'
  );
}
