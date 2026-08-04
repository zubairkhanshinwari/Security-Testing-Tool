import type { AuthSession, ScanRequest } from '../../core/types/finding';
import type { Logger } from '../../core/logging/logger';
import type { AuthEngine } from '../auth/AuthEngine';
import type { BrowserEngine } from '../browser/BrowserEngine';
import type { KnowledgeRepository } from '../../core/knowledge';

/**
 * Session Engine — login, token recovery, header injection into the browser context.
 * Prefers discovery data from KnowledgeRepository when available (Phase 2).
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

    if (session.ok && session.headers) {
      await this.browser.setExtraHTTPHeaders(session.headers);
    }

    if (repo) repo.setSession(session);

    return session;
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
      headers: { authorization: raw },
      message: 'Token discovered from application traffic/storage',
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
