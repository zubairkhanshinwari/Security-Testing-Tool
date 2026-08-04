import path from 'path';
import { createRequire } from 'module';
import type { AuthSession, ScanRequest } from '../../core/types/finding';
import type { Logger } from '../../core/logging/logger';

const nodeRequire = createRequire(__filename);

/**
 * Authentication Engine — password login, JWT/Bearer/API key injection, session headers.
 * OAuth/SAML/social providers are scaffolded for future adapters (safe stubs).
 */
export class AuthEngine {
  constructor(private readonly logger: Logger) {}

  async authenticate(
    page: any,
    request: ScanRequest,
    apiBases: string[],
  ): Promise<AuthSession> {
    const origin = new URL(request.targetUrl).origin;

    if (request.authHeader) {
      const token = String(request.authHeader).replace(/^Bearer\s+/i, '').trim();
      this.logger.info('Using provided Authorization header/token');
      return {
        ok: true,
        type: /^eyJ/.test(token) ? 'jwt' : 'bearer',
        token,
        headers: { authorization: request.authHeader },
        message: 'Using provided auth header',
      };
    }

    if (request.apiKey) {
      this.logger.info('Using provided API key');
      return {
        ok: true,
        type: 'apiKey',
        token: request.apiKey,
        headers: { 'x-api-key': request.apiKey, authorization: `ApiKey ${request.apiKey}` },
        message: 'Using API key',
      };
    }

    if (request.username && request.password) {
      this.logger.info('Attempting username/password login');
      const { loginWithCredentials } = nodeRequire(path.join(
        process.cwd(),
        'src',
        'scanner',
        'login.js',
      ));
      const result = await loginWithCredentials(page, {
        username: request.username,
        password: request.password,
        apiBases,
        origin,
        loginUrl: request.targetUrl,
      });
      if (result.ok) {
        const isCookie = result.sessionType === 'cookie' || String(result.token || '').startsWith('cookie:');
        if (result.token && !isCookie) {
          try {
            await page.evaluate((tok: string) => {
              localStorage.setItem('access_u_token', tok);
              localStorage.setItem('access_token', tok);
              sessionStorage.setItem('access_token', tok);
            }, result.token);
          } catch {
            /* ignore */
          }
        }
        return {
          ok: true,
          type: isCookie ? 'cookie' : 'password',
          token: isCookie ? null : result.token,
          // Cookie sessions rely on Playwright context cookies — do not force Authorization
          headers: isCookie ? {} : { authorization: result.token },
          message: result.message,
          endpoint: result.endpoint,
        };
      }
      return {
        ok: false,
        type: 'password',
        token: null,
        message: result.message || 'Login failed',
      };
    }

    return { ok: false, type: 'none', token: null, message: 'No credentials provided' };
  }

  /**
   * Future: OAuth2 / OIDC / SAML / social login adapters.
   * Kept as explicit stubs so the architecture is ready without unsafe automation.
   */
  listSupportedProviders(): string[] {
    return [
      'username-password',
      'jwt',
      'bearer',
      'api-key',
      'cookie',
      'oauth2 (planned)',
      'google (planned)',
      'github (planned)',
      'microsoft (planned)',
      'azure-ad (planned)',
      'okta (planned)',
      'auth0 (planned)',
      'saml (planned)',
    ];
  }
}
