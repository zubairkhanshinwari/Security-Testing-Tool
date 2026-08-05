import path from 'path';
import { createRequire } from 'module';
import type { AuthSession, ScanRequest } from '../../core/types/finding';
import type { Logger } from '../../core/logging/logger';

const nodeRequire = createRequire(__filename);

/**
 * Authentication Engine — adaptive adapters (API JWT, cookie session, SPA form).
 * OAuth/SAML/social providers remain planned stubs.
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
        adapter: 'provided-header',
        ready: true,
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
        adapter: 'api-key',
        ready: true,
      };
    }

    if (request.username && request.password) {
      this.logger.info('Attempting adaptive username/password login', {
        adapters: ['api-token', 'cookie-session', 'spa-form'],
      });
      const { loginWithCredentials, assertSessionReady } = nodeRequire(
        path.join(process.cwd(), 'src', 'scanner', 'login.js'),
      );
      const result = await loginWithCredentials(page, {
        username: request.username,
        password: request.password,
        apiBases,
        origin,
        loginUrl: request.targetUrl,
      });

      if (!result.ok) {
        this.logger.warn('Adaptive login failed', {
          message: result.message,
          tried: result.strategiesTried,
        });
        return {
          ok: false,
          type: 'password',
          token: null,
          message: result.message || 'Login failed',
          adapter: result.strategiesTried?.slice(-1)[0],
          ready: false,
        };
      }

      // Final settle + readiness (adapter already checked; re-verify after header prep)
      const ready = result.ready
        ? { ready: true, reason: 'adapter-gated', token: result.token, url: result.postLoginUrl }
        : await assertSessionReady(page, origin, result);

      if (!ready.ready) {
        this.logger.warn('Login reported ok but session not ready', { reason: ready.reason });
        return {
          ok: false,
          type: 'password',
          token: null,
          message: `Login incomplete: ${ready.reason}`,
          adapter: result.adapter,
          ready: false,
        };
      }

      const isCookie =
        result.sessionType === 'cookie' || String(result.token || '').startsWith('cookie:');
      const isJwt =
        result.sessionType === 'jwt' ||
        (typeof result.token === 'string' && /^eyJ/.test(result.token));

      if (!isCookie && result.token) {
        try {
          await page.evaluate((tok: string) => {
            localStorage.setItem('access_u_token', tok);
            localStorage.setItem('access_token', tok);
            sessionStorage.setItem('access_token', tok);
          }, result.token);
        } catch {
          /* SPA may still be settling — cookies/token already on context */
        }
      }

      const bearer =
        !isCookie && result.token
          ? /^Bearer\s+/i.test(result.token)
            ? result.token
            : `Bearer ${result.token}`
          : undefined;

      this.logger.info('Adaptive login succeeded', {
        adapter: result.adapter,
        sessionType: result.sessionType,
        ready: ready.reason,
        postLoginUrl: result.postLoginUrl || page.url(),
      });

      return {
        ok: true,
        type: isCookie ? 'cookie' : isJwt ? 'jwt' : 'password',
        token: isCookie ? null : result.token,
        headers: isCookie ? {} : bearer ? { authorization: bearer } : {},
        message: result.message,
        endpoint: result.endpoint,
        adapter: result.adapter,
        ready: true,
        proof: result.proof,
        postLoginUrl: result.postLoginUrl || page.url(),
      };
    }

    return { ok: false, type: 'none', token: null, message: 'No credentials provided', ready: false };
  }

  listSupportedProviders(): string[] {
    return [
      'api-token (JWT)',
      'cookie-session',
      'spa-form',
      'username-password (adaptive)',
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
