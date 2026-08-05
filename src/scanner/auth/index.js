/**
 * Auth adapter orchestrator — picks JWT / cookie / SPA strategies and
 * gates success with assertSessionReady before returning.
 */
const { detectAuthStrategies } = require('./detectStrategy');
const { assertSessionReady } = require('./sessionSuccess');
const { settlePage } = require('./settle');
const { tryApiTokenAdapter } = require('./adapters/apiToken');
const { tryCookieSessionAdapter } = require('./adapters/cookieSession');
const { trySpaFormAdapter } = require('./adapters/spaForm');
const { extractToken } = require('./sessionSuccess');

const ADAPTERS = {
  'api-token': tryApiTokenAdapter,
  'cookie-session': tryCookieSessionAdapter,
  'spa-form': trySpaFormAdapter,
};

/**
 * @returns {Promise<{
 *   ok: boolean,
 *   token?: string|null,
 *   sessionType?: string|null,
 *   adapter?: string,
 *   endpoint?: string,
 *   message: string,
 *   cookies?: string[],
 *   proof?: string[],
 *   ready?: boolean,
 *   strategiesTried?: string[],
 * }>}
 */
async function loginWithCredentials(page, { username, password, apiBases = [], origin, loginUrl }) {
  if (!username || !password) {
    return { ok: false, token: null, message: 'No credentials provided' };
  }

  const loginPage = loginUrl || `${origin}/login`;
  const { order, hints } = detectAuthStrategies({
    origin,
    loginUrl: loginPage,
    apiBases,
  });

  const ctx = { username, password, origin, apiBases, loginUrl: loginPage };
  const tried = [];
  const failures = [];

  for (const id of order) {
    const fn = ADAPTERS[id];
    if (!fn) continue;
    tried.push(id);
    let result;
    try {
      result = await fn(page, ctx);
    } catch (e) {
      failures.push(`${id}: ${e.message || e}`);
      continue;
    }
    if (!result?.ok) {
      failures.push(result?.message || `${id}: failed`);
      continue;
    }

    // Settle then prove session before declaring success
    await settlePage(page, { pauseMs: 500 });
    const ready = await assertSessionReady(page, origin, result);
    if (!ready.ready) {
      failures.push(`${id}: login response ok but session not ready (${ready.reason})`);
      continue;
    }

    const token =
      ready.token && !String(ready.token).startsWith('cookie:')
        ? ready.token
        : result.token;

    return {
      ok: true,
      ready: true,
      token,
      sessionType: result.sessionType,
      adapter: result.adapter || id,
      endpoint: result.endpoint,
      message: `${result.message} [ready:${ready.reason}]`,
      cookies: result.cookies || ready.sessionCookies,
      proof: [...(result.proof || []), ready.reason],
      strategiesTried: tried,
      strategyHints: hints,
      postLoginUrl: ready.url || page.url(),
    };
  }

  return {
    ok: false,
    ready: false,
    token: null,
    message: `All auth adapters failed (${tried.join(' → ')}). ${failures.slice(-3).join('; ')}`,
    strategiesTried: tried,
    strategyHints: hints,
  };
}

module.exports = {
  loginWithCredentials,
  extractToken,
  detectAuthStrategies,
  assertSessionReady,
  ADAPTERS,
};
