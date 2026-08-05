/**
 * API token / JWT adapter — POST JSON login bodies, expect access_token / jwt.
 */
const { analyzeApiLoginResponse } = require('../sessionSuccess');
const { buildLoginCandidates } = require('../detectStrategy');

const BODIES = (username, password) => [
  { email: username, password },
  { username, password },
  { user: username, password },
  { login: username, password },
];

async function tryApiTokenAdapter(page, ctx) {
  const { username, password, origin, apiBases = [] } = ctx;
  const request = page.context().request;
  const endpoints = buildLoginCandidates(origin, apiBases).filter(
    (e) => !/\/api\/method\/login/i.test(e),
  );

  for (const endpoint of endpoints) {
    for (const body of BODIES(username, password)) {
      try {
        const res = await request.fetch(endpoint, {
          method: 'POST',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json; charset=UTF-8',
          },
          data: body,
          failOnStatusCode: false,
          timeout: 20000,
        });
        const text = await res.text();
        const cookies = await page.context().cookies(origin);
        const session = analyzeApiLoginResponse(res, text, cookies);
        if (session.ok && (session.sessionType === 'jwt' || session.sessionType === 'token')) {
          return {
            ok: true,
            token: session.token,
            sessionType: session.sessionType,
            adapter: 'api-token',
            endpoint,
            message: `Authenticated via API token adapter (${endpoint})`,
            cookies: session.cookieNames,
            proof: session.proof,
          };
        }
        // Cookie success from a non-frappe JSON login — still valid, hand off as cookie
        if (session.ok && session.sessionType === 'cookie') {
          return {
            ok: true,
            token: session.token,
            sessionType: 'cookie',
            adapter: 'cookie-session',
            endpoint,
            message: `Authenticated via API login with cookie session (${endpoint})`,
            cookies: session.cookieNames,
            proof: session.proof,
          };
        }
      } catch {
        /* try next */
      }
    }
  }

  return { ok: false, adapter: 'api-token', message: 'API token adapter: no successful login' };
}

module.exports = { tryApiTokenAdapter };
