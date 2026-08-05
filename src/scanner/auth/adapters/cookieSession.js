/**
 * Cookie-session adapter — Frappe/ERPNext `/api/method/login` and similar.
 */
const { analyzeApiLoginResponse } = require('../sessionSuccess');
const { buildLoginCandidates } = require('../detectStrategy');

function isFrappeLogin(endpoint) {
  return /\/api\/method\/login/i.test(endpoint);
}

async function tryCookieSessionAdapter(page, ctx) {
  const { username, password, origin, apiBases = [] } = ctx;
  const request = page.context().request;
  const endpoints = buildLoginCandidates(origin, apiBases).filter(
    (e) => isFrappeLogin(e) || /\/api\/login$/i.test(e) || /\/method\/login/i.test(e),
  );

  // Always include canonical Frappe path
  if (!endpoints.some(isFrappeLogin)) {
    endpoints.unshift(`${origin}/api/method/login`);
  }

  const bodies = [
    { usr: username, pwd: password },
    { email: username, password },
    { username, password },
  ];

  for (const endpoint of [...new Set(endpoints)]) {
    for (const body of bodies) {
      try {
        const res = await request.fetch(endpoint, {
          method: 'POST',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json; charset=UTF-8',
            ...(isFrappeLogin(endpoint) ? { 'x-frappe-site-name': new URL(origin).hostname } : {}),
          },
          data: body,
          failOnStatusCode: false,
          timeout: 20000,
        });
        const text = await res.text();
        const cookies = await page.context().cookies(origin);
        const session = analyzeApiLoginResponse(res, text, cookies);
        if (session.ok && session.sessionType === 'cookie') {
          return {
            ok: true,
            token: session.token,
            sessionType: 'cookie',
            adapter: 'cookie-session',
            endpoint,
            message: `Authenticated via cookie-session adapter (${endpoint})`,
            cookies: session.cookieNames,
            proof: session.proof,
          };
        }
        if (session.ok && (session.sessionType === 'jwt' || session.sessionType === 'token')) {
          return {
            ok: true,
            token: session.token,
            sessionType: session.sessionType,
            adapter: 'api-token',
            endpoint,
            message: `Authenticated via cookie adapter path with token (${endpoint})`,
            cookies: session.cookieNames,
            proof: session.proof,
          };
        }
      } catch {
        /* continue */
      }
    }

    if (isFrappeLogin(endpoint)) {
      try {
        const form = `usr=${encodeURIComponent(username)}&pwd=${encodeURIComponent(password)}`;
        const res = await request.fetch(endpoint, {
          method: 'POST',
          headers: {
            accept: 'application/json',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'x-frappe-site-name': new URL(origin).hostname,
          },
          data: form,
          failOnStatusCode: false,
          timeout: 20000,
        });
        const text = await res.text();
        const cookies = await page.context().cookies(origin);
        const session = analyzeApiLoginResponse(res, text, cookies);
        if (session.ok) {
          return {
            ok: true,
            token: session.token,
            sessionType: session.sessionType,
            adapter: session.sessionType === 'cookie' ? 'cookie-session' : 'api-token',
            endpoint,
            message: `Authenticated via cookie-session adapter form (${endpoint})`,
            cookies: session.cookieNames,
            proof: session.proof,
          };
        }
      } catch {
        /* continue */
      }
    }
  }

  return { ok: false, adapter: 'cookie-session', message: 'Cookie-session adapter: no successful login' };
}

module.exports = { tryCookieSessionAdapter };
