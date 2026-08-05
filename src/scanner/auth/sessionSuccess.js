/**
 * Shared login-success detection for JWT, cookie, and SPA adapters.
 */

function extractToken(text, headers = {}) {
  const authH = headers.authorization || headers.Authorization;
  if (authH && String(authH).length > 20) {
    return String(authH).replace(/^Bearer\s+/i, '').trim();
  }

  try {
    const j = JSON.parse(text);
    const paths = [
      j.token,
      j.access_token,
      j.accessToken,
      j.jwt,
      j.data && j.data.token,
      j.data && j.data.access_token,
      j.data && j.data.accessToken,
      j.result && j.result.token,
      j.user && j.user.token,
      j.payload && j.payload.token,
    ];
    for (const p of paths) {
      if (typeof p === 'string' && p.length > 20) return p;
    }
    const flat = JSON.stringify(j);
    const m = flat.match(/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/);
    if (m) return m[0];
  } catch {
    const m = String(text).match(/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/);
    if (m) return m[0];
  }
  return null;
}

function isSessionCookie(cookie) {
  if (!cookie?.name || !cookie?.value) return false;
  const name = String(cookie.name);
  const value = String(cookie.value);
  if (name === 'sid' && value !== 'Guest' && value.length > 8) return true;
  if (/^(session|auth|token|jwt|connect\.sid|access_token|refresh_token)$/i.test(name) && value.length > 8) {
    return true;
  }
  if (/session|auth|token|jwt|sid/i.test(name) && value.length > 12 && value !== 'Guest') return true;
  return false;
}

function analyzeApiLoginResponse(res, text, cookies) {
  const status = res.status();
  const cookieNames = (cookies || []).map((c) => c.name);
  const sessionCookies = (cookies || []).filter(isSessionCookie);
  const hasSid = sessionCookies.some((c) => c.name === 'sid');
  const token = extractToken(text, res.headers());

  let messageLoggedIn = false;
  let rejected = false;
  try {
    const j = JSON.parse(text);
    const msg = String(j.message || j.msg || j.error || '').toLowerCase();
    rejected =
      Boolean(j.exc || j.exception) ||
      /invalid|incorrect|failed|unauthorized|forbidden|bad credentials/i.test(msg);
    messageLoggedIn =
      !rejected &&
      (msg.includes('logged in') ||
        msg === 'ok' ||
        Boolean(j.full_name) ||
        Boolean(j.home_page) ||
        Boolean(j.user) ||
        Boolean(j.data && (j.data.user || j.data.token)));
  } catch {
    /* ignore */
  }

  if (rejected || status === 401 || status === 403) {
    return { ok: false, token: null, sessionType: null, cookieNames, reason: 'rejected' };
  }

  if (status >= 200 && status < 300 && token) {
    return {
      ok: true,
      token,
      sessionType: /^eyJ/.test(token) ? 'jwt' : 'token',
      adapter: 'api-token',
      cookieNames,
      proof: ['api-token'],
    };
  }

  if (status >= 200 && status < 300 && (sessionCookies.length || messageLoggedIn)) {
    return {
      ok: true,
      token: hasSid ? 'cookie:sid' : 'cookie:session',
      sessionType: 'cookie',
      adapter: 'cookie-session',
      cookieNames,
      proof: hasSid ? ['cookie-sid'] : ['cookie-session'],
    };
  }

  return { ok: false, token: null, sessionType: null, cookieNames, reason: 'no-session' };
}

/**
 * Post-login readiness gate — must pass before auth-recrawl / plugins.
 */
async function assertSessionReady(page, origin, loginResult) {
  if (!loginResult?.ok) {
    return { ready: false, reason: loginResult?.message || 'login not ok' };
  }

  await require('./settle').settlePage(page, { pauseMs: 400 });

  const cookies = await page.context().cookies(origin).catch(() => []);
  const sessionCookies = cookies.filter(isSessionCookie);
  const url = page.url();
  const stillOnLogin = /\/login(\?|$|\/)/i.test(url);

  let storageToken = null;
  try {
    storageToken = await require('./settle').safeEvaluate(page, () => {
      for (const store of [localStorage, sessionStorage]) {
        for (const k of Object.keys(store || {})) {
          if (!/token|auth|jwt|access|session/i.test(k)) continue;
          const v = store.getItem(k);
          if (v && (v.length > 20 || /^eyJ/.test(v))) return v;
        }
      }
      return null;
    });
  } catch {
    /* navigation race — cookies may still be enough */
  }

  const isCookie =
    loginResult.sessionType === 'cookie' || String(loginResult.token || '').startsWith('cookie:');
  const isToken =
    loginResult.sessionType === 'jwt' ||
    loginResult.sessionType === 'token' ||
    (loginResult.token && !isCookie);

  if (isToken && (loginResult.token || storageToken)) {
    return {
      ready: true,
      reason: 'token-session',
      token: storageToken || loginResult.token,
      sessionCookies: sessionCookies.map((c) => c.name),
      url,
    };
  }

  if (isCookie && sessionCookies.length) {
    return {
      ready: true,
      reason: 'cookie-session',
      token: loginResult.token,
      sessionCookies: sessionCookies.map((c) => c.name),
      url,
    };
  }

  // SPA success: left login page and has either cookie or storage token
  if (!stillOnLogin && (sessionCookies.length || storageToken)) {
    return {
      ready: true,
      reason: 'spa-navigated',
      token: storageToken || loginResult.token,
      sessionCookies: sessionCookies.map((c) => c.name),
      url,
    };
  }

  // Soft allow: adapter said ok + left login (some apps use httpOnly-only custom cookies)
  if (!stillOnLogin && loginResult.ok && loginResult.adapter === 'spa-form') {
    return {
      ready: true,
      reason: 'spa-left-login',
      token: loginResult.token,
      sessionCookies: sessionCookies.map((c) => c.name),
      url,
    };
  }

  return {
    ready: false,
    reason: stillOnLogin
      ? 'still-on-login-page'
      : 'no-token-or-session-cookie-after-settle',
    url,
    sessionCookies: sessionCookies.map((c) => c.name),
  };
}

module.exports = {
  extractToken,
  isSessionCookie,
  analyzeApiLoginResponse,
  assertSessionReady,
};
