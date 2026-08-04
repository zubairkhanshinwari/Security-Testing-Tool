/**
 * Attempt to authenticate with username/password against discovered API login endpoints.
 * Safe: only uses provided credentials; does not brute force.
 * Supports JWT APIs and cookie-session apps (e.g. Frappe `/api/method/login`).
 */
async function loginWithCredentials(page, { username, password, apiBases = [], origin, loginUrl }) {
  if (!username || !password) {
    return { ok: false, token: null, message: 'No credentials provided' };
  }

  const candidates = [];
  for (const base of apiBases) {
    try {
      const originBase = base.includes('://') ? new URL(base).origin : base;
      const root = /\/api$/i.test(base) ? base : `${originBase}/api`;
      candidates.push(
        `${root}/auth/signin`,
        `${root}/auth/login`,
        `${root}/login`,
        `${root}/users/login`,
        `${root}/method/login`,
      );
    } catch {
      // ignore
    }
  }
  candidates.push(
    `${origin}/api/method/login`,
    `${origin}/api/auth/signin`,
    `${origin}/api/auth/login`,
    `${origin}/api/login`,
    `${origin}/login`,
  );

  const bodies = [
    // Frappe / ERPNext
    { usr: username, pwd: password },
    { email: username, password },
    { username, password },
    { user: username, password },
    { login: username, password },
  ];

  const request = page.context().request;
  for (const endpoint of [...new Set(candidates)]) {
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
        const session = analyzeLoginSuccess(res, text, cookies);
        if (session.ok) {
          return {
            ok: true,
            token: session.token,
            sessionType: session.sessionType,
            endpoint,
            message: `Authenticated via ${endpoint} (${session.sessionType})`,
            cookies: session.cookieNames,
          };
        }
      } catch {
        // try next
      }
    }

    // Also try form-urlencoded (some Frappe installs)
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
        const session = analyzeLoginSuccess(res, text, cookies);
        if (session.ok) {
          return {
            ok: true,
            token: session.token,
            sessionType: session.sessionType,
            endpoint,
            message: `Authenticated via ${endpoint} (form, ${session.sessionType})`,
            cookies: session.cookieNames,
          };
        }
      } catch {
        /* continue */
      }
    }
  }

  // UI form fallback — works for SPA login pages (Frappe desk, Ant Design, etc.)
  const ui = await tryUiLogin(page, { username, password, loginUrl: loginUrl || `${origin}/dashboard/login`, origin });
  if (ui.ok) return ui;

  return {
    ok: false,
    token: null,
    message:
      'Login failed against discovered auth endpoints and UI form (check username/password or endpoint shape).',
  };
}

function isFrappeLogin(endpoint) {
  return /\/api\/method\/login/i.test(endpoint);
}

function analyzeLoginSuccess(res, text, cookies) {
  const status = res.status();
  const cookieNames = (cookies || []).map((c) => c.name);
  const hasSid = (cookies || []).some(
    (c) => c.name === 'sid' && c.value && c.value !== 'Guest' && c.value.length > 8,
  );
  const token = extractToken(text, res.headers());

  let messageLoggedIn = false;
  try {
    const j = JSON.parse(text);
    const msg = String(j.message || j.msg || '').toLowerCase();
    messageLoggedIn =
      msg.includes('logged in') ||
      msg === 'ok' ||
      Boolean(j.full_name) ||
      Boolean(j.home_page);
    if (j.exc || j.exception || /invalid|incorrect|failed/i.test(msg)) {
      messageLoggedIn = false;
    }
  } catch {
    /* ignore */
  }

  if (status >= 200 && status < 300 && token) {
    return { ok: true, token, sessionType: 'token', cookieNames };
  }
  if (status >= 200 && status < 300 && (hasSid || messageLoggedIn)) {
    // Cookie session — no JWT; mark ok with sentinel so AuthEngine accepts it
    return {
      ok: true,
      token: hasSid ? `cookie:sid` : 'cookie:session',
      sessionType: 'cookie',
      cookieNames,
    };
  }
  return { ok: false, token: null, sessionType: null, cookieNames };
}

async function tryUiLogin(page, { username, password, loginUrl, origin }) {
  try {
    await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForTimeout(800);

    const emailSel = [
      'input[type="email"]',
      'input[placeholder*="email" i]',
      'input[id*="email" i]',
      'input[name="email"]',
      'input[name="usr"]',
      'input[autocomplete="username"]',
    ].join(', ');
    const passSel = [
      'input[type="password"]',
      'input[name="password"]',
      'input[name="pwd"]',
      'input[autocomplete="current-password"]',
    ].join(', ');

    const email = page.locator(emailSel).first();
    const pass = page.locator(passSel).first();
    if (!(await email.count()) || !(await pass.count())) {
      return { ok: false, token: null, message: 'UI login fields not found' };
    }

    await email.fill(username);
    await pass.fill(password);

    const loginBtn = page
      .locator('button:has-text("Login"), button:has-text("Sign in"), button[type="submit"]')
      .first();
    if (await loginBtn.count()) {
      await loginBtn.click({ timeout: 5000 }).catch(async () => {
        await pass.press('Enter');
      });
    } else {
      await pass.press('Enter');
    }

    await page.waitForTimeout(2500);
    const cookies = await page.context().cookies(origin);
    const hasSid = cookies.some(
      (c) => c.name === 'sid' && c.value && c.value !== 'Guest' && c.value.length > 8,
    );
    const leftLogin = !/\/login/i.test(page.url());

    if (hasSid || leftLogin) {
      // Prefer any token from storage after UI login
      let token = null;
      try {
        token = await page.evaluate(() => {
          for (const store of [localStorage, sessionStorage]) {
            for (const k of Object.keys(store || {})) {
              const v = store.getItem(k);
              if (v && /^eyJ/.test(v)) return v;
            }
          }
          return null;
        });
      } catch {
        /* ignore */
      }
      return {
        ok: true,
        token: token || (hasSid ? 'cookie:sid' : 'cookie:session'),
        sessionType: token ? 'token' : 'cookie',
        endpoint: loginUrl,
        message: `Authenticated via UI login form (${loginUrl})`,
        cookies: cookies.map((c) => c.name),
      };
    }
  } catch (e) {
    return { ok: false, token: null, message: `UI login error: ${e.message || e}` };
  }
  return { ok: false, token: null, message: 'UI login did not establish a session' };
}

function extractToken(text, headers = {}) {
  const authH = headers.authorization || headers.Authorization;
  if (authH && String(authH).length > 20) return String(authH).replace(/^Bearer\s+/i, '').trim();

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

module.exports = { loginWithCredentials, extractToken };
