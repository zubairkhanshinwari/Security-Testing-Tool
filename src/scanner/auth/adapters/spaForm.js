/**
 * SPA form adapter — fill UI login, wait for navigation, then prove session.
 * Hardened against "Execution context was destroyed" races.
 */
const { settlePage, safeEvaluate } = require('../settle');
const { isSessionCookie } = require('../sessionSuccess');

async function trySpaFormAdapter(page, ctx) {
  const { username, password, origin, loginUrl } = ctx;
  const url = loginUrl || `${origin}/login`;

  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await settlePage(page, { pauseMs: 700 });

    const emailSel = [
      'input[type="email"]',
      'input[placeholder*="email" i]',
      'input[id*="email" i]',
      'input[name="email"]',
      'input[name="usr"]',
      'input[name="username"]',
      'input[autocomplete="username"]',
      'input[type="text"]',
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
      return { ok: false, adapter: 'spa-form', message: 'SPA form adapter: login fields not found' };
    }

    await email.click({ timeout: 5000 });
    await email.fill('');
    await email.fill(username);
    await pass.click({ timeout: 5000 });
    await pass.fill('');
    await pass.fill(password);

    const loginBtn = page
      .locator(
        'button:has-text("Login"), button:has-text("Log in"), button:has-text("Sign in"), button[type="submit"], input[type="submit"]',
      )
      .first();

    const beforeUrl = page.url();
    const navPromise = Promise.race([
      page.waitForURL((u) => !/\/login(\?|$|\/)/i.test(u.pathname), { timeout: 15000 }),
      page.waitForResponse(
        (r) =>
          /login|signin|auth|session|method\/login/i.test(r.url()) &&
          r.request().method() === 'POST' &&
          r.status() < 500,
        { timeout: 15000 },
      ),
    ]).catch(() => null);

    if (await loginBtn.count()) {
      await Promise.all([
        navPromise,
        loginBtn.click({ timeout: 5000 }).catch(async () => pass.press('Enter')),
      ]);
    } else {
      await Promise.all([navPromise, pass.press('Enter')]);
    }

    // Extra settle for client-side routers (Bump Coach style)
    await settlePage(page, { networkIdleMs: 8000, pauseMs: 800 });
    try {
      await page.waitForFunction(
        (prev) => location.href !== prev || !/\/login(\?|$|\/)/i.test(location.pathname),
        beforeUrl,
        { timeout: 8000 },
      );
    } catch {
      /* may stay on login if failed */
    }
    await settlePage(page, { pauseMs: 400 });

    const cookies = await page.context().cookies(origin);
    const sessionCookies = cookies.filter(isSessionCookie);
    const leftLogin = !/\/login(\?|$|\/)/i.test(page.url());

    let token = null;
    for (let i = 0; i < 3 && !token; i++) {
      try {
        token = await safeEvaluate(page, () => {
          for (const store of [localStorage, sessionStorage]) {
            for (const k of Object.keys(store || {})) {
              if (!/token|auth|jwt|access|session/i.test(k)) continue;
              const v = store.getItem(k);
              if (v && (/^eyJ/.test(v) || v.length > 20)) return v;
            }
          }
          return null;
        });
      } catch {
        await page.waitForTimeout(400 * (i + 1));
      }
    }

    const hasSession = Boolean(token || sessionCookies.length || leftLogin);
    if (!hasSession) {
      return {
        ok: false,
        adapter: 'spa-form',
        message: 'SPA form adapter: submit did not establish session or leave login page',
      };
    }

    const sessionType = token ? (/^eyJ/.test(token) ? 'jwt' : 'token') : 'cookie';
    return {
      ok: true,
      token: token || (sessionCookies.some((c) => c.name === 'sid') ? 'cookie:sid' : 'cookie:session'),
      sessionType,
      adapter: 'spa-form',
      endpoint: url,
      message: `Authenticated via SPA form adapter (${url}) → ${page.url()}`,
      cookies: cookies.map((c) => c.name),
      proof: [
        ...(token ? ['storage-token'] : []),
        ...(sessionCookies.length ? ['session-cookie'] : []),
        ...(leftLogin ? ['left-login'] : []),
      ],
    };
  } catch (e) {
    return {
      ok: false,
      adapter: 'spa-form',
      message: `SPA form adapter error: ${e.message || e}`,
    };
  }
}

module.exports = { trySpaFormAdapter };
