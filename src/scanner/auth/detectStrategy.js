/**
 * Choose adapter order from target URL + discovered API bases.
 */

function detectAuthStrategies({ origin, loginUrl, apiBases = [] }) {
  const blob = [origin, loginUrl, ...(apiBases || [])].join(' ').toLowerCase();
  const ordered = [];

  const push = (id) => {
    if (!ordered.includes(id)) ordered.push(id);
  };

  // Frappe / ERPNext style
  if (/\/api\/method\/login|frappe|erpnext/.test(blob)) {
    push('cookie-session');
    push('api-token');
    push('spa-form');
    return { order: ordered, hints: ['frappe-cookie'] };
  }

  // Explicit API auth hosts
  if (/auth\/(login|signin)|\/api\/login|oauth|jwt/.test(blob)) {
    push('api-token');
    push('cookie-session');
    push('spa-form');
    return { order: ordered, hints: ['api-auth'] };
  }

  // Login page URL → try API first (faster), then SPA form (Bump Coach etc.)
  if (/\/login|\/signin|\/sign-in|\/dashboard\/login/.test(String(loginUrl || '').toLowerCase())) {
    push('api-token');
    push('spa-form');
    push('cookie-session');
    return { order: ordered, hints: ['login-page'] };
  }

  push('api-token');
  push('cookie-session');
  push('spa-form');
  return { order: ordered, hints: ['default'] };
}

function buildLoginCandidates(origin, apiBases = []) {
  const candidates = [];
  for (const base of apiBases || []) {
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
      /* ignore */
    }
  }
  candidates.push(
    `${origin}/api/method/login`,
    `${origin}/api/auth/signin`,
    `${origin}/api/auth/login`,
    `${origin}/api/login`,
    `${origin}/login`,
  );
  return [...new Set(candidates)];
}

module.exports = { detectAuthStrategies, buildLoginCandidates };
