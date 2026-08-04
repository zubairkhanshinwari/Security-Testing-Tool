const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

function createPlugin(manifest) {
  return {
    manifest,

    async discover(ctx) {
      const authPages = (ctx.attackSurface.pages || []).filter((p) =>
        /login|signin|signup|register|logout|forgot|reset|account|session/i.test(p),
      );
      const authApis = (ctx.attackSurface.authEndpoints || []).slice(0, 10);
      return {
        targets: [
          { type: 'surface', authPages, authApis },
          ...authPages.slice(0, 8).map((url) => ({ type: 'page', url })),
        ],
      };
    },

    async scan(ctx, discovery) {
      const surface = (discovery.targets || []).find((t) => t.type === 'surface') || {
        authPages: [],
        authApis: [],
      };
      const cookies = await ctx.page.context().cookies(ctx.request.targetUrl);
      const sessionCookies = cookies.filter((c) => /sess|auth|token|sid|jwt/i.test(c.name));

      let storageTokens = 0;
      try {
        storageTokens = await ctx.page.evaluate(() => {
          let n = 0;
          for (const store of [localStorage, sessionStorage]) {
            try {
              for (const k of Object.keys(store || {})) {
                if (/token|auth|jwt|session/i.test(k)) n += 1;
              }
            } catch {
              /* ignore */
            }
          }
          return n;
        });
      } catch {
        storageTokens = 0;
      }

      // Probe logout endpoint existence (GET only — never force logout of real users destructively)
      const logoutHits = [];
      for (const pageUrl of (surface.authPages || []).filter((u) => /logout|signout/i.test(u)).slice(0, 3)) {
        try {
          const res = await ctx.page.context().request.fetch(pageUrl, {
            failOnStatusCode: false,
            timeout: 10000,
          });
          logoutHits.push({ url: pageUrl, status: res.status() });
        } catch {
          /* ignore */
        }
      }

      const issues = [];
      if (!(surface.authPages || []).length && !(surface.authApis || []).length) {
        issues.push('no login/logout surfaces discovered — auth flows not exercised');
      }
      if (ctx.auth && !ctx.auth.ok) {
        issues.push('session not established — authenticated session controls not verified');
      }
      if (sessionCookies.some((c) => !c.expires || c.expires < 0)) {
        // Playwright uses -1 for session cookies — OK, but flag missing expiry on persistent auth cookies
      }
      const persistentAuth = sessionCookies.filter(
        (c) => typeof c.expires === 'number' && c.expires > 0 && c.expires - Date.now() / 1000 > 30 * 24 * 3600,
      );
      if (persistentAuth.length) {
        issues.push(`long-lived auth cookie (>30d): ${persistentAuth.map((c) => c.name).join(', ')}`);
      }
      if (storageTokens > 0 && sessionCookies.length === 0 && !(ctx.auth && ctx.auth.ok)) {
        issues.push('auth-like tokens in web storage without Secure cookie session');
      }

      return [
        {
          authPageCount: (surface.authPages || []).length,
          authApiCount: (surface.authApis || []).length,
          sessionCookieCount: sessionCookies.length,
          storageTokens,
          logoutHits,
          authOk: Boolean(ctx.auth?.ok),
          issues,
        },
      ];
    },

    async verify(ctx, candidates) {
      const c = candidates[0] || { issues: [] };
      const issues = c.issues || [];
      // Informational gaps vs confirmed weaknesses
      const confirmed = issues.filter((i) => /long-lived|web storage/i.test(i));
      const issueFound = confirmed.length > 0;
      const severity = issueFound ? 'Low' : 'Informational';

      return [
        {
          pluginId: manifest.id,
          title: issueFound
            ? `Session management concerns: ${confirmed.join('; ')}`
            : c.authOk
              ? 'Session established; no strong session hygiene issues flagged'
              : 'Session management review (limited without authenticated session)',
          description: [
            `Auth pages=${c.authPageCount || 0}, auth APIs=${c.authApiCount || 0}, session cookies=${c.sessionCookieCount || 0}, storage tokens=${c.storageTokens || 0}.`,
            issues.length ? `Notes: ${issues.join('; ')}.` : '',
          ]
            .filter(Boolean)
            .join(' '),
          severity,
          confidence: issueFound ? 'Likely' : 'Informational',
          cvss: issueFound ? cvssFor('session-mgmt', severity) : null,
          mappings: mappingsFor('session-mgmt'),
          affectedUrl: ctx.request.targetUrl,
          affectedEndpoint: ctx.request.targetUrl,
          parameter: 'session',
          method: 'N/A',
          evidence: [
            {
              technique: 'Session hygiene review',
              ...c,
              issues,
            },
          ],
          http: [],
          impact: issueFound
            ? 'Weak session lifetime or token storage can increase account takeover risk.'
            : 'None confirmed',
          remediation:
            'Rotate session IDs on login; expire sessions reasonably; prefer HttpOnly cookies over localStorage for tokens; invalidate on logout.',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/',
          ],
          status: issueFound ? 'Confirmed' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'Session Management',
          techniques: ['Session Management Testing'],
        },
      ];
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      return { delta: findings.some((f) => f.issueFound) ? 5 : 0, notes: [] };
    },
  };
}

module.exports = { createPlugin };
