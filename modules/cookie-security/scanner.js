const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

function createPlugin(manifest) {
  return {
    manifest,

    async discover(ctx) {
      return { targets: [{ url: ctx.request.targetUrl }] };
    },

    async scan(ctx) {
      const cookies = await ctx.page.context().cookies(ctx.request.targetUrl);
      // Also parse Set-Cookie from a fresh fetch (may include session cookies not yet stored)
      let setCookie = [];
      try {
        const res = await ctx.page.context().request.fetch(ctx.request.targetUrl, {
          failOnStatusCode: false,
          timeout: 15000,
        });
        const raw = res.headers()['set-cookie'];
        if (raw) setCookie = Array.isArray(raw) ? raw : [raw];
      } catch {
        /* ignore */
      }

      const issues = [];
      for (const c of cookies) {
        const name = c.name || '';
        const sessionLike = /sess|auth|token|jwt|sid|login/i.test(name);
        if (!c.secure && /^https:/i.test(ctx.request.targetUrl)) {
          issues.push({ cookie: name, issue: 'missing Secure', sessionLike });
        }
        if (sessionLike && !c.httpOnly) {
          issues.push({ cookie: name, issue: 'session cookie missing HttpOnly', sessionLike });
        }
        if (!c.sameSite || c.sameSite === 'None') {
          issues.push({
            cookie: name,
            issue: `SameSite=${c.sameSite || 'missing'}`,
            sessionLike,
          });
        }
      }

      for (const line of setCookie) {
        if (/Secure/i.test(line) === false && /^https:/i.test(ctx.request.targetUrl)) {
          const name = String(line).split('=')[0];
          if (!issues.some((i) => i.cookie === name && i.issue === 'missing Secure')) {
            issues.push({ cookie: name, issue: 'Set-Cookie missing Secure', sessionLike: true });
          }
        }
        if (/HttpOnly/i.test(line) === false && /sess|auth|token|sid/i.test(line)) {
          const name = String(line).split('=')[0];
          issues.push({ cookie: name, issue: 'Set-Cookie missing HttpOnly', sessionLike: true });
        }
      }

      return [
        {
          cookieCount: cookies.length,
          cookies: cookies.map((c) => ({
            name: c.name,
            secure: c.secure,
            httpOnly: c.httpOnly,
            sameSite: c.sameSite || null,
          })),
          issues,
        },
      ];
    },

    async verify(ctx, candidates) {
      const c = candidates[0] || { issues: [], cookies: [], cookieCount: 0 };
      const issues = c.issues || [];
      const sessionIssues = issues.filter((i) => i.sessionLike);
      const issueFound = issues.length > 0;
      const severity = sessionIssues.length ? 'Medium' : issueFound ? 'Low' : 'Informational';

      return [
        {
          pluginId: manifest.id,
          title: issueFound
            ? `Cookie security issues (${issues.length})`
            : c.cookieCount
              ? 'Cookie flags look reasonable'
              : 'No cookies observed for review',
          description: issueFound
            ? `Observed: ${issues
                .slice(0, 8)
                .map((i) => `${i.cookie}: ${i.issue}`)
                .join('; ')}.`
            : 'Secure/HttpOnly/SameSite review did not find obvious cookie weaknesses.',
          severity,
          confidence: issueFound ? 'Likely' : 'Informational',
          cvss: issueFound ? cvssFor('cookie-security', severity) : null,
          mappings: mappingsFor('cookie-security'),
          affectedUrl: ctx.request.targetUrl,
          affectedEndpoint: ctx.request.targetUrl,
          parameter: 'Set-Cookie',
          method: 'GET',
          evidence: [
            {
              technique: 'Cookie flag review',
              cookieCount: c.cookieCount,
              issues: issues.slice(0, 15),
              sample: (c.cookies || []).slice(0, 10),
            },
          ],
          http: [],
          impact: issueFound
            ? 'Weak cookie flags can enable session theft or CSRF-related abuse.'
            : 'None',
          remediation:
            'Set Secure + HttpOnly on session cookies; use SameSite=Lax or Strict; prefer short lifetimes.',
          references: ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
          status: issueFound ? 'Confirmed' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'Cookie Security',
          techniques: ['Cookie Security Testing'],
        },
      ];
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      const f = findings.find((x) => x.issueFound);
      return { delta: f ? (f.severity === 'Medium' ? 8 : 3) : 0, notes: [] };
    },
  };
}

module.exports = { createPlugin };
