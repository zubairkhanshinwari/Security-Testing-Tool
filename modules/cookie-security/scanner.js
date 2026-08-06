const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

/** Marketing/analytics cookies — flagging these as session risks creates noise. */
const ANALYTICS_COOKIE_RE =
  /^(_ga|_gid|_gat|_gcl_|_fbp|_fbc|_clck|_clsk|__utm|amp_token|ajs_|hubspotutk|_hj|_uetsid|_uetvid|_tt_|_pin_|sbjs_|_mkto_trk)/i;

function isAnalyticsCookie(name) {
  return ANALYTICS_COOKIE_RE.test(String(name || ''));
}

function createPlugin(manifest) {
  return {
    manifest,

    async discover(ctx) {
      return { targets: [{ url: ctx.request.targetUrl }] };
    },

    async scan(ctx) {
      const cookies = await ctx.page.context().cookies(ctx.request.targetUrl);
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
      const skippedAnalytics = [];
      for (const c of cookies) {
        const name = c.name || '';
        if (isAnalyticsCookie(name)) {
          skippedAnalytics.push(name);
          continue;
        }
        const sessionLike = /sess|auth|token|jwt|sid|login|session/i.test(name);
        if (!c.secure && /^https:/i.test(ctx.request.targetUrl)) {
          issues.push({ cookie: name, issue: 'missing Secure', sessionLike });
        }
        if (sessionLike && !c.httpOnly) {
          issues.push({ cookie: name, issue: 'session cookie missing HttpOnly', sessionLike });
        }
        // SameSite noise on non-session cookies is low value — only session-like
        if (sessionLike && (!c.sameSite || c.sameSite === 'None')) {
          issues.push({
            cookie: name,
            issue: `SameSite=${c.sameSite || 'missing'}`,
            sessionLike: true,
          });
        }
      }

      for (const line of setCookie) {
        const name = String(line).split('=')[0];
        if (isAnalyticsCookie(name)) continue;
        const sessionLike = /sess|auth|token|jwt|sid|login|session/i.test(line);
        if (/Secure/i.test(line) === false && /^https:/i.test(ctx.request.targetUrl) && sessionLike) {
          if (!issues.some((i) => i.cookie === name && i.issue.includes('Secure'))) {
            issues.push({ cookie: name, issue: 'Set-Cookie missing Secure', sessionLike: true });
          }
        }
        if (/HttpOnly/i.test(line) === false && sessionLike) {
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
          skippedAnalytics: skippedAnalytics.slice(0, 12),
        },
      ];
    },

    async verify(ctx, candidates) {
      const c = candidates[0] || { issues: [], cookies: [], cookieCount: 0, skippedAnalytics: [] };
      const issues = c.issues || [];
      const sessionIssues = issues.filter((i) => i.sessionLike);
      // Only session-relevant cookie weaknesses count as issues (reduces analytics noise)
      const issueFound = sessionIssues.length > 0;
      const severity = issueFound ? 'Medium' : 'Informational';
      const skippedNote =
        Array.isArray(c.skippedAnalytics) && c.skippedAnalytics.length
          ? ` Analytics/marketing cookies skipped: ${c.skippedAnalytics.slice(0, 6).join(', ')}.`
          : '';

      return [
        {
          pluginId: manifest.id,
          title: issueFound
            ? `Session cookie security issues (${sessionIssues.length})`
            : c.cookieCount
              ? 'No session-cookie flag issues (analytics cookies ignored)'
              : 'No cookies observed for review',
          description: issueFound
            ? `Observed: ${sessionIssues
                .slice(0, 8)
                .map((i) => `${i.cookie}: ${i.issue}`)
                .join('; ')}.${skippedNote}`
            : `Secure/HttpOnly/SameSite review found no session-cookie weaknesses.${skippedNote}`,
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
              issues: sessionIssues.slice(0, 15),
              skippedAnalytics: (c.skippedAnalytics || []).slice(0, 10),
              sample: (c.cookies || []).slice(0, 10),
            },
          ],
          http: [],
          impact: issueFound
            ? 'Weak session cookie flags can enable session theft or CSRF-related abuse of real user accounts.'
            : 'None',
          remediation:
            'Set Secure + HttpOnly on session cookies; use SameSite=Lax or Strict; prefer short lifetimes. Analytics cookies are out of scope for this check.',
          references: ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
          status: issueFound ? 'Likely' : 'Pass',
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

module.exports = { createPlugin, isAnalyticsCookie };
