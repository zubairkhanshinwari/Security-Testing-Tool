const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

function createPlugin(manifest) {
  return {
    manifest,

    async discover(ctx) {
      const tokens = [];
      const fromAuth = ctx.auth?.token;
      if (fromAuth && /^eyJ/.test(String(fromAuth).replace(/^Bearer\s+/i, ''))) {
        tokens.push(String(fromAuth).replace(/^Bearer\s+/i, ''));
      }

      try {
        const fromPage = await ctx.page.evaluate(() => {
          const out = [];
          for (const store of [localStorage, sessionStorage]) {
            try {
              for (const k of Object.keys(store || {})) {
                const v = store.getItem(k);
                if (v && /^eyJ[A-Za-z0-9_-]+\./.test(v)) out.push(v.split(/\s+/).pop());
                if (v && /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(v)) {
                  const m = v.match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
                  if (m) out.push(m[0]);
                }
              }
            } catch {
              /* ignore */
            }
          }
          return out;
        });
        tokens.push(...(fromPage || []));
      } catch {
        /* ignore */
      }

      return { targets: [...new Set(tokens)].slice(0, 5).map((token) => ({ token })) };
    },

    async scan(_ctx, discovery) {
      const candidates = [];
      for (const t of discovery.targets || []) {
        try {
          candidates.push(analyzeJwt(t.token));
        } catch (e) {
          candidates.push({ tokenPresent: true, parseError: String(e.message || e), issues: [] });
        }
      }
      if (!candidates.length) {
        candidates.push({ tokenPresent: false, issues: [], note: 'No JWT observed in session/storage' });
      }
      return candidates;
    },

    async verify(ctx, candidates) {
      const c = candidates[0] || {};
      const issues = c.issues || [];
      const issueFound = issues.length > 0;
      const severity = issueFound
        ? issues.includes('alg=none')
          ? 'High'
          : 'Medium'
        : 'Informational';

      return [
        {
          pluginId: manifest.id,
          title: !c.tokenPresent
            ? 'No JWT observed for review'
            : issueFound
              ? `JWT weaknesses: ${issues.join(', ')}`
              : 'JWT structure looks conventional',
          description: !c.tokenPresent
            ? 'No JWT was found in auth session or browser storage during this scan.'
            : issueFound
              ? `Observed JWT concerns: ${issues.join('; ')}.`
              : 'A JWT was observed with a conventional header/payload structure.',
          severity,
          confidence: issueFound ? 'Confirmed' : 'Informational',
          cvss: issueFound ? cvssFor('jwt', severity) : null,
          mappings: mappingsFor('jwt'),
          affectedUrl: ctx.request.targetUrl,
          affectedEndpoint: ctx.request.targetUrl,
          parameter: 'Authorization/token',
          method: 'N/A',
          evidence: [
            {
              technique: 'JWT structural review',
              alg: c.alg,
              exp: c.exp,
              issues,
              parseError: c.parseError || null,
            },
          ],
          http: [],
          impact: issueFound
            ? 'Weak JWT configuration can enable forgery or long-lived session abuse.'
            : 'None',
          remediation:
            'Reject alg=none; use strong algorithms; always set reasonable exp; validate issuer/audience server-side.',
          references: [
            'https://cwe.mitre.org/data/definitions/347.html',
            'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/',
          ],
          status: issueFound ? 'Confirmed' : 'Pass',
          issueFound,
          testMode: ctx.request.mode || 'active-safe',
          module: 'JWT Security',
          techniques: ['JWT Security Testing'],
        },
      ];
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      const f = findings.find((x) => x.issueFound);
      if (!f) return { delta: 0, notes: [] };
      return { delta: f.severity === 'High' ? 18 : 8, notes: [] };
    },
  };
}

function analyzeJwt(token) {
  const parts = String(token).split('.');
  if (parts.length < 2) throw new Error('not a JWT');
  const header = JSON.parse(b64url(parts[0]));
  const payload = JSON.parse(b64url(parts[1]));
  const issues = [];
  if (String(header.alg || '').toLowerCase() === 'none') issues.push('alg=none');
  if (payload.exp == null) issues.push('missing exp');
  if (payload.exp && payload.exp > 20000000000) issues.push('extremely long-lived exp');
  // Unreasonable lifetime > 1 year from now
  if (payload.exp && payload.exp - Date.now() / 1000 > 365 * 24 * 3600) {
    issues.push('exp > 1 year');
  }
  return {
    tokenPresent: true,
    alg: header.alg,
    exp: payload.exp,
    issues: [...new Set(issues)],
  };
}

function b64url(s) {
  const pad = s + '='.repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(pad.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

module.exports = { createPlugin };
