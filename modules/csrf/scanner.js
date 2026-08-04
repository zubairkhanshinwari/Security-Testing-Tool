const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

function createPlugin(manifest) {
  return {
    manifest,

    async discover(ctx) {
      const forms = (ctx.attackSurface.forms || []).filter((f) =>
        /POST|PUT|PATCH|DELETE/i.test(f.method || 'GET'),
      );
      return {
        targets: [
          { type: 'cookies' },
          ...forms.slice(0, 20).map((f) => ({
            type: 'form',
            action: f.action,
            method: f.method,
            fields: (f.fields || []).map((x) => x.name),
          })),
        ],
      };
    },

    async scan(ctx) {
      const cookies = await ctx.page.context().cookies(ctx.request.targetUrl);
      const weakCookies = cookies
        .filter((c) => !c.sameSite || c.sameSite === 'None')
        .map((c) => ({ name: c.name, sameSite: c.sameSite || 'missing', secure: c.secure }));

      const forms = (ctx.attackSurface.forms || []).filter((f) =>
        /POST|PUT|PATCH|DELETE/i.test(f.method || ''),
      );
      const formsMissingToken = forms
        .filter((f) => {
          const names = (f.fields || []).map((x) => String(x.name || '').toLowerCase());
          return !names.some((n) => /csrf|xsrf|_token|authenticity/i.test(n));
        })
        .map((f) => ({ action: f.action, method: f.method, fields: (f.fields || []).map((x) => x.name) }));

      return [{ weakCookies, formsMissingToken, formCount: forms.length }];
    },

    async verify(ctx, candidates) {
      const c = candidates[0] || { weakCookies: [], formsMissingToken: [], formCount: 0 };
      const issues = [];
      if ((c.weakCookies || []).length) issues.push('weak SameSite cookies');
      if ((c.formsMissingToken || []).length) issues.push('state-changing forms without CSRF token field');

      const issueFound = issues.length > 0;
      const severity =
        (c.formsMissingToken || []).length && (c.weakCookies || []).length
          ? 'Medium'
          : issueFound
            ? 'Low'
            : 'Informational';

      return [
        {
          pluginId: manifest.id,
          title: issueFound
            ? `CSRF risk signals: ${issues.join('; ')}`
            : 'No strong CSRF signals observed',
          description: issueFound
            ? `Signals: ${issues.join('; ')}. Confirm whether state-changing requests rely solely on cookies.`
            : 'Cookie SameSite and form token heuristics did not show an obvious CSRF weakness in this pass.',
          severity,
          confidence: issueFound ? 'Likely' : 'Informational',
          cvss: issueFound ? cvssFor('csrf', severity) : null,
          mappings: mappingsFor('csrf'),
          affectedUrl: ctx.request.targetUrl,
          affectedEndpoint: ctx.request.targetUrl,
          parameter: 'cookies/forms',
          method: 'N/A',
          evidence: [
            {
              technique: 'CSRF heuristic review',
              weakCookies: (c.weakCookies || []).slice(0, 10),
              formsMissingToken: (c.formsMissingToken || []).slice(0, 8),
              stateChangingForms: c.formCount || 0,
            },
          ],
          http: [],
          impact: issueFound
            ? 'Users may be tricked into performing state-changing actions if CSRF defenses are incomplete.'
            : 'None',
          remediation:
            'Use SameSite=Lax/Strict on session cookies; require anti-CSRF tokens (or Fetch metadata checks) on state-changing requests.',
          references: ['https://owasp.org/www-community/attacks/csrf', 'https://cwe.mitre.org/data/definitions/352.html'],
          status: issueFound ? 'Confirmed' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'CSRF',
          techniques: ['CSRF Testing'],
        },
      ];
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      const f = findings.find((x) => x.issueFound);
      return { delta: f ? (f.severity === 'Medium' ? 10 : 4) : 0, notes: [] };
    },
  };
}

module.exports = { createPlugin };
