const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

function createPlugin(manifest) {
  return {
    manifest,
    async discover(ctx) {
      return { targets: [{ type: 'homepage', endpoint: ctx.request.targetUrl }] };
    },
    async scan(ctx) {
      const request = ctx.page.context().request;
      const res = await request.fetch(ctx.request.targetUrl, {
        failOnStatusCode: false,
        timeout: 20000,
      });
      const headers = res.headers();
      const map = {};
      for (const [k, v] of Object.entries(headers)) map[k.toLowerCase()] = v;
      return [{ headers: map, status: res.status(), endpoint: ctx.request.targetUrl }];
    },
    async verify(_ctx, candidates) {
      const c = candidates[0] || { headers: {}, endpoint: '' };
      const needed = {
        'content-security-policy': 'CSP',
        'strict-transport-security': 'HSTS',
        'x-content-type-options': 'X-Content-Type-Options',
        'x-frame-options': 'X-Frame-Options',
        'referrer-policy': 'Referrer-Policy',
        'permissions-policy': 'Permissions-Policy',
      };
      const missing = Object.entries(needed)
        .filter(([k]) => !c.headers[k])
        .map(([, label]) => label);
      const issueFound = missing.length > 0;
      const severity = missing.length >= 3 ? 'Medium' : missing.length ? 'Low' : 'Informational';
      return [
        {
          pluginId: manifest.id,
          title: issueFound
            ? `Missing security headers (${missing.length})`
            : 'Security headers present',
          description: issueFound
            ? `Missing recommended headers: ${missing.join(', ')}.`
            : 'Common security headers were observed.',
          severity,
          confidence: 'Confirmed',
          cvss: cvssFor('headers', severity),
          mappings: mappingsFor('headers'),
          affectedUrl: c.endpoint,
          affectedEndpoint: c.endpoint,
          parameter: 'n/a',
          method: 'GET',
          evidence: [{ missing, sampleHeaders: Object.keys(c.headers).slice(0, 20) }],
          http: [
            {
              request: { method: 'GET', url: c.endpoint },
              response: { status: c.status || 0, headers: c.headers },
            },
          ],
          impact: issueFound
            ? 'Missing headers increase risk of clickjacking, XSS impact, and downgrade attacks.'
            : 'None',
          remediation:
            'Configure CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and clickjacking protections.',
          references: [
            'https://owasp.org/www-project-secure-headers/',
            'https://cwe.mitre.org/data/definitions/693.html',
          ],
          status: issueFound ? 'Confirmed' : 'Pass',
          issueFound,
          testMode: 'passive',
          module: 'HTTP Header Security',
          techniques: ['Passive header review'],
        },
      ];
    },
    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },
    async score(findings) {
      const f = findings.find((x) => x.issueFound);
      if (!f) return { delta: 0, notes: [] };
      return { delta: f.severity === 'Medium' ? 6 : 4, notes: [] };
    },
  };
}

module.exports = { createPlugin };
