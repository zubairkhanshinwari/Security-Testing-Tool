const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

function createPlugin(manifest) {
  return {
    manifest,
    async discover(ctx) {
      return { targets: [{ endpoint: ctx.request.targetUrl }] };
    },
    async scan(ctx) {
      const request = ctx.page.context().request;
      const evil = 'https://evil-secureassess.example';
      const res = await request.fetch(ctx.request.targetUrl, {
        failOnStatusCode: false,
        timeout: 15000,
        headers: { Origin: evil },
      });
      const headers = res.headers();
      const acao = headers['access-control-allow-origin'] || headers['Access-Control-Allow-Origin'];
      const acac =
        headers['access-control-allow-credentials'] ||
        headers['Access-Control-Allow-Credentials'];
      return [{ endpoint: ctx.request.targetUrl, acao, acac, status: res.status() }];
    },
    async verify(_ctx, candidates) {
      const c = candidates[0] || {};
      const reflected = c.acao === 'https://evil-secureassess.example';
      const wildcard = c.acao === '*';
      const creds = String(c.acac || '').toLowerCase() === 'true';
      const issueFound = reflected || (wildcard && creds);
      const severity = reflected && creds ? 'High' : issueFound ? 'Medium' : 'Informational';
      return [
        {
          pluginId: manifest.id,
          title: issueFound ? 'CORS misconfiguration detected' : 'CORS configuration check',
          description: issueFound
            ? `ACAO=${c.acao}; Allow-Credentials=${c.acac}`
            : `No dangerous CORS reflection observed (ACAO=${c.acao || 'n/a'}).`,
          severity,
          confidence: issueFound ? 'Likely' : 'Informational',
          cvss: cvssFor('cors', severity),
          mappings: mappingsFor('cors'),
          affectedUrl: c.endpoint,
          affectedEndpoint: c.endpoint,
          method: 'GET',
          evidence: [c],
          http: [
            {
              request: {
                method: 'GET',
                url: c.endpoint,
                headers: { Origin: 'https://evil-secureassess.example' },
              },
              response: { status: c.status || 0, headers: { 'access-control-allow-origin': c.acao } },
            },
          ],
          impact: issueFound
            ? 'Malicious sites may read authenticated responses depending on browser enforcement.'
            : 'None',
          remediation: 'Avoid reflecting arbitrary Origin; never combine ACAO:* with credentials.',
          references: ['https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'],
          status: issueFound ? 'Confirmed' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'CORS',
          techniques: ['Origin reflection probe'],
        },
      ];
    },
    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },
    async score(findings) {
      const f = findings.find((x) => x.issueFound);
      return { delta: f ? (f.severity === 'High' ? 18 : 6) : 0, notes: [] };
    },
  };
}

module.exports = { createPlugin };
