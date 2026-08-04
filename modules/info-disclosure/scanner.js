const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

const PATHS = ['.env', '.env.local', 'package.json', '.git/HEAD', 'server.map', 'main.js.map'];

function createPlugin(manifest) {
  return {
    manifest,
    async discover(ctx) {
      const origin = new URL(ctx.request.targetUrl).origin;
      return { targets: PATHS.map((p) => ({ endpoint: `${origin}/${p}` })) };
    },
    async scan(ctx, discovery) {
      const request = ctx.page.context().request;
      const out = [];
      for (const t of discovery.targets) {
        try {
          const res = await request.fetch(t.endpoint, { failOnStatusCode: false, timeout: 8000 });
          const text = await res.text();
          out.push({
            endpoint: t.endpoint,
            status: res.status(),
            body: text.slice(0, 200),
          });
        } catch (e) {
          out.push({ endpoint: t.endpoint, status: 0, body: String(e.message || e) });
        }
      }
      return out;
    },
    async verify(_ctx, candidates) {
      const findings = [];
      for (const c of candidates) {
        const looksEnv =
          c.status === 200 &&
          (/^[A-Z0-9_]+=.+/m.test(c.body) ||
            /DB_PASSWORD|API_KEY|SECRET|MONGO/i.test(c.body));
        const looksGit = c.status === 200 && /ref: refs\//.test(c.body);
        const looksMap = c.status === 200 && /"sources"|"version":\s*3/.test(c.body);
        const issueFound = looksEnv || looksGit || looksMap;
        if (!issueFound && c.status !== 200) {
          // skip quiet negatives to reduce noise; keep one aggregate pass later
          continue;
        }
        if (!issueFound) continue;
        const severity = looksEnv || looksGit ? 'High' : 'Low';
        findings.push({
          pluginId: manifest.id,
          title: `Sensitive file accessible: ${c.endpoint}`,
          description: `HTTP ${c.status} returned content that appears sensitive.`,
          severity,
          confidence: 'Likely',
          cvss: cvssFor('info-disclosure', severity),
          mappings: mappingsFor('info-disclosure'),
          affectedUrl: c.endpoint,
          affectedEndpoint: c.endpoint,
          method: 'GET',
          evidence: [{ status: c.status, snippet: c.body }],
          http: [
            {
              request: { method: 'GET', url: c.endpoint },
              response: { status: c.status, bodySnippet: c.body },
            },
          ],
          impact: 'Exposed secrets or source maps aid further attacks.',
          remediation: 'Block public access to env files, VCS metadata, and production source maps.',
          references: ['https://owasp.org/www-project-top-ten/'],
          status: 'Confirmed',
          issueFound: true,
          testMode: 'passive',
          module: 'Information Disclosure',
          techniques: ['Sensitive path probe'],
        });
      }
      if (!findings.length) {
        findings.push({
          pluginId: manifest.id,
          title: 'No common sensitive files exposed',
          description: 'Checked common sensitive paths; none returned clearly sensitive content.',
          severity: 'Informational',
          confidence: 'Informational',
          cvss: null,
          mappings: mappingsFor('info-disclosure'),
          affectedUrl: candidates[0]?.endpoint || '',
          affectedEndpoint: candidates[0]?.endpoint || '',
          method: 'GET',
          evidence: candidates.slice(0, 5),
          impact: 'None',
          remediation: 'Continue denying access to env/VCS/source-map artifacts.',
          references: [],
          status: 'Pass',
          issueFound: false,
          testMode: 'passive',
          module: 'Information Disclosure',
          techniques: ['Sensitive path probe'],
        });
      }
      return findings;
    },
    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },
    async score(findings) {
      let delta = 0;
      for (const f of findings.filter((x) => x.issueFound)) {
        delta += f.severity === 'High' ? 18 : 4;
      }
      return { delta, notes: [] };
    },
  };
}

module.exports = { createPlugin };
