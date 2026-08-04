const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

const REDIRECT_PARAMS = [
  'redirect',
  'url',
  'next',
  'returnUrl',
  'return_to',
  'continue',
  'dest',
  'destination',
  'return',
  'goto',
  'callback',
];

const EVIL = 'https://evil-example-assessment.invalid/path';

function createPlugin(manifest) {
  return {
    manifest,
    lane: 'http',

    async discover(ctx) {
      const targets = [];
      const origin = new URL(ctx.request.targetUrl).origin;
      const bases = new Set([
        `${origin}/`,
        ctx.request.targetUrl.split('?')[0],
        ...(ctx.attackSurface.pages || []).slice(0, 10),
      ]);

      for (const p of ctx.attackSurface.parameters || []) {
        if (REDIRECT_PARAMS.some((n) => n.toLowerCase() === String(p.name).toLowerCase())) {
          targets.push({ endpoint: p.endpoint, parameter: p.name });
        }
      }

      for (const base of bases) {
        for (const param of REDIRECT_PARAMS.slice(0, 6)) {
          targets.push({ endpoint: base.split('?')[0], parameter: param });
        }
      }

      const seen = new Set();
      return {
        targets: targets
          .filter((t) => {
            const k = `${t.endpoint}|${t.parameter}`;
            if (seen.has(k)) return false;
            seen.add(k);
            return true;
          })
          .slice(0, 16),
      };
    },

    async scan(ctx, discovery) {
      const request = ctx.page.context().request;
      const timeout = Number(ctx.config?.safety?.requestTimeoutMs || 8000);
      const candidates = [];

      for (const t of (discovery.targets || []).slice(0, 12)) {
        try {
          const base = new URL(t.endpoint, ctx.request.targetUrl);
          base.search = '';
          base.searchParams.set(t.parameter, EVIL);
          const res = await request.fetch(base.toString(), {
            failOnStatusCode: false,
            maxRedirects: 0,
            timeout,
          });
          const loc = res.headers()['location'] || res.headers()['Location'] || '';
          candidates.push({
            endpoint: base.toString(),
            parameter: t.parameter,
            status: res.status(),
            location: loc,
            open: /evil-example-assessment\.invalid/i.test(loc),
          });
        } catch {
          /* continue */
        }
      }
      return candidates;
    },

    async verify(_ctx, candidates) {
      const hits = (candidates || []).filter((c) => c.open);
      const sample = hits.length ? hits.slice(0, 5) : (candidates || []).slice(0, 1);

      return sample.map((c) => {
        const issueFound = Boolean(c.open);
        const severity = issueFound ? 'Medium' : 'Informational';
        return {
          pluginId: manifest.id,
          title: issueFound
            ? `Open redirect via parameter "${c.parameter}"`
            : 'No open redirect observed on probed parameters',
          description: issueFound
            ? `Server issued a Location redirect to an external assessment host via ${c.parameter}.`
            : 'Redirect-style parameters did not bounce to the external assessment host in this pass.',
          severity,
          confidence: issueFound ? 'Confirmed' : 'Informational',
          cvss: issueFound ? cvssFor('open-redirect', severity) : null,
          mappings: mappingsFor('open-redirect'),
          affectedUrl: c.endpoint,
          affectedEndpoint: c.endpoint,
          parameter: c.parameter,
          method: 'GET',
          evidence: [
            {
              technique: 'Open Redirect Probe',
              status: c.status,
              location: c.location,
              payloadHost: 'evil-example-assessment.invalid',
            },
          ],
          http: [],
          impact: issueFound
            ? 'Attackers may craft links that redirect users to malicious sites while appearing trusted.'
            : 'None',
          remediation: 'Allow-list redirect targets; prefer relative paths; never reflect arbitrary absolute URLs.',
          references: ['https://cwe.mitre.org/data/definitions/601.html'],
          status: issueFound ? 'Confirmed' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'Open Redirect',
          techniques: ['Open Redirect Testing'],
        };
      });
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      return { delta: findings.some((f) => f.issueFound) ? 8 : 0, notes: [] };
    },
  };
}

module.exports = { createPlugin };
