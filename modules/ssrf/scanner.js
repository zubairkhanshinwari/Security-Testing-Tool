const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

const URL_PARAM_RE =
  /^(url|uri|link|src|source|target|webhook|callback|feed|path|endpoint|host|proxy|image|avatar|fetch)$/i;

const SAFE_PROBE = 'https://ssrf-probe.invalid/secureassess';

function createPlugin(manifest) {
  return {
    manifest,
    lane: 'http',

    async discover(ctx) {
      const targets = [];
      const seen = new Set();
      const push = (endpoint, parameter) => {
        const key = `${endpoint}|${parameter}`;
        if (seen.has(key)) return;
        seen.add(key);
        targets.push({ endpoint, parameter });
      };

      for (const p of ctx.attackSurface.parameters || []) {
        if (URL_PARAM_RE.test(p.name)) push(p.endpoint, p.name);
      }

      for (const ep of ctx.attackSurface.endpoints || []) {
        const u = String(ep.url || '');
        if (/webhook|proxy|fetch|preview|import|og-image|avatar/i.test(u)) {
          push(u.split('?')[0], 'url');
        }
      }

      // Common sink seeds on API bases (GET only)
      for (const base of (ctx.attackSurface.apiBases || []).slice(0, 3)) {
        try {
          const origin = base.includes('://') ? new URL(base).origin : `https://${base}`;
          const root = /\/api$/i.test(base) ? base.replace(/\/$/, '') : `${origin}/api`;
          for (const pathSuffix of ['/preview', '/fetch', '/proxy', '/webhook/test']) {
            push(`${root}${pathSuffix}`, 'url');
          }
        } catch {
          /* ignore */
        }
      }

      return { targets: targets.slice(0, 12) };
    },

    async scan(ctx, discovery) {
      const request = ctx.page.context().request;
      const timeout = Number(ctx.config?.safety?.requestTimeoutMs || 8000);
      const candidates = [];

      for (const t of (discovery.targets || []).slice(0, 10)) {
        try {
          const base = new URL(t.endpoint, ctx.request.targetUrl);
          base.searchParams.set(t.parameter, SAFE_PROBE);
          const res = await request.fetch(base.toString(), {
            method: 'GET',
            failOnStatusCode: false,
            timeout,
          });
          const body = await res.text();
          const bodyLower = body.toLowerCase();
          // Signals that the server attempted to process/fetch the URL (heuristic only)
          const processed =
            bodyLower.includes('ssrf-probe.invalid') ||
            /enotfound|getaddrinfo|name resolution|could not resolve|connection refused|connect\s+timed\s+out/i.test(
              body,
            );
          candidates.push({
            endpoint: base.toString(),
            parameter: t.parameter,
            status: res.status(),
            processed,
            bodySnippet: body.slice(0, 300),
          });
        } catch {
          /* continue */
        }
      }

      if (!candidates.length) {
        candidates.push({
          endpoint: ctx.request.targetUrl,
          parameter: null,
          status: 0,
          processed: false,
          sinkCount: (discovery.targets || []).length,
          note: 'No URL-like sinks probed',
        });
      }
      return candidates;
    },

    async verify(ctx, candidates) {
      const hits = (candidates || []).filter((c) => c.processed);
      const sinks = (candidates || []).filter((c) => c.parameter);
      const issueFound = hits.length > 0;
      // Without an out-of-band collaborator we only raise Medium on strong process signals
      const severity = issueFound ? 'Medium' : 'Informational';

      return [
        {
          pluginId: manifest.id,
          title: issueFound
            ? `Possible SSRF sink processed external URL parameter`
            : sinks.length
              ? `SSRF sinks discovered (${sinks.length}) — no confirmed fetch signal`
              : 'SSRF deep testing: no clear URL sinks discovered',
          description: issueFound
            ? 'A URL-like parameter appears to have been processed server-side (error/reflection of the probe host). Manual confirmation recommended; metadata endpoints were not targeted.'
            : 'Safe SSRF pass only probes non-routable assessment hosts on URL-like parameters. Review webhooks, importers, and previewers manually for confirmed SSRF.',
          severity,
          confidence: issueFound ? 'Likely' : 'Informational',
          cvss: issueFound ? cvssFor('ssrf', severity) : null,
          mappings: mappingsFor('ssrf'),
          affectedUrl: (hits[0] || sinks[0] || {}).endpoint || ctx.request.targetUrl,
          affectedEndpoint: (hits[0] || sinks[0] || {}).endpoint || ctx.request.targetUrl,
          parameter: (hits[0] || sinks[0] || {}).parameter || undefined,
          method: 'GET',
          evidence: [
            {
              technique: 'Safe SSRF sink probe',
              probeHost: 'ssrf-probe.invalid',
              hits: hits.slice(0, 5),
              sinksProbed: sinks.length,
            },
          ],
          http: [],
          impact: issueFound
            ? 'Server-side request handling may allow access to internal services if not restricted.'
            : 'None confirmed',
          remediation:
            'Allow-list outbound destinations; block link-local/metadata IPs; do not pass user URLs to server-side fetchers without validation.',
          references: [
            'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
            'https://cwe.mitre.org/data/definitions/918.html',
          ],
          status: issueFound ? 'Confirmed' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'SSRF',
          techniques: ['SSRF Review'],
        },
      ];
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      return { delta: findings.some((f) => f.issueFound) ? 14 : 0, notes: [] };
    },
  };
}

module.exports = { createPlugin };
