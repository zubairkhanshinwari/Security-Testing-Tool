const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

const FILE_PROBES = [
  {
    payload: '../../../etc/passwd',
    markers: [/root:.*:0:0:/, /daemon:.*:1:1:/],
    platform: 'unix',
  },
  {
    payload: '....//....//....//etc/passwd',
    markers: [/root:.*:0:0:/],
    platform: 'unix-bypass',
  },
  {
    payload: '..\\..\\..\\windows\\win.ini',
    markers: [/\[fonts\]/i, /for 16-bit app support/i],
    platform: 'windows',
  },
];

const FILE_PARAMS = /^(file|filepath|path|page|template|doc|document|folder|dir|include|view|content|load)$/i;

function createPlugin(manifest) {
  return {
    manifest,
    lane: 'http',

    async discover(ctx) {
      const targets = [];
      const seen = new Set();
      const push = (endpoint, parameter) => {
        const key = `${endpoint}|${parameter}`;
        if (!parameter || seen.has(key)) return;
        seen.add(key);
        targets.push({ endpoint, parameter });
      };

      for (const p of ctx.attackSurface.parameters || []) {
        if (FILE_PARAMS.test(p.name)) push(p.endpoint, p.name);
      }
      for (const ep of ctx.attackSurface.endpoints || []) {
        const u = String(ep.url || '');
        if (/download|file|export|static|asset|include|view/i.test(u)) {
          push(u.split('?')[0], 'file');
          push(u.split('?')[0], 'path');
        }
      }
      try {
        const origin = new URL(ctx.request.targetUrl).origin;
        push(`${origin}/`, 'file');
        push(`${origin}/`, 'page');
        push(`${origin}/`, 'path');
      } catch {
        /* ignore */
      }
      return { targets: targets.slice(0, 10) };
    },

    async scan(ctx, discovery) {
      const request = ctx.page.context().request;
      const timeout = Number(ctx.config?.safety?.requestTimeoutMs || 8000);
      const candidates = [];

      for (const t of (discovery.targets || []).slice(0, 8)) {
        for (const probe of FILE_PROBES) {
          try {
            const base = new URL(t.endpoint, ctx.request.targetUrl);
            base.searchParams.set(t.parameter, probe.payload);
            const res = await request.fetch(base.toString(), {
              failOnStatusCode: false,
              timeout,
            });
            const body = await res.text();
            const hit = probe.markers.some((re) => re.test(body));
            candidates.push({
              endpoint: base.toString(),
              parameter: t.parameter,
              payload: probe.payload,
              platform: probe.platform,
              status: res.status(),
              hit,
              bodySnippet: body.slice(0, 280),
            });
            if (hit) break;
          } catch {
            /* continue */
          }
        }
      }
      return candidates;
    },

    async verify(_ctx, candidates) {
      const hits = (candidates || []).filter((c) => c.hit);
      const sample = hits.length ? hits.slice(0, 5) : (candidates || []).slice(0, 1);
      return sample.map((c) => {
        const issueFound = Boolean(c && c.hit);
        const severity = issueFound ? 'High' : 'Informational';
        return {
          pluginId: manifest.id,
          title: issueFound
            ? `Possible LFI / path traversal on "${c.parameter}"`
            : 'No obvious LFI / path traversal on probed parameters',
          description: issueFound
            ? `Response contained signatures of a sensitive OS file after a path-traversal payload (${c.platform}).`
            : 'Safe path-traversal probes did not return known OS file signatures.',
          severity,
          confidence: issueFound ? 'Likely' : 'Informational',
          cvss: issueFound ? cvssFor('lfi', severity) : null,
          mappings: mappingsFor('lfi'),
          affectedUrl: c?.endpoint,
          affectedEndpoint: c?.endpoint,
          parameter: c?.parameter,
          method: 'GET',
          evidence: [
            {
              technique: 'LFI / path traversal probe',
              payload: c?.payload,
              platform: c?.platform,
              status: c?.status,
              bodySnippet: c?.bodySnippet,
            },
          ],
          http: [],
          impact: issueFound
            ? 'Attackers may read sensitive files from the application host.'
            : 'None',
          remediation:
            'Normalize and allow-list file paths; never join user input into filesystem paths; use object IDs instead of filenames.',
          references: [
            'https://owasp.org/www-community/attacks/Path_Traversal',
            'https://cwe.mitre.org/data/definitions/22.html',
          ],
          status: issueFound ? 'Confirmed' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'LFI / Path Traversal',
          techniques: ['Path Traversal', 'Local File Inclusion'],
        };
      });
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      return { delta: findings.some((f) => f.issueFound) ? 20 : 0, notes: [] };
    },
  };
}

module.exports = { createPlugin };
