const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

/** Safe math polyglots — expect reflected 49 / 7777, never RCE payloads. */
const PROBES = [
  { payload: '{{7*7}}', expect: '49', engine: 'jinja/twig/nunjucks' },
  { payload: '${7*7}', expect: '49', engine: 'freemarker/expression' },
  { payload: '<%= 7*7 %>', expect: '49', engine: 'erb/ejs' },
  { payload: '#{7*7}', expect: '49', engine: 'ruby' },
  { payload: '*{7*7}', expect: '49', engine: 'thymeleaf' },
  { payload: '{{7*\'7\'}}', expect: '49', engine: 'jinja-str' },
];

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

      for (const p of (ctx.attackSurface.parameters || []).slice(0, 35)) {
        push(p.endpoint, p.name);
      }
      for (const form of (ctx.attackSurface.forms || []).slice(0, 15)) {
        if (!/GET/i.test(form.method || 'GET')) continue;
        for (const f of form.fields || []) {
          if (f.name && !/password|csrf|token/i.test(f.name)) {
            push(form.action || ctx.request.targetUrl, f.name);
          }
        }
      }
      try {
        const origin = new URL(ctx.request.targetUrl).origin;
        push(`${origin}/`, 'q');
        push(`${origin}/`, 'name');
        push(`${origin}/`, 'template');
        push(`${origin}/`, 'message');
      } catch {
        /* ignore */
      }
      return { targets: targets.slice(0, 12) };
    },

    async scan(ctx, discovery) {
      const request = ctx.page.context().request;
      const timeout = Number(ctx.config?.safety?.requestTimeoutMs || 8000);
      const candidates = [];

      for (const t of (discovery.targets || []).slice(0, 8)) {
        for (const probe of PROBES.slice(0, 2)) {
          try {
            const base = new URL(t.endpoint, ctx.request.targetUrl);
            base.searchParams.set(t.parameter, probe.payload);
            const res = await request.fetch(base.toString(), {
              failOnStatusCode: false,
              timeout,
            });
            const body = await res.text();
            // Evaluated math without echoing the raw template expression
            const hit = body.includes(probe.expect) && !body.includes(probe.payload);

            candidates.push({
              endpoint: base.toString(),
              parameter: t.parameter,
              payload: probe.payload,
              engine: probe.engine,
              expect: probe.expect,
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
        const issueFound = Boolean(c.hit);
        const severity = issueFound ? 'High' : 'Informational';
        return {
          pluginId: manifest.id,
          title: issueFound
            ? `Possible SSTI (${c.engine}) on parameter "${c.parameter}"`
            : 'No obvious SSTI on probed parameters',
          description: issueFound
            ? `Template math payload evaluated to ${c.expect} without reflecting the raw expression — possible server-side template injection.`
            : 'Safe SSTI math polyglots were not evaluated on the probed parameters.',
          severity,
          confidence: issueFound ? 'Likely' : 'Informational',
          cvss: issueFound ? cvssFor('ssti', severity) : null,
          mappings: mappingsFor('ssti'),
          affectedUrl: c.endpoint,
          affectedEndpoint: c.endpoint,
          parameter: c.parameter,
          method: 'GET',
          evidence: [
            {
              technique: 'SSTI math polyglot',
              payload: c.payload,
              expect: c.expect,
              engine: c.engine,
              status: c.status,
              bodySnippet: c.bodySnippet,
            },
          ],
          http: [],
          impact: issueFound
            ? 'Template injection can lead to remote code execution depending on the engine.'
            : 'None',
          remediation: 'Never concat user input into templates; use sandboxed logic-less templates and strict allow-lists.',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection',
            'https://cwe.mitre.org/data/definitions/1336.html',
          ],
          status: issueFound ? 'Confirmed' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'SSTI',
          techniques: ['Server-Side Template Injection'],
        };
      });
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      return { delta: findings.some((f) => f.issueFound) ? 22 : 0, notes: [] };
    },
  };
}

module.exports = { createPlugin };
