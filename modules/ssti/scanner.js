const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

/** Safe math polyglots — expect reflected 49 / never RCE payloads. */
const PROBES = [
  { payload: '{{7*7}}', expect: '49', engine: 'jinja/twig/nunjucks' },
  { payload: '${7*7}', expect: '49', engine: 'freemarker/expression' },
  { payload: '<%= 7*7 %>', expect: '49', engine: 'erb/ejs' },
  { payload: '#{7*7}', expect: '49', engine: 'ruby' },
  { payload: '*{7*7}', expect: '49', engine: 'thymeleaf' },
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
            const baselineUrl = new URL(t.endpoint, ctx.request.targetUrl);
            // Neutral value for baseline — avoids empty-param edge cases
            baselineUrl.searchParams.set(t.parameter, 'secureassess_baseline');
            const baseRes = await request.fetch(baselineUrl.toString(), {
              failOnStatusCode: false,
              timeout,
            });
            const baselineBody = await baseRes.text();

            const probeUrl = new URL(t.endpoint, ctx.request.targetUrl);
            probeUrl.searchParams.set(t.parameter, probe.payload);
            const res = await request.fetch(probeUrl.toString(), {
              failOnStatusCode: false,
              timeout,
            });
            const body = await res.text();

            // Require evaluation signal AND that baseline did not already contain "49"
            // (HubSpot/marketing pages often contain "49" → classic false positive).
            const evaluated =
              body.includes(probe.expect) &&
              !body.includes(probe.payload) &&
              !baselineBody.includes(probe.expect);
            const signals = [];
            if (evaluated) signals.push('baseline-diff', 'math-eval');
            if (body.includes(probe.expect) && baselineBody.includes(probe.expect)) {
              signals.push('expect-already-in-baseline');
            }

            candidates.push({
              endpoint: probeUrl.toString(),
              parameter: t.parameter,
              payload: probe.payload,
              engine: probe.engine,
              expect: probe.expect,
              status: res.status(),
              hit: evaluated,
              signals,
              bodySnippet: body.slice(0, 280),
              baselineHadExpect: baselineBody.includes(probe.expect),
            });
            if (evaluated) break;
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
        // Keep Possible/Medium until VerificationEngine has stronger multi-signal proof
        const severity = issueFound ? 'Medium' : 'Informational';
        return {
          pluginId: manifest.id,
          title: issueFound
            ? `Possible SSTI (${c.engine}) on parameter "${c.parameter}"`
            : 'No obvious SSTI on probed parameters',
          description: issueFound
            ? `Template math payload appears evaluated to ${c.expect} and the baseline response did not contain ${c.expect}. Still requires manual confirmation — not treated as Confirmed RCE.`
            : c.baselineHadExpect || (c.signals || []).includes('expect-already-in-baseline')
              ? 'SSTI math expect string was already present in the baseline page (common false positive); no differential evaluation proved.'
              : 'Safe SSTI math polyglots were not evaluated on the probed parameters.',
          severity,
          confidence: issueFound ? 'Possible' : 'Informational',
          cvss: issueFound ? cvssFor('ssti', severity) : null,
          mappings: mappingsFor('ssti'),
          affectedUrl: c.endpoint,
          affectedEndpoint: c.endpoint,
          parameter: c.parameter,
          method: 'GET',
          evidence: [
            {
              technique: 'SSTI math polyglot + baseline compare',
              payload: c.payload,
              expect: c.expect,
              engine: c.engine,
              status: c.status,
              bodySnippet: c.bodySnippet,
              confirmationSignals: c.signals || [],
              baselineHadExpect: c.baselineHadExpect,
            },
          ],
          http: [],
          impact: issueFound
            ? 'If confirmed, template injection can lead to remote code execution depending on the engine.'
            : 'None',
          remediation:
            'Never concatenate user input into server-side templates; use sandboxed logic-less templates and strict allow-lists. Manually verify any Possible SSTI before treating it as RCE.',
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing-for-Server-Side-Template-Injection',
            'https://cwe.mitre.org/data/definitions/1336.html',
          ],
          status: issueFound ? 'Possible' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'SSTI',
          techniques: ['Server-Side Template Injection', 'Baseline differential'],
          verification: issueFound
            ? { signalCount: (c.signals || []).length, signals: c.signals || [], retestRecommended: true }
            : undefined,
        };
      });
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      return { delta: findings.some((f) => f.issueFound) ? 12 : 0, notes: [] };
    },
  };
}

module.exports = { createPlugin };
