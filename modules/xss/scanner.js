const path = require('path');
const fs = require('fs');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));
const { sortByParamPriority } = require(path.join(
  process.cwd(),
  'src/platform/plugins/paramRank.js',
));
const { compareToBaseline } = require(path.join(
  process.cwd(),
  'src/platform/plugins/baselineCompare.js',
));

const payloadsDoc = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'payloads.json'), 'utf8'),
);

function createPlugin(manifest) {
  return {
    manifest,
    lane: 'http',

    async discover(ctx) {
      const targets = [];
      const seen = new Set();
      const push = (endpoint, parameter, location = 'query') => {
        const key = `${location}|${endpoint}|${parameter}`;
        if (!parameter || seen.has(key)) return;
        if (/password|csrf|token|_method|captcha|nonce/i.test(parameter)) return;
        seen.add(key);
        targets.push({ type: location, endpoint, parameter });
      };

      for (const p of ctx.attackSurface.parameters || []) {
        push(p.endpoint, p.name, p.location || 'query');
      }

      for (const form of (ctx.attackSurface.forms || []).slice(0, 25)) {
        const action = form.action || ctx.request.targetUrl;
        for (const field of form.fields || []) {
          if (!field.name) continue;
          push(action, field.name, (form.method || 'GET').toUpperCase() === 'GET' ? 'query' : 'form');
        }
      }

      for (const ep of (ctx.focusEndpoints || []).slice(0, 15)) {
        try {
          const u = new URL(ep.includes('://') ? ep : new URL(ep, ctx.request.targetUrl).href);
          push(`${u.origin}${u.pathname}`, 'q', 'query');
          push(`${u.origin}${u.pathname}`, 'search', 'query');
          for (const [name] of u.searchParams) push(`${u.origin}${u.pathname}`, name, 'query');
        } catch {
          /* ignore */
        }
      }

      try {
        const origin = new URL(ctx.request.targetUrl).origin;
        push(`${origin}/`, 'q', 'query');
        push(`${origin}/`, 'search', 'query');
        push(ctx.request.targetUrl.split('?')[0], 'q', 'query');
      } catch {
        /* ignore */
      }

      return { targets: sortByParamPriority(targets).slice(0, 20) };
    },

    async scan(ctx, discovery) {
      const request = ctx.page.context().request;
      const marker = `xss${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
      const templates = payloadsDoc.reflected || [];
      const candidates = [];
      const ordered = sortByParamPriority(discovery.targets || []).slice(0, 15);

      for (const t of ordered) {
        for (const tmpl of templates.slice(0, 1)) {
          const payload = tmpl.replace(/__MARKER__/g, marker);
          try {
            const result = await probeReflect(request, t, payload, marker, ctx.config);
            candidates.push({
              ...result,
              endpoint: t.endpoint,
              parameter: t.parameter,
              location: t.type,
              marker,
              payload,
            });
            if (result.reflected) break;
          } catch {
            /* continue */
          }
        }
      }
      return candidates;
    },

    async verify(_ctx, candidates) {
      const findings = [];
      const hits = (candidates || []).filter((c) => c.reflected && c.baselineOk !== false);
      const sampled = hits.length ? hits.slice(0, 8) : (candidates || []).slice(0, 1);

      for (const c of sampled) {
        const issueFound = Boolean(c.reflected && c.baselineOk !== false);
        const multiSignal = Boolean(c.reflected && c.baselineSignificant);
        const severity = issueFound ? 'High' : 'Informational';
        findings.push({
          pluginId: manifest.id,
          title: issueFound
            ? `Reflected XSS indicator on parameter "${c.parameter}"`
            : 'No obvious reflected XSS on probed parameters',
          description: issueFound
            ? 'Attacker-controlled markup/marker was reflected without apparent encoding on a user-controlled parameter.'
            : 'Safe reflected-XSS markers were not returned unencoded on the probed parameters.',
          severity,
          confidence: issueFound ? (multiSignal ? 'Likely' : 'Possible') : 'Informational',
          cvss: cvssFor('xss', severity),
          mappings: mappingsFor('xss'),
          affectedUrl: c.fullUrl || c.endpoint,
          affectedEndpoint: c.endpoint,
          parameter: c.parameter,
          method: c.method || 'GET',
          evidence: [
            {
              technique: 'Reflected XSS Probe (alert-free)',
              status: c.status,
              parameter: c.parameter,
              payload: c.payload,
              marker: c.marker,
              bodySnippet: (c.bodySnippet || '').slice(0, 280),
              baselineDiff: c.baselineDiff || null,
              significant: Boolean(c.baselineSignificant),
            },
            ...(c.baselineDiff
              ? [
                  {
                    technique: 'baseline-compare',
                    signals: c.baselineDiff.signals || [],
                    significant: c.baselineSignificant,
                  },
                ]
              : []),
          ],
          http: c.http || [],
          impact: issueFound
            ? 'An attacker may execute script in the victim browser context if this reflection is exploitable.'
            : 'None',
          remediation:
            'Context-aware output encoding; prefer strict CSP; validate/encode all reflected input.',
          references: [
            'https://owasp.org/www-community/attacks/xss/',
            'https://cwe.mitre.org/data/definitions/79.html',
          ],
          status: issueFound ? 'Likely' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'XSS',
          techniques: multiSignal
            ? ['Reflected XSS Testing', 'Baseline differential']
            : ['Reflected XSS Testing'],
        });
      }
      return findings;
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      const f = findings.find((x) => x.issueFound);
      return { delta: f ? 20 : 0, notes: [] };
    },
  };
}

async function probeReflect(request, target, payload, marker, config) {
  const timeout = Number(config?.safety?.requestTimeoutMs || 10000);
  const base = target.endpoint;
  let fullUrl = base;
  let method = 'GET';

  // Clean baseline (benign value) for differential check
  let baselineBody = '';
  let baselineStatus = 0;
  try {
    if (target.type === 'form') {
      const body = new URLSearchParams({ [target.parameter]: 'secureassess_baseline' }).toString();
      const bRes = await request.fetch(base, {
        method: 'POST',
        failOnStatusCode: false,
        timeout,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        data: body,
      });
      baselineStatus = bRes.status();
      baselineBody = await bRes.text();
    } else {
      const u = new URL(base.includes('://') ? base : `https://${base}`);
      u.searchParams.set(target.parameter, 'secureassess_baseline');
      const bRes = await request.fetch(u.toString(), { failOnStatusCode: false, timeout });
      baselineStatus = bRes.status();
      baselineBody = await bRes.text();
    }
  } catch {
    /* continue without baseline */
  }

  let res;
  if (target.type === 'form') {
    method = 'POST';
    const body = new URLSearchParams({ [target.parameter]: payload }).toString();
    res = await request.fetch(base, {
      method: 'POST',
      failOnStatusCode: false,
      timeout,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      data: body,
    });
    fullUrl = base;
  } else {
    const u = new URL(base.includes('://') ? base : `https://${base}`);
    u.searchParams.set(target.parameter, payload);
    fullUrl = u.toString();
    res = await request.fetch(fullUrl, { failOnStatusCode: false, timeout });
  }

  const body = await res.text();
  const contentType = (res.headers()['content-type'] || '').toLowerCase();
  const looksHtml = /html|xml|svg|text\/plain/.test(contentType) || /<html|<body|<svg/i.test(body);
  const markerPresent = body.includes(marker);
  const markupPresent = /<svg|onload=|onerror=|<sa-xss|<img|<b>/i.test(body);
  const encodedAway =
    body.includes(`&lt;`) && !body.includes(`<svg`) && body.includes(marker)
      ? body.indexOf('&lt;') < body.indexOf(marker)
      : false;

  const reflected = Boolean(looksHtml && markerPresent && markupPresent && !encodedAway);
  // Baseline must NOT already contain the marker (false positive if page always has similar content)
  const baselineOk = !baselineBody.includes(marker);
  const baselineDiff = compareToBaseline(
    { status: baselineStatus, body: baselineBody },
    { status: res.status(), body },
  );
  const baselineSignificant = Boolean(reflected && baselineOk && (baselineDiff.bodyChanged || baselineDiff.significant));

  return {
    reflected,
    baselineOk,
    baselineSignificant,
    baselineDiff,
    status: res.status(),
    fullUrl,
    method,
    bodySnippet: body.slice(0, 400),
    http: [
      {
        request: { method: 'GET', url: 'baseline', headers: {} },
        response: { status: baselineStatus },
      },
      {
        request: { method, url: fullUrl, headers: {} },
        response: { status: res.status(), headers: { 'content-type': contentType } },
      },
    ],
  };
}

module.exports = { createPlugin };
