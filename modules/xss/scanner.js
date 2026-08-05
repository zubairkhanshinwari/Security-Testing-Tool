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
const { gradeFromSignals, evidenceWithSignals } = require(path.join(
  process.cwd(),
  'src/platform/plugins/confirmationSignals.js',
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
        let best = null;
        for (const tmpl of templates.slice(0, 2)) {
          const payload = tmpl.replace(/__MARKER__/g, marker);
          try {
            const result = await probeReflect(request, t, payload, marker, ctx.config);
            const merged = {
              ...result,
              endpoint: t.endpoint,
              parameter: t.parameter,
              location: t.type,
              marker,
              payload,
            };
            if (!best || (merged.reflected && !best.reflected) || merged.signalScore > best.signalScore) {
              best = merged;
            }
            if (merged.reflected && merged.unencoded) break;
          } catch {
            /* continue */
          }
        }
        if (best) candidates.push(best);
      }
      return candidates;
    },

    async verify(_ctx, candidates) {
      const findings = [];
      const hits = (candidates || []).filter((c) => c.reflected && c.baselineOk !== false);
      const sampled = hits.length ? hits.slice(0, 8) : (candidates || []).slice(0, 1);

      for (const c of sampled) {
        const issueFound = Boolean(c.reflected && c.baselineOk !== false);
        const signals = c.confirmationSignals || [];
        const confidence = issueFound
          ? gradeFromSignals(signals, { issueFound: true })
          : 'Informational';
        const severity = issueFound
          ? confidence === 'Confirmed' || confidence === 'Likely'
            ? 'High'
            : 'Medium'
          : 'Informational';
        findings.push({
          pluginId: manifest.id,
          title: issueFound
            ? `Reflected XSS indicator on parameter "${c.parameter}"`
            : 'No obvious reflected XSS on probed parameters',
          description: issueFound
            ? c.unencoded
              ? 'Attacker-controlled marker reflected without HTML encoding, with baseline differential confirmation.'
              : 'Marker reflection observed; encoding/context evidence may be incomplete.'
            : 'Safe reflected-XSS markers were not returned unencoded on the probed parameters.',
          severity,
          confidence,
          cvss: cvssFor('xss', severity),
          mappings: mappingsFor('xss'),
          affectedUrl: c.fullUrl || c.endpoint,
          affectedEndpoint: c.endpoint,
          parameter: c.parameter,
          method: c.method || 'GET',
          evidence: [
            evidenceWithSignals('Reflected XSS Probe (alert-free)', signals, {
              status: c.status,
              parameter: c.parameter,
              payload: c.payload,
              marker: c.marker,
              unencoded: Boolean(c.unencoded),
              bodySnippet: (c.bodySnippet || '').slice(0, 280),
              baselineDiff: c.baselineDiff || null,
              confirmationSignals: signals,
            }),
            ...(c.baselineDiff
              ? [
                  evidenceWithSignals('baseline-compare', ['baseline-diff'], {
                    signals: c.baselineDiff.signals || ['baseline-diff'],
                    significant: c.baselineSignificant,
                  }),
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
          status: issueFound
            ? confidence === 'Confirmed'
              ? 'Confirmed'
              : confidence === 'Likely'
                ? 'Likely'
                : 'Possible'
            : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'XSS',
          techniques: [
            'Reflected XSS Testing',
            ...(c.baselineSignificant ? ['Baseline differential'] : []),
            ...(c.unencoded ? ['Unencoded reflection'] : []),
            ...(c.contextProbe ? ['Context second probe'] : []),
          ],
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

function analyzeReflection(body, marker, payload) {
  const markerPresent = body.includes(marker);
  if (!markerPresent) {
    return { reflected: false, unencoded: false, encodedAway: false };
  }
  const encodedMarker = body.includes(`&lt;`) && /&lt;(svg|img|sa-xss|b)/i.test(body);
  const rawMarkupNearMarker = (() => {
    const idx = body.indexOf(marker);
    const window = body.slice(Math.max(0, idx - 80), idx + marker.length + 80);
    return /<(svg|img|sa-xss|b)\b/i.test(window) || /on(load|error)\s*=/i.test(window);
  })();
  const payloadTagRaw =
    /<svg|<img|<sa-xss|<b>/i.test(payload) &&
    /<svg|<img|<sa-xss|<b>/i.test(body) &&
    !encodedMarker;
  const unencoded = Boolean(rawMarkupNearMarker || payloadTagRaw);
  const reflected = Boolean(markerPresent && (unencoded || /<svg|onload=|onerror=|<sa-xss|<img|<b>/i.test(body)));
  return {
    reflected,
    unencoded,
    encodedAway: encodedMarker && !unencoded,
  };
}

async function probeReflect(request, target, payload, marker, config) {
  const timeout = Number(config?.safety?.requestTimeoutMs || 10000);
  const base = target.endpoint;
  let fullUrl = base;
  let method = 'GET';
  const confirmationSignals = [];

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
  const analysis = analyzeReflection(body, marker, payload);
  const reflected = Boolean(looksHtml && analysis.reflected);
  const baselineOk = !baselineBody.includes(marker);
  const baselineDiff = compareToBaseline(
    { status: baselineStatus, body: baselineBody },
    { status: res.status(), body },
  );
  const baselineSignificant = Boolean(
    reflected && baselineOk && (baselineDiff.bodyChanged || baselineDiff.significant),
  );

  if (reflected) confirmationSignals.push('evidence');
  if (analysis.unencoded && reflected) confirmationSignals.push('reflection-unencoded');
  if (baselineSignificant) confirmationSignals.push('baseline-diff', 'body-diff');
  if (baselineDiff.signals?.length) confirmationSignals.push(...baselineDiff.signals);

  // Context second probe: different safe template, same marker
  let contextProbe = false;
  if (reflected && analysis.unencoded) {
    try {
      const altPayload = `"><b data-sa="${marker}">`;
      let altRes;
      if (target.type === 'form') {
        const altBody = new URLSearchParams({ [target.parameter]: altPayload }).toString();
        altRes = await request.fetch(base, {
          method: 'POST',
          failOnStatusCode: false,
          timeout,
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          data: altBody,
        });
      } else {
        const u = new URL(base.includes('://') ? base : `https://${base}`);
        u.searchParams.set(target.parameter, altPayload);
        altRes = await request.fetch(u.toString(), { failOnStatusCode: false, timeout });
      }
      const altText = await altRes.text();
      if (altText.includes(marker) && /<b\s+data-sa=/i.test(altText)) {
        contextProbe = true;
        confirmationSignals.push('context-probe', 'reproducible');
      }
    } catch {
      /* ignore */
    }
  }

  const signalScore =
    (reflected ? 1 : 0) +
    (analysis.unencoded ? 2 : 0) +
    (baselineSignificant ? 2 : 0) +
    (contextProbe ? 2 : 0);

  return {
    reflected,
    unencoded: analysis.unencoded,
    baselineOk,
    baselineSignificant,
    baselineDiff,
    contextProbe,
    confirmationSignals: [...new Set(confirmationSignals)],
    signalScore,
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
