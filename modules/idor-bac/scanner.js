const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

const SENSITIVE_JSON_RE =
  /("(email|phone|password|role|ssn|address|dob|dateOfBirth|creditCard|accountNumber|secret|apiKey|privateKey)"\s*:)/i;

const OBJECT_PATH_RE =
  /\/(users?|accounts?|profiles?|orders?|invoices?|documents?|files?|listings?|properties|items?|customers?)\/([^/?#]+)/i;

function createPlugin(manifest) {
  return {
    manifest,
    lane: 'http',

    async discover(ctx) {
      const targets = [];
      const seen = new Set();
      const push = (url, objectId, source) => {
        const key = url.split('?')[0];
        if (seen.has(key)) return;
        seen.add(key);
        targets.push({ url: key, objectId, source });
      };

      for (const ep of ctx.attackSurface.endpoints || []) {
        const method = (ep.method || 'GET').toUpperCase();
        if (method !== 'GET' && method !== 'HEAD') continue;
        const m = String(ep.url || '').match(OBJECT_PATH_RE);
        if (m) {
          const base = String(ep.url).replace(OBJECT_PATH_RE, `/${m[1]}/{id}`);
          push(String(ep.url).split('?')[0], m[2], 'endpoint');
          // Neighbor IDs for BOLA-style probe (GET only)
          push(base.replace('{id}', '1'), '1', 'neighbor');
          push(base.replace('{id}', '2'), '2', 'neighbor');
        }
      }

      for (const p of ctx.attackSurface.parameters || []) {
        if (!/^(id|userId|accountId|orderId|docId|uuid)$/i.test(p.name)) continue;
        push(`${p.endpoint}?${p.name}=1`, '1', 'query');
        push(`${p.endpoint}?${p.name}=2`, '2', 'query');
      }

      for (const base of (ctx.attackSurface.apiBases || []).slice(0, 4)) {
        try {
          const origin = base.includes('://') ? new URL(base).origin : `https://${base}`;
          const root = /\/api$/i.test(base) ? base.replace(/\/$/, '') : `${origin}/api`;
          for (const tpl of ['/users/1', '/users/2', '/accounts/1', '/orders/1', '/profiles/1']) {
            push(`${root}${tpl}`, tpl.split('/').pop(), 'seed');
          }
        } catch {
          /* ignore */
        }
      }

      for (const ep of (ctx.focusEndpoints || []).slice(0, 10)) {
        try {
          const u = ep.includes('://') ? ep : new URL(ep, ctx.request.targetUrl).href;
          const m = u.match(OBJECT_PATH_RE);
          if (m) push(u.split('?')[0], m[2], 'focus');
        } catch {
          /* ignore */
        }
      }

      return { targets: targets.slice(0, 16) };
    },

    async scan(ctx, discovery) {
      const request = ctx.page.context().request;
      const timeout = Number(ctx.config?.safety?.requestTimeoutMs || 10000);
      const authHeaders = ctx.auth?.ok && ctx.auth?.headers ? ctx.auth.headers : {};
      const candidates = [];

      for (const t of (discovery.targets || []).slice(0, 12)) {
        try {
          // Unauthenticated probe
          const anon = await fetchProbe(request, t.url, {}, timeout);
          candidates.push({ ...t, mode: 'anonymous', ...anon });

          // Authenticated probe (if session present) — still GET-only
          if (Object.keys(authHeaders).length) {
            const authed = await fetchProbe(request, t.url, authHeaders, timeout);
            candidates.push({ ...t, mode: 'authenticated', ...authed });
          }
        } catch {
          /* continue */
        }
      }
      return candidates;
    },

    async verify(_ctx, candidates) {
      const findings = [];
      const hits = (candidates || []).filter(isSensitiveExposure);
      const report = hits.length ? hits.slice(0, 6) : (candidates || []).slice(0, 1);

      // Precision: prefer anonymous exposures; require JSON content-type (not HTML soft-404s)
      for (const c of report) {
        const issueFound = isSensitiveExposure(c);
        const jsonTyped = /json/i.test(c.contentType || '');
        const strong = issueFound && jsonTyped;
        const severity = strong
          ? c.mode === 'anonymous'
            ? 'High'
            : 'Medium'
          : issueFound
            ? 'Medium'
            : 'Informational';
        findings.push({
          pluginId: manifest.id,
          title: issueFound
            ? `Possible IDOR / BOLA on ${shortPath(c.url)} (${c.mode})`
            : 'No obvious IDOR / broken object access on probed endpoints',
          description: issueFound
            ? `A ${c.mode} GET to an object endpoint returned user/object-like JSON fields without apparent authorization failure.`
            : 'Safe GET probes against object-style endpoints did not return clear unauthorized sensitive JSON.',
          severity,
          confidence: strong ? 'Likely' : issueFound ? 'Possible' : 'Informational',
          cvss: cvssFor('idor', severity),
          mappings: {
            ...mappingsFor('idor'),
            cwe: issueFound ? ['CWE-639', 'CWE-284'] : mappingsFor('idor').cwe,
          },
          affectedUrl: c.url,
          affectedEndpoint: c.url,
          parameter: c.objectId || 'id',
          method: 'GET',
          evidence: [
            {
              technique: 'IDOR/BOLA GET probe',
              mode: c.mode,
              status: c.status,
              contentType: c.contentType,
              bodySnippet: (c.bodySnippet || '').slice(0, 280),
              significant: strong,
              baselineDiff: strong ? { signals: ['sensitive-json', c.mode] } : null,
            },
          ],
          http: c.http || [],
          impact: issueFound
            ? 'Attackers may read other users’ or objects’ data by changing identifiers.'
            : 'None',
          remediation:
            'Enforce object-level authorization on every request; avoid trusting client-supplied IDs; return 403/404 when unauthorized.',
          references: [
            'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
            'https://cwe.mitre.org/data/definitions/639.html',
          ],
          status: issueFound ? 'Likely' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'Broken Access Control / IDOR',
          techniques: strong
            ? ['Broken Access Control', 'IDOR Testing', 'JSON content-type check']
            : ['Broken Access Control', 'IDOR Testing'],
        });
      }
      return findings;
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      const f = findings.find((x) => x.issueFound);
      if (!f) return { delta: 0, notes: [] };
      return { delta: f.severity === 'High' ? 22 : 12, notes: [] };
    },
  };
}

function isSensitiveExposure(c) {
  if (!c || c.status !== 200) return false;
  if (/html/i.test(c.contentType || '') || /<!doctype html/i.test((c.bodySnippet || '').slice(0, 40))) {
    return false;
  }
  return SENSITIVE_JSON_RE.test(c.bodySnippet || '');
}

function shortPath(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return String(url).slice(0, 80);
  }
}

async function fetchProbe(request, url, headers, timeout) {
  const res = await request.fetch(url, {
    method: 'GET',
    failOnStatusCode: false,
    timeout,
    headers,
  });
  const body = await res.text();
  const contentType = res.headers()['content-type'] || '';
  return {
    status: res.status(),
    contentType,
    bodySnippet: body.slice(0, 500),
    http: [
      {
        request: { method: 'GET', url, headers: redactHeaders(headers) },
        response: { status: res.status(), headers: { 'content-type': contentType } },
      },
    ],
  };
}

function redactHeaders(headers) {
  const out = { ...headers };
  for (const k of Object.keys(out)) {
    if (/authorization|cookie|token/i.test(k)) out[k] = '[REDACTED]';
  }
  return out;
}

module.exports = { createPlugin };
