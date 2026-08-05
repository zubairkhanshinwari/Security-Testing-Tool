const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));
const { gradeFromSignals, evidenceWithSignals } = require(path.join(
  process.cwd(),
  'src/platform/plugins/confirmationSignals.js',
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
      const primaryRequest = ctx.page.context().request;
      const timeout = Number(ctx.config?.safety?.requestTimeoutMs || 10000);
      const authHeaders = ctx.auth?.ok && ctx.auth?.headers ? ctx.auth.headers : {};
      const candidates = [];

      let altSession = null;
      try {
        altSession = await establishAltSession(ctx);
      } catch {
        altSession = null;
      }

      try {
        for (const t of (discovery.targets || []).slice(0, 12)) {
          try {
            const anon = await fetchProbe(primaryRequest, t.url, {}, timeout);
            candidates.push({ ...t, mode: 'anonymous', ...anon });

            if (Object.keys(authHeaders).length) {
              const authed = await fetchProbe(primaryRequest, t.url, authHeaders, timeout);
              candidates.push({ ...t, mode: 'authenticated', ...authed });
            }

            // Negative control: nonexistent id should not return the same sensitive 200
            const negUrl = negativeControlUrl(t.url);
            if (negUrl) {
              const negHeaders = Object.keys(authHeaders).length ? authHeaders : {};
              const neg = await fetchProbe(primaryRequest, negUrl, negHeaders, timeout);
              candidates.push({
                ...t,
                mode: 'negative-control',
                negativeOf: t.url,
                ...neg,
              });
            }

            // Dual-account: user B session against same object URL
            if (altSession) {
              const cross = await fetchProbe(altSession.request, t.url, altSession.headers, timeout);
              candidates.push({
                ...t,
                mode: 'cross-user',
                ...cross,
                altUser: true,
              });
            }
          } catch {
            /* continue */
          }
        }
      } finally {
        if (altSession?.close) await altSession.close().catch(() => undefined);
      }
      return candidates;
    },

    async verify(_ctx, candidates) {
      const findings = [];
      const byUrl = groupByUrl(candidates || []);
      const urls = Object.keys(byUrl).slice(0, 8);

      for (const url of urls) {
        const group = byUrl[url];
        const anon = group.find((c) => c.mode === 'anonymous' && isSensitiveExposure(c));
        const authed = group.find((c) => c.mode === 'authenticated' && isSensitiveExposure(c));
        const cross = group.find((c) => c.mode === 'cross-user' && isSensitiveExposure(c));
        const neg = group.find((c) => c.mode === 'negative-control');
        const hit = cross || anon || authed;
        if (!hit) continue;

        const signals = [];
        const jsonTyped = /json/i.test(hit.contentType || '');
        if (jsonTyped) signals.push('json-typed', 'evidence');
        if (anon) signals.push('evidence');
        if (cross) signals.push('cross-user', 'evidence');
        if (
          neg &&
          hit.status === 200 &&
          (neg.status === 403 || neg.status === 404 || neg.status === 401 || !isSensitiveExposure(neg))
        ) {
          signals.push('negative-control');
        }
        if (hit.http?.length >= 1) signals.push('http');

        const confidence = gradeFromSignals(signals, { issueFound: true });
        const severity =
          confidence === 'Confirmed'
            ? 'High'
            : cross || (anon && jsonTyped)
              ? 'High'
              : 'Medium';

        const titleMode = cross
          ? 'cross-user Account B'
          : hit.mode === 'anonymous'
            ? 'anonymous'
            : 'authenticated Account A';

        findings.push({
          pluginId: manifest.id,
          title: `IDOR / BOLA on ${shortPath(hit.url)} (${titleMode})`,
          description: buildIdorDescription(hit, { cross: Boolean(cross), negOk: signals.includes('negative-control') }),
          severity,
          confidence,
          cvss: cvssFor('idor', severity),
          mappings: {
            ...mappingsFor('idor'),
            cwe: ['CWE-639', 'CWE-284'],
          },
          affectedUrl: hit.url,
          affectedEndpoint: hit.url,
          parameter: hit.objectId || 'id',
          method: 'GET',
          evidence: [
            evidenceWithSignals(
              cross
                ? 'IDOR/BOLA dual-account proof (Account A object → Account B session)'
                : 'IDOR/BOLA GET probe (Account A / anonymous)',
              signals,
              {
                mode: hit.mode,
                accountRole: cross ? 'Account B against Account A object' : hit.mode === 'anonymous' ? 'anonymous' : 'Account A',
                status: hit.status,
                contentType: hit.contentType,
                bodySnippet: (hit.bodySnippet || '').slice(0, 280),
                crossUser: Boolean(cross),
                negativeControl: signals.includes('negative-control'),
                confirmationSignals: signals,
              },
            ),
            ...(cross
              ? [
                  evidenceWithSignals('cross-user-access (Account B)', ['cross-user'], {
                    mode: 'cross-user',
                    accountRole: 'Account B',
                    status: cross.status,
                    bodySnippet: (cross.bodySnippet || '').slice(0, 160),
                    note: 'Account B session retrieved sensitive data for an object associated with Account A discovery.',
                  }),
                ]
              : []),
            ...(neg
              ? [
                  evidenceWithSignals('negative-control', ['negative-control'], {
                    url: neg.url,
                    status: neg.status,
                    sensitive: isSensitiveExposure(neg),
                  }),
                ]
              : []),
          ],
          http: [...(hit.http || []), ...(cross?.http || []), ...(neg?.http || [])].slice(0, 6),
          impact: cross
            ? 'Account B can read Account A’s object data by identifier — broken object-level authorization (BOLA).'
            : 'Attackers may read other users’ or objects’ data by changing identifiers.',
          remediation:
            'Enforce object-level authorization on every request; avoid trusting client-supplied IDs; return 403/404 when unauthorized. Retest with dual accounts (Account A + Account B) in CI.',
          references: [
            'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
            'https://cwe.mitre.org/data/definitions/639.html',
          ],
          status:
            confidence === 'Confirmed' ? 'Confirmed' : confidence === 'Likely' ? 'Likely' : 'Possible',
          issueFound: true,
          testMode: 'active-safe',
          module: 'Broken Access Control / IDOR',
          techniques: [
            'Broken Access Control',
            'IDOR Testing',
            ...(jsonTyped ? ['JSON content-type check'] : []),
            ...(cross ? ['Dual-account access (Account A → Account B)'] : []),
            ...(signals.includes('negative-control') ? ['Negative control'] : []),
          ],
        });
      }

      if (!findings.length) findings.push(passFinding(manifest, (candidates || [])[0]));
      return findings.slice(0, 6);
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

function passFinding(manifest, sample) {
  return {
    pluginId: manifest.id,
    title: 'No obvious IDOR / broken object access on probed endpoints',
    description:
      'Safe GET probes against object-style endpoints did not return clear unauthorized sensitive JSON.',
    severity: 'Informational',
    confidence: 'Informational',
    cvss: cvssFor('idor', 'Informational'),
    mappings: mappingsFor('idor'),
    affectedUrl: sample?.url || '',
    affectedEndpoint: sample?.url || '',
    parameter: 'id',
    method: 'GET',
    evidence: [{ technique: 'IDOR/BOLA GET probe', status: sample?.status || 0 }],
    http: sample?.http || [],
    impact: 'None',
    remediation:
      'Enforce object-level authorization on every request; avoid trusting client-supplied IDs; return 403/404 when unauthorized.',
    references: [
      'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
    ],
    status: 'Pass',
    issueFound: false,
    testMode: 'active-safe',
    module: 'Broken Access Control / IDOR',
    techniques: ['Broken Access Control', 'IDOR Testing'],
  };
}

function buildIdorDescription(hit, { cross, negOk }) {
  const parts = [];
  if (cross) {
    parts.push(
      'Dual-account proof: an object URL discovered under Account A returned sensitive fields when requested with Account B’s session (cross-user / BOLA).',
    );
  } else if (hit.mode === 'anonymous') {
    parts.push(
      'An unauthenticated GET to an object endpoint returned user/object-like JSON fields without an authorization failure.',
    );
  } else {
    parts.push(
      'An authenticated (Account A) GET to an object endpoint returned user/object-like JSON fields without an apparent authorization failure.',
    );
  }
  if (negOk) parts.push('A negative-control object ID did not return the same sensitive exposure.');
  return parts.join(' ');
}

function groupByUrl(candidates) {
  const map = {};
  for (const c of candidates) {
    const key = (c.negativeOf || c.url || '').split('?')[0];
    if (!key) continue;
    if (!map[key]) map[key] = [];
    map[key].push(c);
  }
  return map;
}

function negativeControlUrl(url) {
  try {
    if (OBJECT_PATH_RE.test(url)) {
      return url.replace(OBJECT_PATH_RE, (_m, coll) => `/${coll}/999999991`);
    }
    const hasScheme = /^https?:\/\//i.test(url);
    const u = new URL(
      hasScheme ? url : `https://placeholder.local${url.startsWith('/') ? url : `/${url}`}`,
    );
    for (const key of ['id', 'userId', 'accountId', 'orderId']) {
      if (u.searchParams.has(key)) {
        u.searchParams.set(key, '999999991');
        return hasScheme ? u.toString() : `${u.pathname}${u.search}`;
      }
    }
  } catch {
    /* ignore */
  }
  return null;
}

async function establishAltSession(ctx) {
  const u2 = ctx.request?.username2;
  const p2 = ctx.request?.password2;
  if (!u2 || !p2) return null;

  const browser = ctx.page?.context?.()?.browser?.();
  if (!browser) return null;

  const { loginWithCredentials } = require(path.join(process.cwd(), 'src/scanner/login.js'));
  const altCtx = await browser.newContext();
  const altPage = await altCtx.newPage();
  try {
    const origin = new URL(ctx.request.targetUrl).origin;
    const result = await loginWithCredentials(altPage, {
      username: u2,
      password: p2,
      apiBases: ctx.attackSurface?.apiBases || [],
      origin,
      loginUrl: ctx.request.targetUrl,
    });
    if (!result.ok) {
      await altCtx.close();
      return null;
    }
    const headers = {};
    const isCookie =
      result.sessionType === 'cookie' || String(result.token || '').startsWith('cookie:');
    if (!isCookie && result.token) {
      headers.authorization = /^Bearer\s+/i.test(result.token)
        ? result.token
        : `Bearer ${result.token}`;
    }
    // Cookie sessions: altCtx.request already carries Set-Cookie from login
    return {
      headers,
      request: altCtx.request,
      close: () => altCtx.close(),
      sessionType: result.sessionType,
    };
  } catch (e) {
    await altCtx.close().catch(() => undefined);
    throw e;
  }
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
