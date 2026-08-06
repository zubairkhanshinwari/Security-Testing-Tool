const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));
const { gradeFromSignals, evidenceWithSignals } = require(path.join(
  process.cwd(),
  'src/platform/plugins/confirmationSignals.js',
));

/**
 * Safe, non-destructive IDOR / BOLA checks (GET-only).
 * Prefer dual-account (Account B) confirmation; otherwise use horizontal ID mutation + negative controls.
 */

const SENSITIVE_JSON_RE =
  /("(email|phone|password|role|ssn|address|dob|dateOfBirth|creditCard|accountNumber|secret|apiKey|privateKey|username|fullName|firstName|lastName|mobile|iban)"\s*:)/i;

const IDENTITY_RE =
  /"(email|userId|user_id|accountId|account_id|username|phone|mobile)"\s*:\s*"?([^",}\s]+)/gi;

const OBJECT_PATH_RE =
  /\/(users?|accounts?|profiles?|orders?|invoices?|documents?|files?|listings?|properties|items?|customers?|tickets?|messages?|bookings?|payments?|transactions?|carts?|members?|tenants?|orgs?|organizations?|projects?|reports?|records?|resources?)\/([^/?#]+)/i;

const ID_PARAMS =
  /^(id|user[_-]?id|account[_-]?id|order[_-]?id|doc[_-]?id|document[_-]?id|file[_-]?id|customer[_-]?id|invoice[_-]?id|ticket[_-]?id|project[_-]?id|org[_-]?id|member[_-]?id|uuid|object[_-]?id|resource[_-]?id|entity[_-]?id|record[_-]?id)$/i;

const MAX_TARGETS = 24;
const MAX_SCAN = 16;

function createPlugin(manifest) {
  return {
    manifest,
    lane: 'http',

    async discover(ctx) {
      const targets = [];
      const seen = new Set();
      const push = (url, objectId, source) => {
        const key = String(url).split('?')[0] + (String(url).includes('?') ? `?${String(url).split('?')[1]}` : '');
        const dedupe = key.replace(/\/$/, '');
        if (!url || seen.has(dedupe)) return;
        seen.add(dedupe);
        targets.push({ url: String(url).split('#')[0], objectId: String(objectId || ''), source });
      };

      const pushObjectAndNeighbors = (url, objectId, source) => {
        push(url, objectId, source);
        for (const nid of neighborIds(objectId).slice(0, 3)) {
          const nurl = replaceObjectId(url, objectId, nid);
          if (nurl && nurl !== url) push(nurl, nid, `${source}-neighbor`);
        }
      };

      for (const ep of ctx.attackSurface?.endpoints || []) {
        const method = (ep.method || 'GET').toUpperCase();
        if (method !== 'GET' && method !== 'HEAD') continue;
        const raw = String(ep.url || '');
        const m = raw.match(OBJECT_PATH_RE);
        if (m) {
          pushObjectAndNeighbors(raw.split('?')[0], m[2], 'endpoint');
        }
      }

      for (const p of ctx.attackSurface?.parameters || []) {
        if (!ID_PARAMS.test(p.name || '')) continue;
        const sample = p.sample || p.example || p.value || '1';
        const base = String(p.endpoint || '').split('?')[0];
        if (!base) continue;
        pushObjectAndNeighbors(`${base}?${p.name}=${encodeURIComponent(sample)}`, sample, 'query');
        for (const nid of ['1', '2']) {
          push(`${base}?${p.name}=${nid}`, nid, 'query-seed');
        }
      }

      for (const base of (ctx.attackSurface?.apiBases || []).slice(0, 4)) {
        try {
          const origin = base.includes('://') ? new URL(base).origin : `https://${base}`;
          const root = /\/api$/i.test(String(base).replace(/\/$/, ''))
            ? String(base).replace(/\/$/, '')
            : `${origin}/api`;
          for (const tpl of [
            '/users/1',
            '/users/2',
            '/accounts/1',
            '/orders/1',
            '/orders/2',
            '/profiles/1',
            '/customers/1',
            '/invoices/1',
          ]) {
            push(`${root}${tpl}`, tpl.split('/').pop(), 'seed');
          }
        } catch {
          /* ignore */
        }
      }

      for (const ep of (ctx.focusEndpoints || []).slice(0, 12)) {
        try {
          const u = ep.includes('://') ? ep : new URL(ep, ctx.request.targetUrl).href;
          const m = u.match(OBJECT_PATH_RE);
          if (m) pushObjectAndNeighbors(u.split('?')[0], m[2], 'focus');
          else {
            const parsed = new URL(u);
            for (const [k, v] of parsed.searchParams.entries()) {
              if (ID_PARAMS.test(k) && v) pushObjectAndNeighbors(u.split('#')[0], v, 'focus-query');
            }
          }
        } catch {
          /* ignore */
        }
      }

      // Prefer real discovered IDs over generic seeds
      targets.sort((a, b) => rankSource(a.source) - rankSource(b.source));
      return { targets: targets.slice(0, MAX_TARGETS) };
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

      const dualAccount = Boolean(altSession);
      candidates.push({
        mode: 'meta',
        dualAccount,
        hasAccountBCreds: Boolean(ctx.request?.username2 && ctx.request?.password2),
      });

      try {
        for (const t of (discovery.targets || []).slice(0, MAX_SCAN)) {
          try {
            const anon = await fetchProbe(primaryRequest, t.url, {}, timeout);
            candidates.push({ ...t, mode: 'anonymous', ...anon });

            if (Object.keys(authHeaders).length) {
              const authed = await fetchProbe(primaryRequest, t.url, authHeaders, timeout);
              candidates.push({ ...t, mode: 'authenticated', ...authed });
            }

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
      const reported = new Set();
      const meta = (candidates || []).find((c) => c.mode === 'meta');
      const byUrl = groupByUrl((candidates || []).filter((c) => c.mode !== 'meta'));
      const urls = Object.keys(byUrl).slice(0, 10);
      // Compute horizontal pairs once across the whole candidate set
      const globalHorizontal = findHorizontalPair([], byUrl);

      for (const url of urls) {
        const group = byUrl[url];
        const anon = group.find((c) => c.mode === 'anonymous' && isSensitiveExposure(c));
        const cross = group.find((c) => c.mode === 'cross-user' && isSensitiveExposure(c));
        const neg = group.find((c) => c.mode === 'negative-control');
        const horizontal =
          globalHorizontal &&
          (globalHorizontal.primary.url.startsWith(url) ||
            globalHorizontal.neighbor.url.startsWith(url) ||
            globalHorizontal.primary.url.split('?')[0] === url ||
            globalHorizontal.neighbor.url.split('?')[0] === url)
            ? globalHorizontal
            : null;

        const hit = cross || anon || (horizontal ? horizontal.primary : null);
        if (!hit) continue;

        const reportKey = `${shortPath(hit.url)}|${hit.mode}|${horizontal ? 'h' : ''}|${cross ? 'c' : ''}|${anon ? 'a' : ''}`;
        if (reported.has(reportKey)) continue;
        reported.add(reportKey);

        const signals = [];
        const jsonTyped = /json/i.test(hit.contentType || '');
        if (jsonTyped) signals.push('json-typed', 'evidence');
        if (anon) signals.push('evidence', 'unauthenticated');
        if (cross) signals.push('cross-user', 'evidence');
        if (horizontal) signals.push('horizontal-idor', 'evidence');
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
          confidence === 'Confirmed' || cross || anon
            ? 'High'
            : horizontal
              ? 'High'
              : 'Medium';

        const titleMode = cross
          ? 'cross-user Account B'
          : anon
            ? 'anonymous'
            : horizontal
              ? 'horizontal ID mutation'
              : 'authenticated Account A';

        findings.push({
          pluginId: manifest.id,
          title: `IDOR / BOLA on ${shortPath(hit.url)} (${titleMode})`,
          description: buildIdorDescription(hit, {
            cross: Boolean(cross),
            anon: Boolean(anon),
            horizontal: Boolean(horizontal),
            negOk: signals.includes('negative-control'),
            dualAccount: Boolean(meta?.dualAccount),
          }),
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
                : horizontal
                  ? 'IDOR horizontal proof (multiple object IDs return sensitive JSON)'
                  : 'IDOR/BOLA GET probe (anonymous / unauthorized)',
              signals,
              {
                mode: hit.mode,
                accountRole: cross
                  ? 'Account B against Account A object'
                  : anon
                    ? 'anonymous'
                    : 'Account A',
                status: hit.status,
                contentType: hit.contentType,
                bodySnippet: (hit.bodySnippet || '').slice(0, 280),
                crossUser: Boolean(cross),
                horizontal: Boolean(horizontal),
                neighborUrl: horizontal?.neighbor?.url,
                negativeControl: signals.includes('negative-control'),
                confirmationSignals: signals,
                dualAccountUsed: Boolean(meta?.dualAccount),
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
            ...(horizontal?.neighbor
              ? [
                  evidenceWithSignals('horizontal-neighbor', ['horizontal-idor'], {
                    url: horizontal.neighbor.url,
                    objectId: horizontal.neighbor.objectId,
                    status: horizontal.neighbor.status,
                    identityA: horizontal.identityA,
                    identityB: horizontal.identityB,
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
          http: [...(hit.http || []), ...(cross?.http || []), ...(horizontal?.neighbor?.http || []), ...(neg?.http || [])].slice(
            0,
            6,
          ),
          impact: cross
            ? 'Account B can read Account A’s object data by identifier — broken object-level authorization (BOLA).'
            : horizontal
              ? 'Changing object identifiers returns other records’ sensitive fields — classic IDOR.'
              : 'Attackers may read other users’ or objects’ data by changing identifiers (including unauthenticated access).',
          remediation:
            'Enforce object-level authorization on every request; never trust client-supplied IDs alone; return 403/404 when unauthorized. Retest with dual accounts (Account A + Account B).',
          references: [
            'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
            'https://cwe.mitre.org/data/definitions/639.html',
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References',
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
            ...(horizontal ? ['Horizontal ID mutation'] : []),
            ...(signals.includes('negative-control') ? ['Negative control'] : []),
            ...(anon ? ['Unauthenticated object access'] : []),
          ],
        });
      }

      if (!findings.length) {
        const pass = passFinding(manifest, (candidates || []).find((c) => c.mode !== 'meta'));
        if (meta && !meta.dualAccount && meta.hasAccountBCreds === false) {
          pass.evidence = [
            ...(pass.evidence || []),
            {
              technique: 'dual-account-hint',
              note: 'Account B credentials were not provided — cross-user BOLA confirmation was skipped. Add Account B for stronger IDOR proof.',
            },
          ];
        }
        findings.push(pass);
      }
      return findings.slice(0, 8);
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

function rankSource(source) {
  const s = String(source || '');
  if (s.startsWith('focus')) return 0;
  if (s.startsWith('endpoint')) return 1;
  if (s.startsWith('query')) return 2;
  if (s.includes('neighbor')) return 3;
  return 4;
}

function neighborIds(objectId) {
  const id = String(objectId || '').trim();
  if (!id) return ['1', '2'];
  if (/^\d+$/.test(id)) {
    const n = Number(id);
    const out = [];
    for (const d of [1, -1, 2, 10, 100]) {
      const v = n + d;
      if (v > 0) out.push(String(v));
    }
    return [...new Set(out)];
  }
  // UUID / opaque: only try well-known numeric neighbors on alternate probes, not fake UUIDs
  return [];
}

function replaceObjectId(url, fromId, toId) {
  try {
    if (OBJECT_PATH_RE.test(url) && fromId) {
      return url.replace(OBJECT_PATH_RE, (_m, coll, id) =>
        id === String(fromId) ? `/${coll}/${toId}` : `/${coll}/${id}`,
      );
    }
    const hasScheme = /^https?:\/\//i.test(url);
    const u = new URL(hasScheme ? url : `https://placeholder.local${url.startsWith('/') ? url : `/${url}`}`);
    for (const key of [...u.searchParams.keys()]) {
      if (ID_PARAMS.test(key) && u.searchParams.get(key) === String(fromId)) {
        u.searchParams.set(key, String(toId));
        return hasScheme ? u.toString() : `${u.pathname}${u.search}`;
      }
    }
    if (OBJECT_PATH_RE.test(u.pathname)) {
      u.pathname = u.pathname.replace(OBJECT_PATH_RE, (_m, coll) => `/${coll}/${toId}`);
      return hasScheme ? u.toString() : `${u.pathname}${u.search}`;
    }
  } catch {
    /* ignore */
  }
  return null;
}

function extractIdentities(bodySnippet) {
  const out = new Set();
  const text = String(bodySnippet || '');
  let m;
  const re = new RegExp(IDENTITY_RE.source, IDENTITY_RE.flags);
  while ((m = re.exec(text))) {
    out.add(`${m[1].toLowerCase()}:${String(m[2]).toLowerCase()}`);
  }
  return [...out];
}

function findHorizontalPair(authedHits, byUrl) {
  // Compare sensitive authenticated responses across different object URLs
  const pool = [];
  for (const url of Object.keys(byUrl || {})) {
    for (const c of byUrl[url]) {
      if (c.mode === 'authenticated' && isSensitiveExposure(c)) pool.push(c);
    }
  }
  // Also include authedHits from current group
  for (const c of authedHits || []) {
    if (!pool.includes(c)) pool.push(c);
  }

  for (let i = 0; i < pool.length; i++) {
    for (let j = i + 1; j < pool.length; j++) {
      const a = pool[i];
      const b = pool[j];
      if (!a.objectId || !b.objectId || a.objectId === b.objectId) continue;
      if (a.url.split('?')[0] === b.url.split('?')[0] && a.url === b.url) continue;
      const idA = extractIdentities(a.bodySnippet);
      const idB = extractIdentities(b.bodySnippet);
      if (!idA.length || !idB.length) continue;
      const overlap = idA.filter((x) => idB.includes(x));
      // Different identity fields → likely different users/objects accessible
      if (overlap.length < Math.min(idA.length, idB.length)) {
        return {
          primary: a,
          neighbor: b,
          identityA: idA.slice(0, 4),
          identityB: idB.slice(0, 4),
        };
      }
    }
  }
  return null;
}

function passFinding(manifest, sample) {
  return {
    pluginId: manifest.id,
    title: 'No obvious IDOR / broken object access on probed endpoints',
    description:
      'Safe GET probes against object-style endpoints did not show clear unauthorized sensitive JSON (anonymous, cross-user, or horizontal ID mutation).',
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
      'Enforce object-level authorization on every request; avoid trusting client-supplied IDs; return 403/404 when unauthorized. Provide Account B credentials for dual-account BOLA confirmation.',
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

function buildIdorDescription(hit, { cross, anon, horizontal, negOk, dualAccount }) {
  const parts = [];
  if (cross) {
    parts.push(
      'Dual-account proof: an object URL discovered under Account A returned sensitive fields when requested with Account B’s session (cross-user / BOLA).',
    );
  } else if (anon) {
    parts.push(
      'An unauthenticated GET to an object endpoint returned user/object-like JSON fields without an authorization failure.',
    );
  } else if (horizontal) {
    parts.push(
      'Horizontal IDOR signal: multiple different object identifiers returned sensitive JSON with differing identity fields under the same session.',
    );
  } else {
    parts.push(
      'An authenticated GET to an object endpoint returned user/object-like JSON fields without an apparent authorization failure.',
    );
  }
  if (negOk) parts.push('A negative-control object ID did not return the same sensitive exposure.');
  if (!dualAccount && !cross) {
    parts.push('Account B was not used — add a second test account to confirm cross-user BOLA.');
  }
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
    for (const key of [...u.searchParams.keys()]) {
      if (ID_PARAMS.test(key)) {
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

module.exports = {
  createPlugin,
  OBJECT_PATH_RE,
  ID_PARAMS,
  neighborIds,
  replaceObjectId,
  negativeControlUrl,
  isSensitiveExposure,
  extractIdentities,
};
