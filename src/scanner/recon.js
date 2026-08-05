const { URL } = require('url');

const THIRD_PARTY_HOST_RE =
  /(google|gstatic|googleapis|doubleclick|facebook|fbcdn|clarity\.ms|hotjar|segment|sentry|newrelic|cloudflareinsights|hs-scripts|hubspot|twilio|stripe|paypal|analytics)/i;

function isNavContextError(err) {
  const msg = String(err?.message || err || '');
  return /Execution context was destroyed|Target closed|frame was detached|most likely because of a navigation/i.test(
    msg,
  );
}

/** Wait until the page finishes navigating / SPA redirects before DOM work. */
async function waitForStablePage(page, { settleMs = 400 } = {}) {
  try {
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 });
  } catch {
    /* ignore */
  }
  try {
    await page.waitForLoadState('networkidle', { timeout: 5000 });
  } catch {
    /* many SPAs never reach networkidle */
  }
  if (settleMs > 0) await new Promise((r) => setTimeout(r, settleMs));
}

/**
 * page.evaluate that retries when login/SPA navigation destroys the context mid-call.
 */
async function safeEvaluate(page, fn, arg, { retries = 3, settleMs = 350 } = {}) {
  let lastErr;
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      await waitForStablePage(page, { settleMs: attempt === 0 ? settleMs : settleMs + 200 });
      return arg === undefined ? await page.evaluate(fn) : await page.evaluate(fn, arg);
    } catch (err) {
      lastErr = err;
      if (!isNavContextError(err) || attempt === retries - 1) throw err;
      try {
        await page.waitForLoadState('load', { timeout: 10000 });
      } catch {
        /* ignore */
      }
      await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
    }
  }
  throw lastErr;
}

function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

function relatedHost(candidate, targetUrl) {
  try {
    const target = new URL(targetUrl);
    const host = new URL(candidate).hostname.toLowerCase();
    const base = target.hostname.toLowerCase().replace(/^www\./, '');
    const root = base.split('.').slice(-2).join('.');
    return (
      host === base ||
      host.endsWith(`.${base}`) ||
      host.endsWith(`.${root}`) ||
      host.includes(root.split('.')[0])
    );
  } catch {
    return false;
  }
}

function isAppApiUrl(url, targetUrl) {
  try {
    const u = new URL(url);
    if (THIRD_PARTY_HOST_RE.test(u.hostname)) return false;
    if (!relatedHost(url, targetUrl) && !sameOrigin(url, targetUrl)) return false;
    // Prefer API-looking paths, but allow any related XHR that isn't static media
    if (/\.(svg|png|jpg|jpeg|gif|css|woff2?|ttf|ico)(\?|$)/i.test(u.pathname)) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Discover forms, links, query params, API traffic, JS-bundle routes, and tokens.
 * Phase A: optional extraSeedLinks (sitemap/SPA), deeper form collection while crawling.
 */
async function discoverSurfaces(
  page,
  targetUrl,
  {
    maxLinks = 8,
    extraSeedLinks = [],
    collectFormsOnCrawl = true,
    pageSettleMs = 400,
    homeSettleMs = 800,
    scriptScanLimit = 8,
    scriptByteLimit = 400_000,
  } = {},
) {
  const apiHits = [];
  const onResponse = async (response) => {
    try {
      const req = response.request();
      const url = response.url();
      const resourceType = req.resourceType();
      if (!['xhr', 'fetch'].includes(resourceType)) return;
      if (!isAppApiUrl(url, targetUrl)) return;
      const headers = req.headers();
      let postData = null;
      try {
        postData = req.postData();
      } catch {
        postData = null;
      }
      apiHits.push({
        url,
        method: req.method(),
        status: response.status(),
        contentType: response.headers()['content-type'] || '',
        postData: postData ? String(postData).slice(0, 2000) : null,
        authHeader: headers.authorization || headers.Authorization || null,
        source: 'network',
      });
    } catch {
      // ignore
    }
  };

  page.on('response', onResponse);

  await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 25000 });
  await waitForStablePage(page, { settleMs: homeSettleMs });

  const pageInfo = await safeEvaluate(page, (originLimit) => {
    const forms = Array.from(document.querySelectorAll('form')).map((form, idx) => {
      const fields = Array.from(form.querySelectorAll('input, textarea, select'))
        .map((el) => ({
          name: el.getAttribute('name') || el.getAttribute('id') || `field_${idx}_${el.tagName.toLowerCase()}`,
          type: (el.getAttribute('type') || el.tagName).toLowerCase(),
          value: el.value || '',
        }))
        .filter((f) => f.name && !['submit', 'button', 'image', 'file'].includes(f.type));
      return {
        action: form.action || location.href,
        method: (form.method || 'GET').toUpperCase(),
        fields,
      };
    });

    const links = Array.from(document.querySelectorAll('a[href]'))
      .map((a) => a.href)
      .filter((href) => href.startsWith('http'))
      .filter((href) => {
        try {
          return new URL(href).origin === originLimit;
        } catch {
          return false;
        }
      });

    // Prefer auth-ish links first
    links.sort((a, b) => {
      const score = (u) => (/login|signin|signup|register|forgot|search|listing|property/i.test(u) ? 0 : 1);
      return score(a) - score(b);
    });

    const tokenKeys = Object.keys(localStorage || {}).filter((k) =>
      /token|auth|jwt|access|session/i.test(k)
    );
    const tokens = {};
    for (const k of tokenKeys) {
      const v = localStorage.getItem(k);
      if (v && v.length > 20 && v.length < 5000) tokens[k] = v;
    }

    return {
      title: document.title,
      url: location.href,
      forms,
      links: [...new Set(links)].slice(0, 40),
      inputs: Array.from(document.querySelectorAll('input[name], textarea[name], select[name]')).map((el) => ({
        name: el.getAttribute('name'),
        type: (el.getAttribute('type') || el.tagName).toLowerCase(),
      })),
      localStorageKeys: Object.keys(localStorage || {}),
      tokens,
    };
  }, new URL(targetUrl).origin);

  // Extract API hosts + route fragments from JS bundles on the page (bounded + parallel)
  const bundleIntel = await safeEvaluate(
    page,
    async ({ targetOrigin, scriptLimit, byteLimit }) => {
      const scripts = Array.from(document.querySelectorAll('script[src]'))
        .map((s) => s.src)
        .filter((src) => src.startsWith(targetOrigin));

      const apiHosts = new Set();
      const routes = new Set();
      const authRoutes = new Set();

      const hostRe = /https?:\/\/[a-z0-9.-]*(?:api|devapi|stagingapi|backend)[a-z0-9.-]*/gi;
      const routeRe =
        /["'`](\/?(?:api\/)?(?:v\d+\/)?(?:auth|oauth|users?|accounts?|profiles?|listings?|documents?|notifications?|search|admin|offers?|properties|property|orders?|payments?|cart|checkout|upload|files?|graphql|webhooks?|settings|password|reset|forgot|login|signin|signup|register)[a-zA-Z0-9_\-\/${}.]*)["'`]/g;

      const ranked = scripts
        .map((src) => ({
          src,
          rank: /vendor|framework|polyfill|runtime|chunk-vendors/i.test(src) ? 2 : 0,
        }))
        .sort((a, b) => a.rank - b.rank)
        .map((x) => x.src)
        .slice(0, scriptLimit);

      await Promise.all(
        ranked.map(async (src) => {
          try {
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), 4000);
            const res = await fetch(src, { signal: ctrl.signal });
            clearTimeout(timer);
            const text = (await res.text()).slice(0, byteLimit);
            let m;
            hostRe.lastIndex = 0;
            routeRe.lastIndex = 0;
            while ((m = hostRe.exec(text))) apiHosts.add(m[0].replace(/\/$/, ''));
            while ((m = routeRe.exec(text))) {
              const r = m[1];
              if (r.length < 3 || r.length > 120) continue;
              if (/webpack|node_modules|component|module/i.test(r)) continue;
              routes.add(r.replace(/\$\{[^}]+\}/g, '{id}'));
              if (/auth\/|login|signin|signup|forgot/i.test(r)) authRoutes.add(r);
            }
            const abs = text.match(/https?:\/\/devapi\.[a-z0-9.-]+/gi) || [];
            abs.forEach((h) => apiHosts.add(h.replace(/\/$/, '')));
          } catch {
            // ignore fetch failures / aborts
          }
        }),
      );

      try {
        const html = document.documentElement.innerHTML.slice(0, 200000);
        const abs = html.match(/https?:\/\/[a-z0-9.-]*api[a-z0-9.-]*/gi) || [];
        abs.forEach((h) => apiHosts.add(h.replace(/\/$/, '')));
      } catch {
        // ignore
      }

      return {
        apiHosts: [...apiHosts].slice(0, 10),
        routes: [...routes].slice(0, 60),
        authRoutes: [...authRoutes].slice(0, 20),
        scriptCount: scripts.length,
      };
    },
    {
      targetOrigin: new URL(targetUrl).origin,
      scriptLimit: scriptScanLimit,
      byteLimit: scriptByteLimit,
    },
    { settleMs: 200 },
  );

  // If SPA redirected away during evaluate, keep current URL as the discovered page
  try {
    if (page.url() && page.url() !== pageInfo.url) {
      pageInfo.url = page.url();
    }
  } catch {
    /* ignore */
  }

  const visited = new Set([pageInfo.url]);
  const queryParams = new Map();
  const crawledForms = [...(pageInfo.forms || [])];
  const recordQuery = (u) => {
    try {
      const parsed = new URL(u);
      if (!sameOrigin(parsed.href, targetUrl)) return;
      const key = `${parsed.origin}${parsed.pathname}`;
      if (!queryParams.has(key)) queryParams.set(key, new Set());
      for (const [k] of parsed.searchParams) queryParams.get(key).add(k);
    } catch {
      // ignore
    }
  };
  recordQuery(pageInfo.url);

  const highValue = (u) =>
    /login|signin|signup|register|forgot|reset|search|admin|account|profile|upload|settings|dashboard|cart|checkout|order/i.test(
      u,
    )
      ? 0
      : 1;

  const seedLinks = [
    ...pageInfo.links,
    ...(Array.isArray(extraSeedLinks) ? extraSeedLinks : []),
  ]
    .filter((href) => {
      try {
        return sameOrigin(href, targetUrl);
      } catch {
        return false;
      }
    })
    .sort((a, b) => highValue(a) - highValue(b));

  const crawlQueue = [...new Set(seedLinks)];
  const queued = new Set(crawlQueue);
  const originLimit = new URL(targetUrl).origin;

  while (crawlQueue.length && visited.size <= maxLinks + 1) {
    const link = crawlQueue.shift();
    if (!link || visited.has(link)) continue;
    visited.add(link);
    try {
      await page.goto(link, { waitUntil: 'domcontentloaded', timeout: 12000 });
      await waitForStablePage(page, { settleMs: pageSettleMs });
      recordQuery(page.url());

      if (collectFormsOnCrawl) {
        const pageForms = await safeEvaluate(page, () =>
          Array.from(document.querySelectorAll('form')).map((form, idx) => {
            const fields = Array.from(form.querySelectorAll('input, textarea, select'))
              .map((el) => ({
                name:
                  el.getAttribute('name') ||
                  el.getAttribute('id') ||
                  `field_${idx}_${el.tagName.toLowerCase()}`,
                type: (el.getAttribute('type') || el.tagName).toLowerCase(),
                value: el.value || '',
              }))
              .filter((f) => f.name && !['submit', 'button', 'image'].includes(f.type));
            return {
              action: form.action || location.href,
              method: (form.method || 'GET').toUpperCase(),
              fields,
              pageUrl: location.href,
            };
          }),
        );
        crawledForms.push(...pageForms);
      }

      const moreTokens = await safeEvaluate(page, () => {
        const out = {};
        for (const k of Object.keys(localStorage || {})) {
          if (/token|auth|jwt|access|session/i.test(k)) {
            const v = localStorage.getItem(k);
            if (v && v.length > 20 && v.length < 5000) out[k] = v;
          }
        }
        return out;
      });
      Object.assign(pageInfo.tokens, moreTokens);

      // Harvest more same-origin links (bounded 1-hop expansion)
      const moreLinks = await safeEvaluate(
        page,
        (origin) =>
          Array.from(document.querySelectorAll('a[href]'))
            .map((a) => a.href)
            .filter((href) => {
              try {
                return new URL(href).origin === origin;
              } catch {
                return false;
              }
            }),
        originLimit,
      );
      for (const ml of moreLinks) {
        if (queued.has(ml) || queued.size >= maxLinks * 3) continue;
        queued.add(ml);
        if (highValue(ml) === 0) crawlQueue.unshift(ml);
        else crawlQueue.push(ml);
      }
    } catch {
      // continue
    }
  }

  // Dedupe forms by action+method+field names
  const formSeen = new Set();
  pageInfo.forms = crawledForms.filter((f) => {
    const key = `${f.method}|${f.action}|${(f.fields || []).map((x) => x.name).join(',')}`;
    if (formSeen.has(key)) return false;
    formSeen.add(key);
    return true;
  });

  page.off('response', onResponse);

  // Build synthetic API candidates from bundle intel
  const guessedApis = [];
  const apiBases = [...bundleIntel.apiHosts];
  // Heuristic: frontend host -> api/devapi sibling
  try {
    const t = new URL(targetUrl);
    const host = t.hostname.replace(/^www\./, '');
    const parts = host.split('.');
    if (parts.length >= 2) {
      const root = parts.slice(-2).join('.');
      const sub = parts.length > 2 ? parts[0] : '';
      apiBases.push(`${t.protocol}//api.${root}`);
      if (sub) apiBases.push(`${t.protocol}//${sub}api.${root}`);
      if (sub === 'dev') apiBases.push(`${t.protocol}//devapi.${root}`);
      apiBases.push(`${t.origin}/api`);
    }
  } catch {
    // ignore
  }

  const uniqueBases = [...new Set(apiBases)].filter((b) => {
    try {
      const full = b.includes('://') ? b : `https://${b}`;
      const h = new URL(full).hostname;
      if (THIRD_PARTY_HOST_RE.test(h)) return false;
      if (/whatsapp|facebook|amazon|amazonaws|elasticbeanstalk|execute-api/i.test(h)) {
        // keep AWS execute-api only if hostname also contains target brand token
        const brand = new URL(targetUrl).hostname.split('.').slice(-2, -1)[0];
        return brand && h.toLowerCase().includes(brand.toLowerCase());
      }
      return relatedHost(full, targetUrl) || /\/api$/i.test(b);
    } catch {
      return false;
    }
  });

  // Keep synthetic API guesses small — large OpenAPI/bundle lists explode probe time
  const seedPaths = [
    ...bundleIntel.routes.slice(0, 20),
    'api/auth/signin',
    'api/auth/login',
    'api/auth/forgot',
  ];

  for (const base of uniqueBases.slice(0, 3)) {
    const origin = base.includes('://') ? new URL(base).origin : base;
    const prefix = /\/api$/i.test(base) ? base : `${origin}`;
    for (const route of seedPaths) {
      let path = route.replace(/^\/+/, '');
      if (/\/api$/i.test(prefix) && path.startsWith('api/')) path = path.slice(4);
      const url = path.startsWith('http') ? path : `${prefix}/${path}`.replace(/([^:]\/)\/+/g, '$1');
      guessedApis.push({
        url,
        method: /auth\/(signin|login|forgot|signup)/i.test(url) ? 'POST' : 'GET',
        status: 0,
        contentType: 'application/json',
        postData: null,
        authHeader: null,
        source: 'bundle',
      });
    }
  }

  const seenApi = new Set();
  const apis = [];
  for (const hit of [...apiHits, ...guessedApis]) {
    const key = `${hit.method} ${hit.url.split('?')[0]}`;
    if (seenApi.has(key)) continue;
    seenApi.add(key);
    apis.push(hit);
    if (apis.length >= 80) break;
  }

  const querySurfaces = [...queryParams.entries()].map(([base, params]) => ({
    baseUrl: base,
    parameters: [...params],
  }));

  // Pick best token from localStorage
  let discoveredToken = null;
  for (const [k, v] of Object.entries(pageInfo.tokens || {})) {
    if (/access|token|jwt|auth/i.test(k)) {
      discoveredToken = v.startsWith('Bearer ') ? v : v;
      break;
    }
  }

  return {
    pageInfo,
    apis,
    querySurfaces,
    visitedUrls: [...visited],
    apiBases: uniqueBases,
    bundleRoutes: bundleIntel.routes,
    discoveredToken,
  };
}

module.exports = { discoverSurfaces, sameOrigin, isAppApiUrl, relatedHost };
