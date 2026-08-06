const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

/** Hard cap — never a flood. */
const MAX_PROBES = 6;

function createPlugin(manifest) {
  return {
    manifest,
    lane: 'http',

    async discover(ctx) {
      const targets = [];
      const seen = new Set();
      const push = (url, kind) => {
        const key = String(url).split('?')[0];
        if (!key || seen.has(key)) return;
        seen.add(key);
        targets.push({ url: key, kind });
      };

      for (const a of ctx.attackSurface?.authEndpoints || []) {
        push(a.url || a, 'auth');
      }
      for (const ep of ctx.attackSurface?.endpoints || []) {
        const u = String(ep.url || '');
        if (/login|signin|auth\/|token|session/i.test(u)) push(u, 'auth-api');
      }
      try {
        const origin = new URL(ctx.request.targetUrl).origin;
        push(`${origin}/login`, 'login-page');
        push(`${origin}/api/login`, 'login-api');
        push(`${origin}/api/method/login`, 'login-api');
      } catch {
        /* ignore */
      }
      return { targets: targets.slice(0, 6) };
    },

    async scan(ctx, discovery) {
      const request = ctx.page.context().request;
      const timeout = Math.min(Number(ctx.config?.safety?.requestTimeoutMs || 8000), 10000);
      const out = [];

      for (const t of (discovery.targets || []).slice(0, 3)) {
        const statuses = [];
        const retryAfter = [];
        for (let i = 0; i < MAX_PROBES; i++) {
          try {
            const res = await request.fetch(t.url, {
              method: /api|method/i.test(t.url) ? 'POST' : 'GET',
              headers: { 'content-type': 'application/json' },
              data: /api|method/i.test(t.url)
                ? JSON.stringify({
                    usr: `sa_probe_${i}@invalid.example`,
                    pwd: `WrongPass${i}!`,
                    email: `sa_probe_${i}@invalid.example`,
                    password: `WrongPass${i}!`,
                  })
                : undefined,
              failOnStatusCode: false,
              timeout,
            });
            statuses.push(res.status());
            const ra = res.headers()['retry-after'];
            if (ra) retryAfter.push(ra);
            // Stop early if clearly rate limited
            if (res.status() === 429 || res.status() === 503) break;
          } catch {
            statuses.push(0);
          }
        }
        out.push({
          url: t.url,
          kind: t.kind,
          statuses,
          retryAfter,
          limited: statuses.some((s) => s === 429) || retryAfter.length > 0,
        });
      }
      return out;
    },

    async verify(_ctx, candidates) {
      const list = candidates || [];
      if (!list.length) {
        return [
          {
            pluginId: manifest.id,
            title: 'No auth endpoints available for rate-limit probe',
            description: 'Could not identify login/auth endpoints to probe safely.',
            severity: 'Informational',
            confidence: 'Informational',
            cvss: null,
            mappings: mappingsFor('rate-limiting'),
            affectedUrl: '',
            affectedEndpoint: '',
            evidence: [],
            impact: 'None',
            remediation: 'Ensure login URLs are discoverable or provide OpenAPI/focus routes.',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'],
            status: 'Pass',
            issueFound: false,
            testMode: 'active-safe',
            module: 'Rate Limiting',
            techniques: ['Bounded auth probe'],
          },
        ];
      }

      const findings = [];
      for (const c of list.slice(0, 4)) {
        const issueFound = !c.limited && c.statuses.filter((s) => s > 0).length >= MAX_PROBES - 1;
        findings.push({
          pluginId: manifest.id,
          title: issueFound
            ? `No rate limit observed on ${short(c.url)} (${MAX_PROBES} probes)`
            : `Rate limiting signals present on ${short(c.url)}`,
          description: issueFound
            ? `Sent ${c.statuses.length} bounded invalid auth probes; statuses=[${c.statuses.join(', ')}] with no HTTP 429/Retry-After. This is a soft signal — WAF delays may still exist. Not a DoS test.`
            : `Observed rate-limit style responses (429 and/or Retry-After) during bounded probes. Statuses=[${c.statuses.join(', ')}].`,
          severity: issueFound ? 'Medium' : 'Informational',
          confidence: issueFound ? 'Possible' : 'Informational',
          cvss: issueFound ? cvssFor('rate-limiting', 'Medium') : null,
          mappings: mappingsFor('rate-limiting'),
          affectedUrl: c.url,
          affectedEndpoint: c.url,
          parameter: 'auth',
          method: 'POST',
          evidence: [
            {
              technique: 'Bounded auth rate probe',
              maxProbes: MAX_PROBES,
              statuses: c.statuses,
              retryAfter: c.retryAfter,
              limited: c.limited,
            },
          ],
          http: [],
          impact: issueFound
            ? 'Missing auth rate limits enable credential stuffing and password spraying against user accounts.'
            : 'None',
          remediation:
            'Apply per-IP and per-account rate limits / lockouts on login and token endpoints; return 429 with Retry-After; consider CAPTCHA after repeated failures.',
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/307.html',
          ],
          status: issueFound ? 'Possible' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'Rate Limiting',
          techniques: ['Bounded auth probe'],
        });
      }
      return findings;
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      return { delta: findings.some((f) => f.issueFound) ? 8 : 0, notes: [] };
    },
  };
}

function short(url) {
  try {
    const u = new URL(url);
    return u.pathname || url;
  } catch {
    return String(url).slice(0, 60);
  }
}

module.exports = { createPlugin };
