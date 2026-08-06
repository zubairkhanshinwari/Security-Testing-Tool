const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

/**
 * Safe clickjacking / UI-redressing checks (header-only).
 * Does not load attacker iframes or perform UI interaction exploits.
 */

function createPlugin(manifest) {
  return {
    manifest,
    lane: 'http',

    async discover(ctx) {
      const targets = [];
      const seen = new Set();
      const push = (endpoint, note) => {
        const key = String(endpoint || '').split('?')[0];
        if (!key || seen.has(key)) return;
        seen.add(key);
        targets.push({ endpoint: key, note });
      };

      push(ctx.request.targetUrl, 'homepage');

      for (const ep of (ctx.focusEndpoints || []).slice(0, 6)) {
        try {
          const u = ep.includes('://') ? ep : new URL(ep, ctx.request.targetUrl).href;
          push(u, 'focus');
        } catch {
          /* ignore */
        }
      }

      for (const ep of ctx.attackSurface?.endpoints || []) {
        const method = (ep.method || 'GET').toUpperCase();
        if (method !== 'GET' && method !== 'HEAD') continue;
        const url = String(ep.url || '');
        if (/login|signin|signup|register|account|checkout|payment|admin|dashboard|settings|profile/i.test(url)) {
          push(url, 'sensitive-ui');
        }
      }

      for (const f of ctx.attackSurface?.forms || []) {
        if (/login|password|sign.?in|register/i.test(`${f.action || ''} ${(f.inputs || []).map((i) => i.name).join(' ')}`)) {
          push(f.action || ctx.request.targetUrl, 'auth-form');
        }
      }

      return { targets: targets.slice(0, 8) };
    },

    async scan(ctx, discovery) {
      const request = ctx.page.context().request;
      const timeout = Number(ctx.config?.safety?.requestTimeoutMs || 15000);
      const out = [];

      for (const t of discovery.targets || []) {
        try {
          const res = await request.fetch(t.endpoint, {
            method: 'GET',
            failOnStatusCode: false,
            timeout,
          });
          const headers = {};
          for (const [k, v] of Object.entries(res.headers())) headers[k.toLowerCase()] = v;
          out.push({
            endpoint: t.endpoint,
            note: t.note,
            status: res.status(),
            headers,
            analysis: analyzeFrameProtection(headers),
          });
        } catch {
          /* continue */
        }
      }
      return out;
    },

    async verify(_ctx, candidates) {
      const findings = [];
      const list = candidates || [];

      for (const c of list.slice(0, 6)) {
        const a = c.analysis || analyzeFrameProtection(c.headers || {});
        if (a.protected) continue;

        const severity = a.level === 'missing' ? 'Medium' : 'Low';
        findings.push({
          pluginId: manifest.id,
          title:
            a.level === 'missing'
              ? `Clickjacking: no frame protection on ${shortPath(c.endpoint)}`
              : `Clickjacking: weak frame protection on ${shortPath(c.endpoint)}`,
          description: a.summary,
          severity,
          confidence: 'Confirmed',
          cvss: cvssFor('clickjacking', severity),
          mappings: {
            ...mappingsFor('clickjacking'),
            cwe: ['CWE-1021', 'CWE-693'],
          },
          affectedUrl: c.endpoint,
          affectedEndpoint: c.endpoint,
          parameter: 'response-headers',
          method: 'GET',
          evidence: [
            {
              technique: 'Frame-protection header review',
              note: c.note,
              xFrameOptions: a.xfo || '(absent)',
              cspFrameAncestors: a.frameAncestors || '(absent)',
              level: a.level,
              reasons: a.reasons,
            },
          ],
          http: [
            {
              request: { method: 'GET', url: c.endpoint },
              response: {
                status: c.status || 0,
                headers: {
                  'x-frame-options': a.xfo || undefined,
                  'content-security-policy': a.csp ? String(a.csp).slice(0, 240) : undefined,
                },
              },
            },
          ],
          impact:
            'Attackers may embed this page in a malicious iframe and trick users into clicking hidden UI (UI redressing), risking unintended actions while authenticated.',
          remediation:
            "Set Content-Security-Policy frame-ancestors 'none' or 'self' (preferred), and/or X-Frame-Options: DENY or SAMEORIGIN. Avoid obsolete ALLOW-FROM and frame-ancestors *.",
          references: [
            'https://owasp.org/www-community/attacks/Clickjacking',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors',
            'https://cwe.mitre.org/data/definitions/1021.html',
          ],
          status: 'Confirmed',
          issueFound: true,
          testMode: 'passive',
          module: 'Clickjacking',
          techniques: ['X-Frame-Options review', 'CSP frame-ancestors review'],
        });
      }

      if (!findings.length) {
        const sample = list[0];
        const a = sample?.analysis || analyzeFrameProtection(sample?.headers || {});
        findings.push({
          pluginId: manifest.id,
          title: 'Clickjacking protections present',
          description:
            a.summary ||
            'X-Frame-Options and/or CSP frame-ancestors adequately restrict framing on probed pages.',
          severity: 'Informational',
          confidence: 'Informational',
          cvss: cvssFor('clickjacking', 'Informational'),
          mappings: mappingsFor('clickjacking'),
          affectedUrl: sample?.endpoint || '',
          affectedEndpoint: sample?.endpoint || '',
          parameter: 'response-headers',
          method: 'GET',
          evidence: [
            {
              technique: 'Frame-protection header review',
              pagesChecked: list.length,
              xFrameOptions: a.xfo || '(absent)',
              cspFrameAncestors: a.frameAncestors || '(absent)',
            },
          ],
          http: sample
            ? [
                {
                  request: { method: 'GET', url: sample.endpoint },
                  response: { status: sample.status || 0 },
                },
              ]
            : [],
          impact: 'None',
          remediation:
            "Keep CSP frame-ancestors 'none'/'self' (or an allowlist) and X-Frame-Options DENY/SAMEORIGIN on interactive pages.",
          references: ['https://owasp.org/www-community/attacks/Clickjacking'],
          status: 'Pass',
          issueFound: false,
          testMode: 'passive',
          module: 'Clickjacking',
          techniques: ['X-Frame-Options review', 'CSP frame-ancestors review'],
        });
      }

      return findings.slice(0, 6);
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      const f = findings.find((x) => x.issueFound);
      if (!f) return { delta: 0, notes: [] };
      return { delta: f.severity === 'Medium' ? 8 : 4, notes: [] };
    },
  };
}

/**
 * @returns {{
 *  protected: boolean,
 *  level: 'ok'|'weak'|'missing',
 *  xfo: string,
 *  csp: string,
 *  frameAncestors: string|null,
 *  reasons: string[],
 *  summary: string
 * }}
 */
function analyzeFrameProtection(headers) {
  const h = headers || {};
  const xfo = String(h['x-frame-options'] || '').trim();
  const csp = String(h['content-security-policy'] || '').trim();
  const frameAncestors = extractFrameAncestors(csp);
  const reasons = [];
  const xfoUpper = xfo.toUpperCase();

  const xfoDeny = xfoUpper === 'DENY';
  const xfoSame = xfoUpper === 'SAMEORIGIN';
  const xfoAllowFrom = xfoUpper.startsWith('ALLOW-FROM');
  const faNone = frameAncestors != null && /(^|\s)'none'(\s|$)/i.test(frameAncestors);
  const faSelf = frameAncestors != null && /(^|\s)'self'(\s|$)/i.test(frameAncestors);
  const faStar = frameAncestors != null && /(^|\s)\*(\s|$)/.test(frameAncestors);
  const faAllowlist =
    frameAncestors != null &&
    !faStar &&
    frameAncestors.trim() !== '' &&
    (faNone || faSelf || /https?:\/\//i.test(frameAncestors) || /'self'|'none'/i.test(frameAncestors));

  if (xfoDeny || xfoSame) reasons.push(`X-Frame-Options: ${xfo}`);
  if (faNone) reasons.push("CSP frame-ancestors 'none'");
  if (faSelf) reasons.push("CSP frame-ancestors 'self'");
  if (frameAncestors && !faStar && !faNone && !faSelf) {
    reasons.push(`CSP frame-ancestors allowlist: ${frameAncestors}`);
  }

  if (xfoDeny || xfoSame || faNone || faSelf || (faAllowlist && !faStar)) {
    return {
      protected: true,
      level: 'ok',
      xfo,
      csp,
      frameAncestors,
      reasons,
      summary: `Frame embedding is restricted (${reasons.join('; ') || 'policy present'}).`,
    };
  }

  if (xfoAllowFrom || faStar) {
    const weakReasons = [];
    if (xfoAllowFrom) weakReasons.push('X-Frame-Options ALLOW-FROM is obsolete and ignored by modern browsers');
    if (faStar) weakReasons.push("CSP frame-ancestors * allows any origin to frame the page");
    return {
      protected: false,
      level: 'weak',
      xfo,
      csp,
      frameAncestors,
      reasons: weakReasons,
      summary: `Weak clickjacking protection: ${weakReasons.join('; ')}.`,
    };
  }

  return {
    protected: false,
    level: 'missing',
    xfo,
    csp,
    frameAncestors,
    reasons: ['Neither X-Frame-Options nor CSP frame-ancestors was detected'],
    summary:
      'Neither X-Frame-Options nor CSP frame-ancestors was detected — the page may be embeddable in a cross-origin iframe (clickjacking risk).',
  };
}

function extractFrameAncestors(csp) {
  if (!csp) return null;
  const m = String(csp).match(/frame-ancestors\s+([^;]+)/i);
  return m ? m[1].trim() : null;
}

function shortPath(url) {
  try {
    return new URL(url).pathname || '/';
  } catch {
    return String(url).slice(0, 80);
  }
}

module.exports = {
  createPlugin,
  analyzeFrameProtection,
  extractFrameAncestors,
};
