const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));
const { probePathParam, probeGetParam } = require(path.join(
  process.cwd(),
  'src/scanner/probes.js',
));
const { getSeverity } = require(path.join(process.cwd(), 'src/scanner/severity.js'));

function createPlugin(manifest) {
  return {
    manifest,
    async discover(ctx) {
      const targets = [];
      const seen = new Set();
      const push = (t) => {
        const key = `${t.type}|${t.endpoint}|${t.parameter}`;
        if (seen.has(key)) return;
        seen.add(key);
        targets.push(t);
      };
      for (const base of ctx.attackSurface.apiBases || []) {
        try {
          const origin = base.includes('://') ? new URL(base).origin : `https://${base}`;
          const root = /\/api$/i.test(base) ? base : `${origin}/api`;
          push({
            type: 'path',
            endpoint: `${root}/listings/{postal_code}/postal_code`,
            parameter: 'postal_code',
          });
          push({ type: 'path', endpoint: `${root}/users/{id}`, parameter: 'id' });
        } catch {
          /* ignore */
        }
      }
      for (const p of (ctx.attackSurface.parameters || []).slice(0, 30)) {
        push({ type: 'query', endpoint: p.endpoint, parameter: p.name });
      }
      for (const form of (ctx.attackSurface.forms || []).slice(0, 15)) {
        if (!/GET/i.test(form.method || 'GET')) continue;
        for (const field of form.fields || []) {
          if (!field.name || /password|csrf|token/i.test(field.name)) continue;
          push({ type: 'query', endpoint: form.action || ctx.request.targetUrl, parameter: field.name });
        }
      }
      for (const fe of (ctx.focusEndpoints || []).slice(0, 10)) {
        try {
          const u = new URL(fe.includes('://') ? fe : new URL(fe, ctx.request.targetUrl).href);
          for (const [name] of u.searchParams) {
            push({ type: 'query', endpoint: `${u.origin}${u.pathname}`, parameter: name });
          }
        } catch {
          /* ignore */
        }
      }
      return { targets: targets.slice(0, 18) };
    },
    async scan(ctx, discovery) {
      const auth = ctx.auth.token || null;
      const candidates = [];
      for (const t of discovery.targets.slice(0, 14)) {
        try {
          if (t.type === 'path') {
            const results = await probePathParam(ctx.page, t.endpoint, auth);
            for (const r of Array.isArray(results) ? results : [results]) {
              candidates.push({ ...r, endpoint: t.endpoint, parameter: t.parameter });
            }
          } else {
            const r = await probeGetParam(ctx.page, t.endpoint, t.parameter, auth);
            candidates.push({ ...r, endpoint: t.endpoint, parameter: t.parameter });
          }
        } catch {
          /* continue */
        }
      }
      return candidates;
    },
    async verify(_ctx, candidates) {
      return candidates
        .filter(
          (c) =>
            !c.issueFound ||
            (c.cwe || []).includes('CWE-943') ||
            /nosql/i.test(c.title || ''),
        )
        .map((c) => {
          const severity = getSeverity(c) || c.severity || (c.issueFound ? 'High' : 'Informational');
          return {
            id: c.id,
            pluginId: manifest.id,
            title: c.title || 'NoSQL Injection check',
            description: c.description || '',
            severity,
            confidence: c.issueFound ? 'Confirmed' : 'Informational',
            cvss: cvssFor('nosqli', severity),
            mappings: {
              ...mappingsFor('nosqli'),
              cwe: c.cwe?.length ? c.cwe : ['CWE-943'],
            },
            affectedUrl: c.fullUrl || c.endpoint,
            affectedEndpoint: c.endpoint,
            parameter: c.parameter,
            method: c.method || 'GET',
            evidence: c.evidence || [],
            http: [],
            impact: c.issueFound
              ? 'Attackers may bypass filters or extract data via NoSQL operators.'
              : 'None',
            remediation: c.issueFound
              ? 'Avoid interpolating untrusted input into query operators; use allow-lists and typed schemas.'
              : 'No action required.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection',
              'https://cwe.mitre.org/data/definitions/943.html',
            ],
            status: c.status || (c.issueFound ? 'Confirmed' : 'Pass'),
            issueFound: Boolean(c.issueFound),
            testMode: 'active-safe',
            module: 'NoSQL Injection',
            techniques: c.techniques || ['Operator injection', 'Regex differential'],
            cwe: c.cwe,
            owasp: c.owasp,
            authBlocked: c.authBlocked,
          };
        });
    },
    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },
    async score(findings) {
      let delta = 0;
      for (const f of findings.filter((x) => x.issueFound)) {
        if (f.severity === 'High') delta += 18;
        else if (f.severity === 'Medium') delta += 6;
        else if (f.severity === 'Low') delta += 4;
      }
      return { delta, notes: [] };
    },
  };
}

module.exports = { createPlugin };
