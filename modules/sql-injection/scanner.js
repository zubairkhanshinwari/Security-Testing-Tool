const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));
const { probeGetParam, probePathParam, probeJsonAuth } = require(path.join(
  process.cwd(),
  'src/scanner/probes.js',
));
const { getSeverity } = require(path.join(process.cwd(), 'src/scanner/severity.js'));
const { prioritizeByFocus } = require(path.join(
  process.cwd(),
  'src/platform/plugins/focusTargets.js',
));
const { sortByParamPriority } = require(path.join(
  process.cwd(),
  'src/platform/plugins/paramRank.js',
));

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

      for (const p of (ctx.attackSurface.parameters || []).slice(0, 40)) {
        push({ type: 'query', endpoint: p.endpoint, parameter: p.name });
      }
      for (const form of (ctx.attackSurface.forms || []).slice(0, 20)) {
        const action = form.action || ctx.request.targetUrl;
        for (const field of form.fields || []) {
          if (!field.name || /password|csrf|token/i.test(field.name)) continue;
          if (/GET/i.test(form.method || 'GET')) {
            push({ type: 'query', endpoint: action, parameter: field.name });
          }
        }
      }
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
          push({ type: 'path', endpoint: `${root}/items/{id}`, parameter: 'id' });
          push({ type: 'path', endpoint: `${root}/orders/{id}`, parameter: 'id' });
        } catch {
          /* ignore */
        }
      }
      for (const ep of (ctx.attackSurface.authEndpoints || []).slice(0, 6)) {
        push({ type: 'auth-json', endpoint: ep.split('?')[0], parameter: 'password' });
      }
      for (const fe of (ctx.focusEndpoints || []).slice(0, 12)) {
        try {
          const u = new URL(fe.includes('://') ? fe : new URL(fe, ctx.request.targetUrl).href);
          push({ type: 'query', endpoint: `${u.origin}${u.pathname}`, parameter: 'id' });
          push({ type: 'query', endpoint: `${u.origin}${u.pathname}`, parameter: 'q' });
          for (const [name] of u.searchParams) {
            push({ type: 'query', endpoint: `${u.origin}${u.pathname}`, parameter: name });
          }
        } catch {
          /* ignore */
        }
      }
      const ranked = sortByParamPriority(targets);
      return { targets: prioritizeByFocus(ranked, ctx.focusEndpoints, 24) };
    },

    async scan(ctx, discovery) {
      const auth = ctx.auth.token || null;
      const candidates = [];
      const ordered = prioritizeByFocus(
        sortByParamPriority(discovery.targets || []),
        ctx.focusEndpoints,
        18,
      );
      for (const t of ordered) {
        try {
          if (t.type === 'query') {
            const r = await probeGetParam(ctx.page, t.endpoint, t.parameter, auth);
            candidates.push({ ...r, endpoint: t.endpoint, parameter: t.parameter, method: 'GET' });
          } else if (t.type === 'path') {
            const results = await probePathParam(ctx.page, t.endpoint, auth);
            const list = Array.isArray(results) ? results : [results];
            for (const r of list) {
              candidates.push({ ...r, endpoint: t.endpoint, parameter: t.parameter, method: 'GET' });
            }
          } else if (t.type === 'auth-json') {
            const r = await probeJsonAuth(ctx.page, t.endpoint, null);
            candidates.push({ ...r, endpoint: t.endpoint, parameter: t.parameter, method: 'POST' });
          }
        } catch {
          /* continue */
        }
      }
      return candidates;
    },

    async verify(_ctx, candidates) {
      const findings = [];
      for (const c of candidates) {
        const isSqli =
          c.issueFound &&
          ((c.cwe || []).includes('CWE-89') || /sql injection/i.test(c.title || ''));
        // Keep NoSQLi/other for nosql plugin; still emit non-SQLi from path probes as generic if CWE-943
        const isOurs =
          isSqli ||
          (!c.issueFound && c.endpoint) ||
          ((c.cwe || []).includes('CWE-209') && /sql/i.test(JSON.stringify(c.evidence || [])));

        if ((c.cwe || []).includes('CWE-943')) continue; // owned by nosql plugin
        if (!isOurs && c.issueFound && !(c.cwe || []).includes('CWE-89') && !(c.cwe || []).includes('CWE-209') && !(c.cwe || []).includes('CWE-476')) {
          continue;
        }

        const severity = getSeverity(c) || c.severity || (c.issueFound ? 'Medium' : 'Informational');
        const key = (c.cwe || []).includes('CWE-89') ? 'sqli' : 'info-disclosure';
        findings.push({
          id: c.id,
          pluginId: manifest.id,
          title: c.title || 'SQL Injection check',
          description: c.description || '',
          severity,
          confidence: c.issueFound ? 'Likely' : 'Informational',
          cvss: cvssFor(key, severity),
          mappings: { ...mappingsFor(key), cwe: c.cwe || mappingsFor(key).cwe },
          affectedUrl: c.fullUrl || c.endpoint,
          affectedEndpoint: c.endpoint,
          parameter: c.parameter,
          method: c.method || 'GET',
          evidence: c.evidence || [],
          http: [],
          screenshotPath: null,
          impact: c.issueFound
            ? 'Attackers may read or modify database data via crafted input.'
            : 'None',
          remediation: c.issueFound
            ? 'Use parameterized queries / prepared statements; never concatenate SQL.'
            : 'No action required.',
          references: [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cwe.mitre.org/data/definitions/89.html',
          ],
          status: c.status || (c.issueFound ? 'Confirmed' : 'Pass'),
          issueFound: Boolean(c.issueFound),
          testMode: 'active-safe',
          module: c.module || 'SQL Injection',
          featureName: c.featureName,
          techniques: c.techniques || ['Error-based', 'Boolean', 'Time-based'],
          cwe: c.cwe,
          owasp: c.owasp,
          authBlocked: c.authBlocked,
        });
      }
      return findings;
    },

    async report(findings) {
      return {
        plugin: manifest.id,
        issues: findings.filter((f) => f.issueFound).length,
        passes: findings.filter((f) => !f.issueFound).length,
      };
    },

    async score(findings) {
      let delta = 0;
      for (const f of findings.filter((x) => x.issueFound)) {
        if (f.severity === 'Critical') delta += 30;
        else if (f.severity === 'High') delta += 18;
        else if (f.severity === 'Medium') delta += 6;
        else if (f.severity === 'Low') delta += 4;
      }
      return { delta, notes: [`${manifest.id} contributed -${delta}`] };
    },
  };
}

module.exports = { createPlugin };
