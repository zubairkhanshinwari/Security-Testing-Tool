const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

function createPlugin(manifest) {
  return {
    manifest,
    lane: 'browser',

    async discover(ctx) {
      return { targets: [{ url: ctx.request.targetUrl }] };
    },

    async scan(ctx) {
      const page = ctx.page;
      let fields = [];
      try {
        fields = await page.evaluate(() => {
          const nodes = [...document.querySelectorAll('input[type="password"], input[name*="pass" i], input[id*="pass" i]')];
          return nodes.slice(0, 12).map((el) => {
            const form = el.closest('form');
            return {
              name: el.getAttribute('name') || el.id || 'password',
              type: el.getAttribute('type') || '',
              minLength: el.getAttribute('minlength') || el.minLength || null,
              maxLength: el.getAttribute('maxlength') || el.maxLength || null,
              pattern: el.getAttribute('pattern') || null,
              autocomplete: el.getAttribute('autocomplete') || null,
              required: el.required || el.hasAttribute('required'),
              formAction: form?.getAttribute('action') || '',
              formId: form?.id || '',
            };
          });
        });
      } catch {
        fields = [];
      }

      // Also inspect discovered forms from attack surface
      const surfaceFields = [];
      for (const form of (ctx.attackSurface?.forms || []).slice(0, 20)) {
        for (const f of form.fields || []) {
          if (/pass/i.test(f.name || '') || /pass/i.test(f.type || '')) {
            surfaceFields.push({
              name: f.name,
              type: f.type || 'password',
              minLength: f.minLength || null,
              pattern: f.pattern || null,
              autocomplete: f.autocomplete || null,
              required: Boolean(f.required),
              formAction: form.action || '',
              fromSurface: true,
            });
          }
        }
      }

      return [
        {
          url: ctx.request.targetUrl,
          fields: [...fields, ...surfaceFields].slice(0, 20),
        },
      ];
    },

    async verify(ctx, candidates) {
      const c = candidates[0] || { fields: [] };
      const fields = c.fields || [];
      const issues = [];

      if (!fields.length) {
        return [
          {
            pluginId: manifest.id,
            title: 'No password fields observed for policy review',
            description:
              'No password inputs were found on the loaded page or discovered forms. Policy checks were skipped.',
            severity: 'Informational',
            confidence: 'Informational',
            cvss: null,
            mappings: mappingsFor('weak-password'),
            affectedUrl: ctx.request.targetUrl,
            affectedEndpoint: ctx.request.targetUrl,
            evidence: [{ technique: 'Password field discovery', count: 0 }],
            impact: 'None',
            remediation: 'Ensure signup/login pages are in crawl scope when testing password policy.',
            references: ['https://cwe.mitre.org/data/definitions/521.html'],
            status: 'Pass',
            issueFound: false,
            testMode: 'passive',
            module: 'Weak Password Policy',
            techniques: ['Password policy review'],
          },
        ];
      }

      for (const f of fields) {
        const min = f.minLength != null && f.minLength !== '' ? Number(f.minLength) : null;
        if (min == null || !Number.isFinite(min) || min < 8) {
          issues.push({
            field: f.name,
            issue: min == null ? 'missing minlength' : `weak minlength=${min}`,
            formAction: f.formAction,
          });
        }
        if (!f.pattern) {
          issues.push({
            field: f.name,
            issue: 'no complexity pattern attribute',
            formAction: f.formAction,
          });
        }
        if (!f.autocomplete || /off/i.test(String(f.autocomplete))) {
          // autocomplete=off on password is mixed advice; flag missing new-password/current-password hints on signup-like forms
          if (/sign|regist|create/i.test(`${f.formAction} ${f.formId || ''}`)) {
            issues.push({
              field: f.name,
              issue: 'signup password missing autocomplete=new-password hint',
              formAction: f.formAction,
            });
          }
        }
      }

      // Deduplicate issue lines
      const seen = new Set();
      const unique = issues.filter((i) => {
        const k = `${i.field}|${i.issue}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });

      // Only missing minlength / very weak minlength count as issues (pattern alone is soft)
      const hard = unique.filter((i) => /minlength/i.test(i.issue));
      const issueFound = hard.length > 0;
      const severity = issueFound ? 'Low' : 'Informational';

      return [
        {
          pluginId: manifest.id,
          title: issueFound
            ? `Weak password policy signals (${hard.length})`
            : 'Password fields expose basic policy attributes',
          description: issueFound
            ? `Password inputs lack a strong client-side length policy: ${hard
                .slice(0, 6)
                .map((i) => `${i.field}: ${i.issue}`)
                .join('; ')}. Server-side policy must still be verified — this is a safe form-signal check only (no credential stuffing).`
            : `Reviewed ${fields.length} password field(s); minlength ≥ 8 present where checked. Server-side enforcement was not proven.`,
          severity,
          confidence: issueFound ? 'Possible' : 'Informational',
          cvss: issueFound ? cvssFor('weak-password', severity) : null,
          mappings: mappingsFor('weak-password'),
          affectedUrl: ctx.request.targetUrl,
          affectedEndpoint: ctx.request.targetUrl,
          parameter: 'password',
          method: 'GET',
          evidence: [
            {
              technique: 'Password field policy review',
              fields: fields.slice(0, 10),
              issues: unique.slice(0, 12),
            },
          ],
          http: [],
          impact: issueFound
            ? 'Weak password rules make credential stuffing and account takeover easier against customer/agent accounts.'
            : 'None',
          remediation:
            'Enforce password length/complexity server-side (min 12+ recommended), rate-limit failures, and align HTML minlength/pattern with backend rules. Never rely on client-only checks.',
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/521.html',
          ],
          status: issueFound ? 'Possible' : 'Pass',
          issueFound,
          testMode: 'passive',
          module: 'Weak Password Policy',
          techniques: ['Password policy review', 'Form attribute inspection'],
        },
      ];
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      return { delta: findings.some((f) => f.issueFound) ? 4 : 0, notes: [] };
    },
  };
}

module.exports = { createPlugin };
