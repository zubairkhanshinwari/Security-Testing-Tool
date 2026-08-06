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
      let inputs = [];
      try {
        inputs = await page.evaluate(() => {
          return [...document.querySelectorAll('input[type="file"]')].slice(0, 15).map((el) => {
            const form = el.closest('form');
            return {
              name: el.getAttribute('name') || el.id || 'file',
              accept: el.getAttribute('accept') || '',
              multiple: el.multiple,
              capture: el.getAttribute('capture') || '',
              formAction: form?.getAttribute('action') || '',
              formMethod: (form?.getAttribute('method') || 'GET').toUpperCase(),
              formEnctype: form?.getAttribute('enctype') || '',
            };
          });
        });
      } catch {
        inputs = [];
      }

      // Heuristic API upload endpoints from attack surface (no upload performed)
      const apiHints = [];
      for (const ep of (ctx.attackSurface?.endpoints || []).slice(0, 80)) {
        const u = String(ep.url || '');
        if (/upload|multipart|attachment|media\/|files?\//i.test(u)) {
          apiHints.push({ url: u, method: ep.method || 'POST' });
        }
      }

      return [{ url: ctx.request.targetUrl, inputs, apiHints: apiHints.slice(0, 12) }];
    },

    async verify(ctx, candidates) {
      const c = candidates[0] || { inputs: [], apiHints: [] };
      const inputs = c.inputs || [];
      const apiHints = c.apiHints || [];
      const issues = [];

      for (const inp of inputs) {
        if (!inp.accept) {
          issues.push({
            control: inp.name,
            issue: 'file input missing accept= allow-list',
            formAction: inp.formAction,
          });
        }
        if (inp.formEnctype && !/multipart\/form-data/i.test(inp.formEnctype) && /post|put/i.test(inp.formMethod)) {
          issues.push({
            control: inp.name,
            issue: 'upload form enctype may be incorrect for files',
            formAction: inp.formAction,
          });
        }
        if (inp.multiple) {
          issues.push({
            control: inp.name,
            issue: 'multiple files allowed — ensure server quotas',
            formAction: inp.formAction,
            soft: true,
          });
        }
      }

      for (const hint of apiHints) {
        issues.push({
          control: hint.url,
          issue: 'upload-like API endpoint observed (not probed with files)',
          soft: true,
        });
      }

      const hard = issues.filter((i) => !i.soft && /accept=/i.test(i.issue));
      const issueFound = hard.length > 0;
      const hasSurface = inputs.length > 0 || apiHints.length > 0;

      if (!hasSurface) {
        return [
          {
            pluginId: manifest.id,
            title: 'No file upload surfaces observed',
            description: 'No file inputs or upload-like API paths were found in scope.',
            severity: 'Informational',
            confidence: 'Informational',
            cvss: null,
            mappings: mappingsFor('file-upload'),
            affectedUrl: ctx.request.targetUrl,
            affectedEndpoint: ctx.request.targetUrl,
            evidence: [{ technique: 'Upload surface discovery', inputs: 0, apiHints: 0 }],
            impact: 'None',
            remediation: 'When adding uploads, enforce server-side type/size/content checks.',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'],
            status: 'Pass',
            issueFound: false,
            testMode: 'passive',
            module: 'File Upload',
            techniques: ['Upload surface review'],
          },
        ];
      }

      return [
        {
          pluginId: manifest.id,
          title: issueFound
            ? `File upload controls lack client allow-list (${hard.length})`
            : `File upload surfaces reviewed (${inputs.length} input(s), ${apiHints.length} API hint(s))`,
          description: issueFound
            ? `File inputs without accept= allow-lists: ${hard
                .slice(0, 5)
                .map((i) => i.control)
                .join(', ')}. Client hints are not security controls — server-side validation must still be verified. No files were uploaded during this safe review.`
            : `Observed upload UI/API surfaces. No missing accept= issues on file inputs; server-side validation was not exercised (safe mode — no malware/shell uploads).`,
          severity: issueFound ? 'Low' : 'Informational',
          confidence: issueFound ? 'Possible' : 'Informational',
          cvss: issueFound ? cvssFor('file-upload', 'Low') : null,
          mappings: mappingsFor('file-upload'),
          affectedUrl: ctx.request.targetUrl,
          affectedEndpoint: ctx.request.targetUrl,
          parameter: 'file',
          method: 'POST',
          evidence: [
            {
              technique: 'Safe upload surface review',
              inputs: inputs.slice(0, 10),
              apiHints: apiHints.slice(0, 10),
              issues: issues.slice(0, 15),
            },
          ],
          http: [],
          impact: issueFound
            ? 'Unrestricted upload surfaces increase risk of malicious file storage if server checks are also weak — can lead to malware hosting or later RCE if executed.'
            : 'None proven',
          remediation:
            'Allow-list extensions and MIME types server-side, scan content, store outside web root, randomize names, enforce size limits. Never trust client accept= alone.',
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/434.html',
          ],
          status: issueFound ? 'Possible' : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'File Upload',
          techniques: ['Upload surface review', 'Safe attribute inspection'],
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
