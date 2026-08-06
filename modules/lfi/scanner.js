const path = require('path');
const { mappingsFor, cvssFor } = require(path.join(
  process.cwd(),
  'src/platform/core/standards/mappings.js',
));

/**
 * Safe, non-destructive LFI / path-traversal probes.
 * Only look for well-known file signatures in responses — no write/RCE payloads.
 */
const FILE_PROBES = [
  {
    payload: '../../../etc/passwd',
    markers: [/root:.*:0:0:/, /daemon:.*:1:1:/, /nobody:.*:\d+:\d+:/],
    platform: 'unix',
  },
  {
    payload: '....//....//....//etc/passwd',
    markers: [/root:.*:0:0:/],
    platform: 'unix-bypass',
  },
  {
    payload: '..%2f..%2f..%2fetc%2fpasswd',
    markers: [/root:.*:0:0:/],
    platform: 'unix-urlencoded',
    rawQuery: true,
  },
  {
    payload: '/etc/passwd',
    markers: [/root:.*:0:0:/],
    platform: 'unix-absolute',
  },
  {
    payload: '../../../etc/hosts',
    markers: [/localhost/i, /127\.0\.0\.1/],
    platform: 'unix-hosts',
    // hosts is weaker alone — require with other signals in verify
    soft: true,
  },
  {
    payload: '..\\..\\..\\windows\\win.ini',
    markers: [/\[fonts\]/i, /for 16-bit app support/i],
    platform: 'windows',
  },
  {
    payload: '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    markers: [/127\.0\.0\.1/, /localhost/i],
    platform: 'windows-hosts',
    soft: true,
  },
  {
    // PHP filter — read-only; hit if large base64-looking body appears vs baseline
    payload: 'php://filter/convert.base64-encode/resource=index.php',
    markers: [/PD9waH/i, /PCFET0NUVFlQRS/i], // <?php / <!DOCTYPE in base64
    platform: 'php-filter',
  },
];

const FILE_PARAMS =
  /^(file|filepath|filename|path|pathname|page|template|doc|document|folder|dir|directory|include|inc|view|content|load|src|source|read|download|attachment|resource|url|uri|name|pdf|img|image)$/i;

function createPlugin(manifest) {
  return {
    manifest,
    lane: 'http',

    async discover(ctx) {
      const targets = [];
      const seen = new Set();
      const push = (endpoint, parameter, note) => {
        const key = `${String(endpoint).split('?')[0]}|${parameter}`;
        if (!parameter || seen.has(key)) return;
        seen.add(key);
        targets.push({ endpoint: String(endpoint).split('?')[0], parameter, note });
      };

      for (const p of ctx.attackSurface?.parameters || []) {
        if (FILE_PARAMS.test(p.name || '')) push(p.endpoint, p.name, 'surface-param');
      }

      for (const form of (ctx.attackSurface?.forms || []).slice(0, 20)) {
        if (!/GET/i.test(form.method || 'GET')) continue;
        for (const f of form.fields || []) {
          if (FILE_PARAMS.test(f.name || '')) {
            push(form.action || ctx.request.targetUrl, f.name, 'form');
          }
        }
      }

      for (const ep of ctx.attackSurface?.endpoints || []) {
        const u = String(ep.url || '');
        if (/download|file|export|static|asset|include|view|attachment|media|document|pdf|read/i.test(u)) {
          const base = u.split('?')[0];
          push(base, 'file', 'endpoint-hint');
          push(base, 'path', 'endpoint-hint');
          push(base, 'filename', 'endpoint-hint');
          // Existing query keys that look file-like
          try {
            const parsed = new URL(u, ctx.request.targetUrl);
            for (const [k] of parsed.searchParams) {
              if (FILE_PARAMS.test(k)) push(base, k, 'endpoint-query');
            }
          } catch {
            /* ignore */
          }
        }
      }

      // Always seed a few common params on origin so LFI is not skipped on SPAs
      try {
        const origin = new URL(ctx.request.targetUrl).origin;
        for (const param of ['file', 'path', 'page', 'template', 'doc', 'include', 'view']) {
          push(`${origin}/`, param, 'seed');
          push(ctx.request.targetUrl.split('?')[0], param, 'seed');
        }
      } catch {
        /* ignore */
      }

      // Prefer file-like notes first
      targets.sort((a, b) => {
        const rank = (t) =>
          t.note === 'surface-param' ? 0 : t.note === 'form' ? 1 : t.note === 'endpoint-hint' ? 2 : 3;
        return rank(a) - rank(b);
      });

      return { targets: targets.slice(0, 16) };
    },

    async scan(ctx, discovery) {
      const request = ctx.page.context().request;
      const timeout = Number(ctx.config?.safety?.requestTimeoutMs || 10000);
      const candidates = [];
      const headers = { ...(ctx.auth?.headers || {}) };

      for (const t of (discovery.targets || []).slice(0, 12)) {
        // Baseline with a benign value
        let baselineBody = '';
        try {
          const baselineUrl = new URL(t.endpoint, ctx.request.targetUrl);
          baselineUrl.searchParams.set(t.parameter, 'secureassess_lfi_baseline.txt');
          const baseRes = await request.fetch(baselineUrl.toString(), {
            headers,
            failOnStatusCode: false,
            timeout,
          });
          baselineBody = await baseRes.text();
        } catch {
          baselineBody = '';
        }

        for (const probe of FILE_PROBES) {
          try {
            let url;
            if (probe.rawQuery) {
              const base = new URL(t.endpoint, ctx.request.targetUrl);
              const join = base.search && base.search.length > 1 ? '&' : '?';
              url = `${base.origin}${base.pathname}${base.search}${join}${encodeURIComponent(t.parameter)}=${probe.payload}`;
            } else {
              const base = new URL(t.endpoint, ctx.request.targetUrl);
              base.searchParams.set(t.parameter, probe.payload);
              url = base.toString();
            }

            const res = await request.fetch(url, {
              headers,
              failOnStatusCode: false,
              timeout,
            });
            const body = await res.text();
            const markerHit = probe.markers.some((re) => re.test(body));
            // Require marker not already present on baseline (reduces false positives)
            const baselineHas = probe.markers.some((re) => re.test(baselineBody));
            const hit = markerHit && !baselineHas;

            candidates.push({
              endpoint: url,
              parameter: t.parameter,
              payload: probe.payload,
              platform: probe.platform,
              soft: Boolean(probe.soft),
              status: res.status(),
              hit,
              baselineHas,
              bodySnippet: body.slice(0, 320),
              signals: hit
                ? ['baseline-diff', 'file-marker', ...(probe.soft ? ['soft-marker'] : ['os-file-signature'])]
                : baselineHas
                  ? ['marker-in-baseline']
                  : [],
            });
            if (hit && !probe.soft) break;
          } catch {
            /* continue */
          }
        }
      }
      return candidates;
    },

    async verify(_ctx, candidates) {
      const strongHits = (candidates || []).filter((c) => c.hit && !c.soft);
      const softHits = (candidates || []).filter((c) => c.hit && c.soft);
      const hits = strongHits.length ? strongHits : softHits;
      const sample = hits.length ? hits.slice(0, 5) : (candidates || []).slice(0, 1);

      return sample.map((c) => {
        const issueFound = Boolean(c && c.hit);
        const strong = issueFound && !c.soft && (c.signals || []).includes('os-file-signature');
        const severity = issueFound ? (strong ? 'High' : 'Medium') : 'Informational';
        const confidence = issueFound ? (strong ? 'Likely' : 'Possible') : 'Informational';

        return {
          pluginId: manifest.id,
          title: issueFound
            ? `LFI / path traversal on "${c.parameter}" (${c.platform})`
            : 'No obvious LFI / path traversal on probed parameters',
          description: issueFound
            ? `After a safe traversal/LFI payload, the response matched known OS/app file signatures that were absent from the baseline (${c.platform}). Non-destructive read-only check.`
            : c?.baselineHas || (c?.signals || []).includes('marker-in-baseline')
              ? 'Traversal markers appeared in the baseline response as well — treated as non-finding to avoid false positives.'
              : 'Safe path-traversal / LFI probes did not return known file signatures on tested parameters.',
          severity,
          confidence,
          cvss: issueFound ? cvssFor('lfi', severity) : null,
          mappings: mappingsFor('lfi'),
          affectedUrl: c?.endpoint || '',
          affectedEndpoint: c?.endpoint || '',
          parameter: c?.parameter || 'file',
          method: 'GET',
          evidence: [
            {
              technique: 'LFI / path traversal + baseline compare',
              payload: c?.payload,
              platform: c?.platform,
              status: c?.status,
              bodySnippet: c?.bodySnippet,
              confirmationSignals: c?.signals || [],
              baselineHadMarker: c?.baselineHas,
            },
          ],
          http: [],
          impact: issueFound
            ? 'Attackers may read sensitive files (configs, secrets, source) from the application host, enabling further compromise.'
            : 'None',
          remediation:
            'Never join user input into filesystem paths. Use allow-listed object IDs, store files outside the web root, canonicalize paths and reject .. segments, and disable dangerous wrappers (e.g. php://) in production.',
          references: [
            'https://owasp.org/www-community/attacks/Path_Traversal',
            'https://cwe.mitre.org/data/definitions/22.html',
            'https://cwe.mitre.org/data/definitions/98.html',
          ],
          status: issueFound ? (strong ? 'Likely' : 'Possible') : 'Pass',
          issueFound,
          testMode: 'active-safe',
          module: 'LFI / Path Traversal',
          techniques: ['Path Traversal', 'Local File Inclusion', 'Baseline differential'],
          verification: issueFound
            ? {
                signalCount: (c.signals || []).length,
                signals: c.signals || [],
                retestRecommended: !strong,
              }
            : undefined,
        };
      });
    },

    async report(findings) {
      return { plugin: manifest.id, issues: findings.filter((f) => f.issueFound).length };
    },

    async score(findings) {
      const f = findings.find((x) => x.issueFound);
      if (!f) return { delta: 0, notes: [] };
      return { delta: f.severity === 'High' ? 20 : 12, notes: [] };
    },
  };
}

module.exports = { createPlugin, FILE_PROBES, FILE_PARAMS };
