/**
 * Parse OpenAPI / Swagger documents into concrete endpoint candidates.
 * Discovery-only — never probes for vulnerabilities.
 */

export interface OpenApiEndpoint {
  url: string;
  method: string;
  source: 'openapi';
  status: number;
  contentType: string;
  postData: null;
  authHeader: null;
  operationId?: string;
  parameters?: string[];
}

export function parseOpenApiDocument(
  doc: any,
  origin: string,
  maxPaths = 80,
): OpenApiEndpoint[] {
  if (!doc || typeof doc !== 'object') return [];

  const servers: string[] = [];
  if (Array.isArray(doc.servers)) {
    for (const s of doc.servers) {
      if (s?.url) servers.push(String(s.url));
    }
  }
  if (doc.host) {
    const scheme = Array.isArray(doc.schemes) && doc.schemes[0] ? doc.schemes[0] : 'https';
    const basePath = doc.basePath || '';
    servers.push(`${scheme}://${doc.host}${basePath}`);
  }
  if (!servers.length) servers.push(origin);

  const paths = doc.paths && typeof doc.paths === 'object' ? doc.paths : {};
  const out: OpenApiEndpoint[] = [];
  const methods = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'];

  for (const [rawPath, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue;
    for (const method of methods) {
      const op = (pathItem as any)[method];
      if (!op) continue;

      const server = servers[0];
      try {
        const resolved = resolveOpenApiUrl(origin, server, String(rawPath));
        const params: string[] = [];
        for (const p of op.parameters || (pathItem as any).parameters || []) {
          if (p?.name) params.push(String(p.name));
        }
        out.push({
          url: resolved,
          method: method.toUpperCase(),
          source: 'openapi',
          status: 0,
          contentType: 'application/json',
          postData: null,
          authHeader: null,
          operationId: op.operationId,
          parameters: params,
        });
      } catch {
        /* ignore bad paths */
      }
      if (out.length >= maxPaths) return out;
    }
  }
  return out;
}

/** Join server base + path without dropping basePath (URL('/x', base) replaces pathname). */
function resolveOpenApiUrl(origin: string, server: string, rawPath: string): string {
  let base = server;
  if (server.startsWith('/')) base = origin.replace(/\/$/, '') + server;
  else if (!/^https?:\/\//i.test(server)) base = `${origin.replace(/\/$/, '')}/${server}`;

  const pathPart = rawPath.replace(/\{[^}]+\}/g, '1');
  const baseUrl = new URL(ensureSlash(base));
  const joined = `${baseUrl.pathname.replace(/\/$/, '')}/${pathPart.replace(/^\//, '')}`.replace(
    /\/+/g,
    '/',
  );
  baseUrl.pathname = joined.startsWith('/') ? joined : `/${joined}`;
  return baseUrl.toString().split('#')[0];
}

function ensureSlash(base: string): string {
  try {
    const u = new URL(base);
    if (!u.pathname.endsWith('/')) u.pathname += '/';
    return u.toString();
  } catch {
    return base.endsWith('/') ? base : `${base}/`;
  }
}
