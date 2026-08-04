/**
 * Passive technology fingerprinting from headers, HTML, and JS hints.
 * Safe / non-intrusive — no version probing exploits.
 */
export class FingerprintEngine {
  async fingerprint(page: any, targetUrl: string, recon: any) {
    const request = page.context().request;
    let headers: Record<string, string> = {};
    let html = '';
    try {
      const res = await request.fetch(targetUrl, { failOnStatusCode: false, timeout: 15000 });
      const h = res.headers();
      for (const [k, v] of Object.entries(h)) headers[k.toLowerCase()] = String(v);
      html = (await res.text()).slice(0, 200000);
    } catch {
      /* ignore */
    }

    const frontend: string[] = [];
    const backend: string[] = [];
    const database: string[] = [];
    const languages: string[] = [];
    const cdn: string[] = [];
    const auth: string[] = [];
    const cloud: string[] = [];
    const server: string[] = [];
    const waf: string[] = [];

    if (/ng-version|angular/i.test(html)) frontend.push('Angular');
    if (/react|__NEXT_DATA__|data-reactroot/i.test(html)) frontend.push(/__NEXT_DATA__/i.test(html) ? 'Next.js/React' : 'React');
    if (/vue\.js|__VUE__/i.test(html)) frontend.push('Vue');
    if (/wp-content|wordpress/i.test(html)) frontend.push('WordPress');

    const serverH = headers.server || '';
    if (serverH) server.push(serverH);
    if (/express/i.test(serverH) || /x-powered-by:\s*express/i.test(JSON.stringify(headers))) {
      backend.push('Express/Node.js');
    }
    if (headers['x-powered-by']) backend.push(headers['x-powered-by']);
    if (headers['x-aspnet-version'] || headers['x-aspnetmvc-version']) backend.push('ASP.NET');
    if (/php/i.test(headers['x-powered-by'] || '')) backend.push('PHP');

    if (/cloudflare/i.test(headers.server || '') || headers['cf-ray']) cdn.push('Cloudflare');
    if (headers['x-amz-cf-id'] || /amazon|aws/i.test(headers.via || '')) cloud.push('AWS');
    if (headers['x-azure-ref']) cloud.push('Azure');
    if (headers['x-vercel-id']) cloud.push('Vercel');

    if (headers['x-sucuri-id']) waf.push('Sucuri');
    if (/akamai/i.test(headers.server || '')) waf.push('Akamai');

    const apis = (recon?.apis || []).map((a: any) => a.url).join(' ');
    if (/auth0\.com|okta\.com|login\.microsoftonline|accounts\.google/i.test(apis + html)) {
      if (/auth0/i.test(apis + html)) auth.push('Auth0');
      if (/okta/i.test(apis + html)) auth.push('Okta');
      if (/microsoftonline/i.test(apis + html)) auth.push('Microsoft Entra ID');
      if (/accounts\.google/i.test(apis + html)) auth.push('Google Identity');
    }
    const routeBlob = JSON.stringify(recon?.bundleRoutes || []).slice(0, 4000);
    if (/mongodb|mongoose/i.test(routeBlob + html)) {
      database.push('MongoDB');
      backend.push('MongoDB/Mongoose hints');
    }
    if (/postgres|prisma|sequelize/i.test(routeBlob)) database.push('SQL (ORM hints)');

    if (frontend.length) languages.push('JavaScript/TypeScript (Frontend)');
    if (/express|node/i.test(backend.join(' ') + (headers['x-powered-by'] || ''))) {
      languages.push('JavaScript/TypeScript (Node.js)');
    }
    if (/php/i.test(headers['x-powered-by'] || '')) languages.push('PHP');
    if (/asp\.net/i.test(backend.join(' '))) languages.push('C# / .NET');

    return {
      frontend: uniq(frontend),
      backend: uniq(backend),
      database: uniq(database),
      languages: uniq(languages),
      server: uniq(server),
      cdn: uniq(cdn),
      cloud: uniq(cloud),
      waf: uniq(waf),
      auth: uniq(auth),
      securityHeadersPresent: [
        'content-security-policy',
        'strict-transport-security',
        'x-content-type-options',
        'x-frame-options',
      ].filter((h) => Boolean(headers[h])),
      rawHeaderKeys: Object.keys(headers).slice(0, 40),
    };
  }
}

function uniq(arr: string[]) {
  return [...new Set(arr.filter(Boolean))];
}
