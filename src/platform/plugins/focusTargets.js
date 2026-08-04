/**
 * Phase E — helpers for plugins to prioritize incremental / high-value endpoints.
 */

function pathKey(url) {
  try {
    const u = new URL(url, 'https://placeholder.local');
    return `${u.origin}${u.pathname}`.replace(/\/$/, '').toLowerCase();
  } catch {
    return String(url || '')
      .split('?')[0]
      .replace(/\/$/, '')
      .toLowerCase();
  }
}

function matchesFocus(endpoint, focusUrl) {
  const ep = pathKey(endpoint);
  const f = pathKey(focusUrl);
  if (!ep || !f) return false;
  if (ep === f) return true;
  // Require path boundary so /a does not match /api
  return ep.startsWith(`${f}/`) || f.startsWith(`${ep}/`);
}

function prioritizeByFocus(items, focusEndpoints, limit) {
  if (!items || !items.length) return [];
  if (!focusEndpoints || !focusEndpoints.length) return items.slice(0, limit);

  const scored = items.map((item, index) => {
    const ep = String(item.endpoint || item.url || '');
    const hit = focusEndpoints.some((f) => matchesFocus(ep, f));
    return { item, index, score: hit ? 0 : 1 };
  });
  scored.sort((a, b) => a.score - b.score || a.index - b.index);
  return scored.slice(0, limit).map((s) => s.item);
}

module.exports = { prioritizeByFocus, matchesFocus };
