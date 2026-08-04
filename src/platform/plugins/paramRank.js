/** Shared param ranking for plugins (CommonJS). */

function rankParameterName(name) {
  const n = String(name || '').toLowerCase();
  if (
    /^(id|user_?id|account_?id|order_?id|q|query|search|keyword|email|file|path|url|redirect|next|callback)$/.test(
      n,
    )
  ) {
    return 0;
  }
  if (/id$|name|term|filter|sort|page|limit|offset/.test(n)) return 1;
  if (/password|csrf|token|_method|captcha|nonce/.test(n)) return 9;
  return 5;
}

function sortByParamPriority(items) {
  return [...(items || [])].sort(
    (a, b) =>
      rankParameterName(String(a.parameter || a.name || '')) -
      rankParameterName(String(b.parameter || b.name || '')),
  );
}

module.exports = { rankParameterName, sortByParamPriority };
