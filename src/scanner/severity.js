/** Canonical severity property name (built from codes to avoid source corruption). */
const SEVERITY_KEY = String.fromCharCode(115, 101, 118, 101, 114, 105, 116, 121);

function getSeverity(obj) {
  if (!obj || typeof obj !== 'object') return undefined;
  return obj[SEVERITY_KEY];
}

function setSeverity(obj, value) {
  if (!obj || typeof obj !== 'object') return obj;
  obj[SEVERITY_KEY] = value;
  return obj;
}

function normalizeSeverity(value, cvss = null) {
  const allowed = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  if (allowed.includes(value)) return value;
  if (typeof cvss === 'number') {
    if (cvss >= 9) return 'Critical';
    if (cvss >= 7) return 'High';
    if (cvss >= 5) return 'Medium';
    if (cvss > 0) return 'Low';
  }
  return 'Informational';
}

module.exports = {
  SEVERITY_KEY,
  getSeverity,
  setSeverity,
  normalizeSeverity,
};
