import type { EvaluationRule } from '../models/ComplianceControl';

/**
 * Generic, data-driven predicate interpreter for EvaluationRule. Keeping this
 * as one small interpreter (rather than one bespoke evaluator function per
 * CIS control) is what lets control *content* live entirely in benchmark
 * JSON instead of TypeScript business logic.
 */
export function ruleMatches(rule: EvaluationRule, fields: Record<string, unknown>): boolean {
  const actual = fields[rule.field];

  switch (rule.operator) {
    case 'exists':
      return actual !== undefined && actual !== null;
    case 'not-exists':
      return actual === undefined || actual === null;
    case 'equals':
      return String(actual) === String(rule.value);
    case 'not-equals':
      return String(actual) !== String(rule.value);
    case 'contains':
      return typeof actual === 'string' && actual.includes(String(rule.value ?? ''));
    case 'not-contains':
      return typeof actual !== 'string' || !actual.includes(String(rule.value ?? ''));
    case 'matches-regex':
      return typeof actual === 'string' && buildRegex(String(rule.value ?? '')).test(actual);
    case 'not-matches-regex':
      return typeof actual !== 'string' || !buildRegex(String(rule.value ?? '')).test(actual);
    case 'permission-at-most':
      return permissionAtMost(actual, rule.value);
    default:
      return false;
  }
}

/**
 * Benchmark JSON writes patterns in the common inline-flag style
 * (e.g. "(?im)^Foo$"), which PCRE/Python support but JavaScript's RegExp
 * constructor does not. This lifts a single leading "(?<flags>)" group of
 * i/m/s letters into JS RegExp flags so control authors don't need to know
 * JS-specific regex syntax when writing benchmark control data.
 */
function buildRegex(pattern: string): RegExp {
  const inlineFlags = pattern.match(/^\(\?([ims]+)\)/);
  if (inlineFlags) {
    return new RegExp(pattern.slice(inlineFlags[0].length), inlineFlags[1]);
  }
  return new RegExp(pattern);
}

/**
 * True when the octal file mode in `actual` grants no more permission bits
 * than `maxMode` at any of owner/group/other. E.g. actual="600", max="644" -> true.
 * actual="666", max="644" -> false (group/other write exceeds allowed).
 */
function permissionAtMost(actual: unknown, maxMode: unknown): boolean {
  const actualStr = String(actual ?? '');
  const maxStr = String(maxMode ?? '');
  if (!/^[0-7]{3,4}$/.test(actualStr) || !/^[0-7]{3,4}$/.test(maxStr)) return false;
  const a = parseInt(actualStr.slice(-3), 8);
  const m = parseInt(maxStr.slice(-3), 8);
  // Every permission bit set in `a` must also be set in `m`.
  return (a & ~m) === 0;
}
