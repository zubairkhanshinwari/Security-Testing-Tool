import type { AttackSurface, TestMode } from '../../core/types/finding';
import type { SecurityPlugin } from '../../core/types/plugin';
import type { Logger } from '../../core/logging/logger';
import type { PluginManager } from '../../plugins/PluginManager';
import type { KnowledgeRepository } from '../../core/knowledge';
import type { BaselineDiff } from '../../dashboard/baseline';

/** Types fully owned by dedicated plugins — residual surfaceChecks skip these when that plugin runs. */
export const PLUGIN_OWNED_TYPES = new Set([
  'sqli',
  'nosqli',
  'http_headers',
  'cors',
  'info_disclosure',
  'clickjacking',
  'security_misconfig',
  'xss',
  'idor',
  'bac',
  'api_security',
  'jwt',
  'csrf',
  'ssrf',
  'open_redirect',
  'ssti',
  'lfi',
  'path_traversal',
  'cookie_security',
  'session_mgmt',
  'broken_auth',
  'weak_password',
  'file_upload',
  'rate_limiting',
]);

/** Deep residual types that stay in surfaceChecks even when OWASP expands the set. */
const DEEP_SURFACE_TYPES = [
  'sensitive_data',
];

const PASSIVE_BLOCKED_PLUGINS = new Set(['sql-injection', 'nosql-injection', 'ssti', 'lfi']);
const PASSIVE_BLOCKED_TYPES = new Set(['sqli', 'nosqli', 'command_injection', 'ssti', 'lfi', 'path_traversal']);

export type ProbeLane = 'http' | 'browser';

export interface ScanTask {
  id: string;
  kind: 'plugin' | 'surface-check';
  pluginId?: string;
  securityTypes?: string[];
  priority: number;
  lane: ProbeLane;
  reason: string;
}

export interface ScanPlan {
  plugins: SecurityPlugin[];
  pluginIds: string[];
  tasks: ScanTask[];
  surfaceTypes: string[];
  skippedPlugins: Array<{ id: string; reason: string }>;
  mode: TestMode;
  httpConcurrencyHint: number;
  summary: string;
  /** Phase 6 incremental focus */
  incremental?: boolean;
  focusEndpoints?: string[];
  retestPluginIds?: string[];
  baselineScanId?: string;
}

export interface PlanInput {
  requestedTypes: string[];
  selectedTypes: string[];
  explicitPluginIds?: string[];
  mode: TestMode;
  attackSurface: AttackSurface;
  fingerprint?: Record<string, unknown>;
  /** Optional shared repo — plan is stored + events emitted when present. */
  repo?: KnowledgeRepository;
  maxConcurrentProbes?: number;
  /** Phase 6: prioritize changed endpoints + prior confirmed issues */
  incremental?: boolean;
  baselineDiff?: BaselineDiff;
  retestConfirmed?: boolean;
  /** Operator-supplied high-value routes (coverage pack) */
  focusEndpoints?: string[];
}

/**
 * Scan Planning Engine — decides what to run, in what order, and on which lane.
 * Orchestrator must not select plugins or residual types itself.
 */
export class ScanPlanningEngine {
  constructor(
    private readonly logger: Logger,
    private readonly plugins: PluginManager,
  ) {}

  plan(input: PlanInput): ScanPlan {
    const {
      requestedTypes,
      selectedTypes,
      explicitPluginIds,
      mode,
      attackSurface,
      fingerprint = {},
      repo,
      maxConcurrentProbes = 4,
      incremental = false,
      baselineDiff,
      retestConfirmed = true,
      focusEndpoints: requestFocus = [],
    } = input;

    const skippedPlugins: Array<{ id: string; reason: string }> = [];
    const retestIds = new Set(
      incremental && retestConfirmed && baselineDiff?.available
        ? baselineDiff.retestPluginIds || []
        : [],
    );

    // 1) Resolve candidates from requested + expanded types
    const active = this.plugins.resolveForTypes(
      requestedTypes.length ? requestedTypes : selectedTypes,
      explicitPluginIds,
    );
    const expanded = this.plugins.resolveForTypes(selectedTypes, explicitPluginIds);
    const pluginMap = new Map<string, SecurityPlugin>();
    for (const p of [...active, ...expanded]) pluginMap.set(p.manifest.id, p);

    // 2) Mode gating
    let selected = [...pluginMap.values()];
    if (mode === 'passive') {
      selected = selected.filter((p) => {
        if (PASSIVE_BLOCKED_PLUGINS.has(p.manifest.id)) {
          skippedPlugins.push({ id: p.manifest.id, reason: 'mode=passive blocks active injection' });
          return false;
        }
        return true;
      });
    }

    // 3) Fingerprint / surface relevance
    selected = selected.filter((p) => {
      const skip = this.relevanceSkip(p, attackSurface, fingerprint);
      if (skip) {
        skippedPlugins.push({ id: p.manifest.id, reason: skip });
        return false;
      }
      return true;
    });

    // 4) Priority: cheap HTTP first; incremental retest plugins boosted ahead of peers
    selected.sort((a, b) => {
      const pa = this.pluginPriority(a, retestIds.has(a.manifest.id));
      const pb = this.pluginPriority(b, retestIds.has(b.manifest.id));
      return pa - pb;
    });

    // 5) Residual surface types
    const ownedByPlugins = new Set<string>();
    for (const p of selected) {
      for (const id of p.manifest.securityTypeIds || []) ownedByPlugins.add(id);
    }
    const residualTypes = selectedTypes.filter(
      (t) => !(PLUGIN_OWNED_TYPES.has(t) && ownedByPlugins.has(t)) && !ownedByPlugins.has(t),
    );
    let surfaceTypes = [
      ...new Set([
        ...residualTypes,
        ...selectedTypes.filter((t) => DEEP_SURFACE_TYPES.includes(t)),
      ]),
    ];
    if (mode === 'passive') {
      surfaceTypes = surfaceTypes.filter((t) => !PASSIVE_BLOCKED_TYPES.has(t));
    }

    // 6) Build task queue
    const tasks: ScanTask[] = selected.map((p, i) => {
      const retest = retestIds.has(p.manifest.id);
      return {
        id: `task-plugin-${p.manifest.id}`,
        kind: 'plugin' as const,
        pluginId: p.manifest.id,
        securityTypes: p.manifest.securityTypeIds || [],
        priority: this.pluginPriority(p, retest) + i * 0.01,
        lane: this.pluginLane(p),
        reason: retest
          ? `Incremental retest — prior confirmed findings via ${p.manifest.id}`
          : this.pluginReason(p, mode),
      };
    });

    if (surfaceTypes.length) {
      tasks.push({
        id: 'task-surface-checks',
        kind: 'surface-check',
        securityTypes: surfaceTypes,
        priority: 80,
        lane: 'browser',
        reason: `Residual surface verification (${surfaceTypes.length} types)`,
      });
    }

    tasks.sort((a, b) => a.priority - b.priority);

    const wafHint = this.hasWaf(fingerprint);
    const httpConcurrencyHint = wafHint
      ? Math.max(1, Math.floor(maxConcurrentProbes / 2))
      : maxConcurrentProbes;

    const baselineFocus =
      incremental && baselineDiff?.available ? baselineDiff.focusEndpoints || [] : [];
    const focusEndpoints = [...new Set([...(requestFocus || []), ...baselineFocus])];
    const incrementalActive = Boolean(incremental && baselineDiff?.available);

    const plan: ScanPlan = {
      plugins: selected,
      pluginIds: selected.map((p) => p.manifest.id),
      tasks,
      surfaceTypes,
      skippedPlugins,
      mode,
      httpConcurrencyHint,
      incremental: incrementalActive,
      focusEndpoints,
      retestPluginIds: [...retestIds],
      baselineScanId: baselineDiff?.baselineScanId,
      summary:
        `${selected.length} plugin(s), ${surfaceTypes.length} residual type(s), ` +
        `${skippedPlugins.length} skipped` +
        (wafHint ? ', WAF-aware concurrency' : '') +
        (focusEndpoints.length ? `, focus=${focusEndpoints.length} endpoint(s)` : '') +
        (incrementalActive ? `, retest=${retestIds.size} plugin(s)` : ''),
    };

    this.logger.info('Scan plan created', {
      plugins: plan.pluginIds,
      surfaceTypes: plan.surfaceTypes.length,
      skipped: skippedPlugins,
      mode,
      httpConcurrencyHint,
      incremental: incrementalActive,
      focusEndpoints: focusEndpoints.length,
      taskOrder: tasks.map((t) => t.id),
    });

    if (repo) {
      repo.setPlan({
        pluginIds: plan.pluginIds,
        surfaceTypes: plan.surfaceTypes,
        skippedPlugins: plan.skippedPlugins,
        mode: plan.mode,
        summary: plan.summary,
        httpConcurrencyHint: plan.httpConcurrencyHint,
        incremental: plan.incremental,
        focusEndpoints: plan.focusEndpoints,
        retestPluginIds: plan.retestPluginIds,
        baselineScanId: plan.baselineScanId,
        tasks: plan.tasks,
      });
      repo.bus.emit('plan.created', repo.scanId, {
        pluginIds: plan.pluginIds,
        surfaceTypes: plan.surfaceTypes,
        skipped: plan.skippedPlugins,
        summary: plan.summary,
        incremental: incrementalActive,
        focusEndpoints: focusEndpoints.length,
      });
    }

    return plan;
  }

  private pluginPriority(plugin: SecurityPlugin, retest = false): number {
    const id = plugin.manifest.id;
    // Retest plugins from prior confirmed findings run first in incremental mode
    if (retest) return 5;
    if (id === 'security-headers' || id === 'cors' || id === 'info-disclosure' || id === 'clickjacking') return 10;
    if (['xss', 'idor-bac', 'open-redirect', 'ssrf', 'ssti', 'lfi'].includes(id)) return 20;
    if (['jwt', 'csrf', 'cookie-security', 'session-mgmt'].includes(id)) return 25;
    if (id === 'sql-injection' || id === 'nosql-injection') return 40;
    return 30;
  }

  private pluginLane(plugin: SecurityPlugin): ProbeLane {
    const id = plugin.manifest.id;
    if (
      [
        'security-headers',
        'cors',
        'info-disclosure',
        'clickjacking',
        'xss',
        'idor-bac',
        'open-redirect',
        'ssrf',
        'ssti',
        'lfi',
      ].includes(id)
    ) {
      return 'http';
    }
    // JWT/CSRF need browser storage/cookies
    return 'browser';
  }

  private pluginReason(plugin: SecurityPlugin, mode: TestMode): string {
    return `Selected for types [${(plugin.manifest.securityTypeIds || []).join(', ')}] mode=${mode}`;
  }

  private relevanceSkip(
    plugin: SecurityPlugin,
    surface: AttackSurface,
    fingerprint: Record<string, unknown>,
  ): string | null {
    const ids = new Set(plugin.manifest.securityTypeIds || []);
    const tags = new Set((plugin.manifest.tags || []).map((t) => String(t).toLowerCase()));
    const pluginId = plugin.manifest.id;
    const fpText = JSON.stringify(fingerprint || {}).toLowerCase();
    const surfaceText = JSON.stringify({
      frameworks: surface.frameworks || [],
      libraries: surface.libraries || [],
      apiBases: surface.apiBases || [],
    }).toLowerCase();
    const blob = `${fpText} ${surfaceText}`;

    const wantsGraphql = ids.has('graphql') || tags.has('graphql');
    if (wantsGraphql && !(surface.graphql || []).length) {
      return 'no GraphQL endpoints discovered';
    }

    const wantsWebsocket = tags.has('websocket') || tags.has('websockets');
    if (wantsWebsocket && !(surface.websockets || []).length) {
      return 'no WebSocket endpoints discovered';
    }

    // Phase E: skip NoSQLi when fingerprint strongly indicates relational-only stack
    if (pluginId === 'nosql-injection') {
      const hasNosql = /mongo|couch|dynamo|firebase|nosql|realm/.test(blob);
      const hasSqlOnly =
        /mysql|mariadb|postgres|postgresql|mssql|sqlserver|oracle|sqlite/.test(blob) && !hasNosql;
      if (hasSqlOnly) return 'relational DB fingerprint without NoSQL signals';
    }

    // Skip JWT plugin when no token-like surface and no auth session likely
    if (pluginId === 'jwt') {
      const hasJwtHint =
        /jwt|bearer|oauth|openid/.test(blob) ||
        (surface.authEndpoints || []).length > 0 ||
        (surface.storageKeys || []).some((k) => /token|jwt|auth/i.test(String(k)));
      // Never skip solely on missing hints — tokens often appear only after login.
      void hasJwtHint;
    }

    // LFI plugin seeds common file/path/page params itself — do not skip lightly.
    // Only skip in passive mode (handled via PASSIVE_BLOCKED_PLUGINS).

    return null;
  }

  private hasWaf(fingerprint: Record<string, unknown>): boolean {
    const text = JSON.stringify(fingerprint || {}).toLowerCase();
    return /cloudflare|akamai|imperva|aws.?waf|sucuri|waf/.test(text);
  }
}
