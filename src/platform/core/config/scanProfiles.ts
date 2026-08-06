export type ScanProfileId = 'quick' | 'standard' | 'deep' | 'focused' | 'openapi';

export interface ScanProfileOverrides {
  id: ScanProfileId;
  label: string;
  description: string;
  /** Soft ETA for UI / operators (minutes) */
  etaMinutes: { min: number; max: number };
  discovery: {
    maxPagesCrawl: number;
    maxOpenApiPaths: number;
    maxSitemapUrls: number;
    authMaxPagesCrawl: number;
    authRecrawl: boolean;
    scriptScanLimit: number;
    pageSettleMs: number;
    homeSettleMs: number;
    /** Prefer user/OpenAPI seeds over broad crawl */
    prioritizeFocusSeeds?: boolean;
    /** Prefer OpenAPI-derived endpoints for API-heavy apps */
    prioritizeOpenApi?: boolean;
  };
  safety: {
    requestTimeoutMs: number;
    maxConcurrentProbes: number;
  };
}

export const SCAN_PROFILES: Record<ScanProfileId, ScanProfileOverrides> = {
  quick: {
    id: 'quick',
    label: 'Quick',
    description: 'Smoke check — shallow crawl, fewer probes. Best for CI / plumbing validation.',
    etaMinutes: { min: 2, max: 4 },
    discovery: {
      maxPagesCrawl: 4,
      maxOpenApiPaths: 12,
      maxSitemapUrls: 8,
      authMaxPagesCrawl: 2,
      authRecrawl: false,
      scriptScanLimit: 4,
      pageSettleMs: 250,
      homeSettleMs: 500,
    },
    safety: { requestTimeoutMs: 8000, maxConcurrentProbes: 6 },
  },
  standard: {
    id: 'standard',
    label: 'Standard',
    description: 'Balanced coverage vs speed — default for most assessments.',
    etaMinutes: { min: 4, max: 10 },
    discovery: {
      maxPagesCrawl: 8,
      maxOpenApiPaths: 30,
      maxSitemapUrls: 15,
      authMaxPagesCrawl: 4,
      authRecrawl: true,
      scriptScanLimit: 6,
      pageSettleMs: 350,
      homeSettleMs: 700,
    },
    safety: { requestTimeoutMs: 10000, maxConcurrentProbes: 6 },
  },
  deep: {
    id: 'deep',
    label: 'Deep',
    description:
      'Broader crawl/OpenAPI/probes. Slower — expect 15–30+ minutes on large apps. May still miss obscure routes; add Focus routes for critical areas.',
    etaMinutes: { min: 15, max: 35 },
    discovery: {
      maxPagesCrawl: 16,
      maxOpenApiPaths: 60,
      maxSitemapUrls: 30,
      authMaxPagesCrawl: 8,
      authRecrawl: true,
      scriptScanLimit: 10,
      pageSettleMs: 450,
      homeSettleMs: 900,
    },
    safety: { requestTimeoutMs: 15000, maxConcurrentProbes: 4 },
  },
  openapi: {
    id: 'openapi',
    label: 'OpenAPI-first',
    description:
      'API-heavy apps (e.g. Falaya): prioritize OpenAPI/Swagger paths, shallow HTML crawl. Provide OpenAPI URL when possible.',
    etaMinutes: { min: 8, max: 25 },
    discovery: {
      maxPagesCrawl: 4,
      maxOpenApiPaths: 120,
      maxSitemapUrls: 8,
      authMaxPagesCrawl: 4,
      authRecrawl: true,
      scriptScanLimit: 6,
      pageSettleMs: 350,
      homeSettleMs: 700,
      prioritizeFocusSeeds: true,
      prioritizeOpenApi: true,
    },
    safety: { requestTimeoutMs: 12000, maxConcurrentProbes: 5 },
  },
  focused: {
    id: 'focused',
    label: 'Focused',
    description:
      'Spend budget on your Focus routes / OpenAPI URL. Shallow site crawl; best when you know high-value paths.',
    etaMinutes: { min: 3, max: 12 },
    discovery: {
      maxPagesCrawl: 3,
      maxOpenApiPaths: 80,
      maxSitemapUrls: 5,
      authMaxPagesCrawl: 3,
      authRecrawl: true,
      scriptScanLimit: 4,
      pageSettleMs: 300,
      homeSettleMs: 600,
      prioritizeFocusSeeds: true,
    },
    safety: { requestTimeoutMs: 12000, maxConcurrentProbes: 5 },
  },
};

export function resolveScanProfile(id?: string | null): ScanProfileOverrides {
  const key = String(id || 'standard').toLowerCase() as ScanProfileId;
  return SCAN_PROFILES[key] || SCAN_PROFILES.standard;
}

export function profileEtaLabel(profile: ScanProfileOverrides): string {
  const { min, max } = profile.etaMinutes;
  return min === max ? `~${min} min` : `~${min}–${max} min`;
}

/** Merge profile knobs into a shallow copy of platform config for one scan. */
export function applyProfileToConfig(
  config: Record<string, any>,
  profileId?: string | null,
  opts?: { openApiUrl?: string | null },
): { config: Record<string, any>; profile: ScanProfileOverrides } {
  let profile = resolveScanProfile(profileId);
  // Deep + explicit OpenAPI URL → boost OpenAPI path budget (keep profile id = deep)
  if (profile.id === 'deep' && opts?.openApiUrl) {
    const oapi = SCAN_PROFILES.openapi;
    profile = {
      ...profile,
      label: 'Deep',
      description: `${profile.description} OpenAPI URL detected — prioritizing API paths within Deep.`,
      discovery: {
        ...profile.discovery,
        maxOpenApiPaths: Math.max(profile.discovery.maxOpenApiPaths, oapi.discovery.maxOpenApiPaths),
        maxPagesCrawl: Math.min(profile.discovery.maxPagesCrawl, 8),
        prioritizeFocusSeeds: true,
        prioritizeOpenApi: true,
      },
    };
  }
  const next = {
    ...config,
    safety: { ...(config.safety || {}), ...profile.safety },
    scan: {
      ...(config.scan || {}),
      discovery: {
        ...(config.scan?.discovery || {}),
        ...profile.discovery,
      },
      profile: profile.id,
    },
  };
  return { config: next, profile };
}

/** Normalize user-supplied focus paths/URLs against the scan target. */
export function normalizeFocusEndpoints(
  targetUrl: string,
  raw: unknown,
  { limit = 40 }: { limit?: number } = {},
): string[] {
  if (!raw) return [];
  const list = Array.isArray(raw)
    ? raw
    : String(raw)
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
  const out: string[] = [];
  const seen = new Set<string>();
  let origin: string;
  try {
    origin = new URL(targetUrl).origin;
  } catch {
    return [];
  }
  for (const item of list) {
    if (out.length >= limit) break;
    const s = String(item).trim();
    if (!s) continue;
    try {
      let href: string;
      if (/^https?:\/\//i.test(s)) href = new URL(s).href;
      else if (s.startsWith('/')) href = new URL(s, origin).href;
      else href = new URL(`/${s}`, origin).href;
      const u = new URL(href);
      // Keep related hosts (api. sibling) but drop obvious third parties
      if (u.origin !== origin && !u.hostname.endsWith(origin.replace(/^https?:\/\//, '').split(':')[0])) {
        const baseHost = new URL(origin).hostname.replace(/^www\./, '');
        const root = baseHost.split('.').slice(-2).join('.');
        if (!u.hostname.endsWith(root)) continue;
      }
      const key = u.href.split('#')[0];
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(key);
    } catch {
      /* skip */
    }
  }
  return out;
}
