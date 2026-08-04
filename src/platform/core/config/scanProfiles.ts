export type ScanProfileId = 'quick' | 'standard' | 'deep';

export interface ScanProfileOverrides {
  id: ScanProfileId;
  label: string;
  description: string;
  discovery: {
    maxPagesCrawl: number;
    maxOpenApiPaths: number;
    maxSitemapUrls: number;
    authMaxPagesCrawl: number;
    authRecrawl: boolean;
    scriptScanLimit: number;
    pageSettleMs: number;
    homeSettleMs: number;
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
    description: 'Faster pass — fewer pages/probes, good for smoke checks (~2–4 min).',
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
    description: 'Balanced precision vs speed (default).',
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
    description: 'Broader crawl and probes — slower, more coverage.',
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
};

export function resolveScanProfile(id?: string | null): ScanProfileOverrides {
  const key = String(id || 'standard').toLowerCase() as ScanProfileId;
  return SCAN_PROFILES[key] || SCAN_PROFILES.standard;
}

/** Merge profile knobs into a shallow copy of platform config for one scan. */
export function applyProfileToConfig(
  config: Record<string, any>,
  profileId?: string | null,
): { config: Record<string, any>; profile: ScanProfileOverrides } {
  const profile = resolveScanProfile(profileId);
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
