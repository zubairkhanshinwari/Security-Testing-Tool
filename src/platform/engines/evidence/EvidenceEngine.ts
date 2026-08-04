import path from 'path';
import type { Finding, Severity } from '../../core/types/finding';
import type { Logger } from '../../core/logging/logger';
import { ScreenshotEvidence, isScreenshotEligible } from './ScreenshotEvidence';

const DEFAULT_EVIDENCE_SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low'];
const VERIFIED_STATUSES = new Set(['Confirmed', 'Likely', 'Possible']);

export interface EvidenceOptions {
  page?: any;
  findings: Finding[];
  targetUrl: string;
  outDir: string;
  /** Prefer existing page (scan). If omitted, standalone browser is used. */
  standalone?: boolean;
}

/**
 * Evidence Engine — collect screenshots (and future HAR/DOM) only after verification.
 * Never captures for Pass / Informational-only noise when onlyVerified is enabled.
 */
export class EvidenceEngine {
  private readonly shots: ScreenshotEvidence;

  constructor(
    private readonly logger: Logger,
    private readonly config: Record<string, any> = {},
  ) {
    this.shots = new ScreenshotEvidence(logger.child('screenshots'));
  }

  /** Findings eligible for visual/HTTP evidence capture after verification. */
  selectEligible(findings: Finding[]): Finding[] {
    const onlyVerified = this.config.reporting?.evidence?.onlyVerified !== false;
    const severities = new Set<Severity>(
      (this.config.reporting?.evidence?.severities as Severity[]) || DEFAULT_EVIDENCE_SEVERITIES,
    );

    return findings.filter((f) => {
      if (!f.issueFound) return false;
      if (!severities.has(f.severity as Severity)) return false;
      if (!isScreenshotEligible(f)) return false;
      if (onlyVerified && !VERIFIED_STATUSES.has(String(f.status))) return false;
      // Skip pure informational confidence with no real issue weight
      if (f.confidence === 'Informational' && f.severity === 'Informational') return false;
      return true;
    });
  }

  async collect(options: EvidenceOptions): Promise<Finding[]> {
    if (this.config.reporting?.includeScreenshots === false) {
      this.logger.info('Evidence capture disabled by config');
      return options.findings;
    }

    const eligible = this.selectEligible(options.findings);
    this.logger.info('Evidence collection', {
      total: options.findings.length,
      eligible: eligible.length,
      onlyVerified: this.config.reporting?.evidence?.onlyVerified !== false,
    });

    if (!eligible.length) return options.findings;

    // Capture only eligible issues, then merge screenshot fields back by id
    let captured: Finding[];
    if (options.page && !options.standalone) {
      captured = await this.shots.captureForFindings(
        options.page,
        eligible,
        options.targetUrl,
        options.outDir,
      );
    } else {
      captured = await this.shots.captureStandalone(
        eligible,
        options.targetUrl,
        options.outDir,
      );
    }

    const byId = new Map(captured.map((f) => [f.id, f]));
    return options.findings.map((f) => {
      const c = byId.get(f.id);
      if (!c) return f;
      return {
        ...f,
        screenshotPath: c.screenshotPath ?? f.screenshotPath,
        screenshotFileName: c.screenshotFileName ?? f.screenshotFileName,
        screenshotCaption: c.screenshotCaption ?? f.screenshotCaption,
        screenshotBase64: c.screenshotBase64 ?? f.screenshotBase64,
        screenshotLiveBase64: c.screenshotLiveBase64 ?? f.screenshotLiveBase64,
      };
    });
  }

  defaultOutDir(reportsDir: string, stamp: string): string {
    return path.join(reportsDir, 'screenshots', stamp);
  }
}

export { isScreenshotEligible };
