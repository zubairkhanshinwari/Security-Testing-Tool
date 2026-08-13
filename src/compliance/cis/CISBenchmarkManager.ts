import fs from 'fs';
import path from 'path';
import type { Logger } from '../../platform/core/logging/logger';
import type { CISBenchmark, CISBenchmarkSummary } from '../models/CISBenchmark';
import type { ComplianceControl } from '../models/ComplianceControl';
import { CISBenchmarkRegistry } from './CISBenchmarkRegistry';

export class BenchmarkLoadError extends Error {
  constructor(
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'BenchmarkLoadError';
  }
}

/**
 * Loads CIS benchmark definitions from disk (data-driven — never hardcoded
 * control logic in TS). Benchmark content lives under:
 *   <benchmarksDir>/<benchmarkId>/<version>/benchmark.meta.json
 *   <benchmarksDir>/<benchmarkId>/<version>/controls/*.json  (one or many files, each an array of controls)
 *
 * Distribution note: this loader ships empty of proprietary CIS text. Operators
 * populate the controls/ directory themselves from their own licensed CIS
 * benchmark export. See src/benchmarks/cis-ubuntu-linux/README.md.
 */
export class CISBenchmarkManager {
  constructor(
    private readonly benchmarksDir: string,
    private readonly logger: Logger,
    private readonly registry: CISBenchmarkRegistry = new CISBenchmarkRegistry(),
  ) {}

  async loadBenchmark(benchmarkId: string, version: string): Promise<CISBenchmark> {
    const cached = this.registry.get(benchmarkId, version);
    if (cached) return cached;

    const baseDir = path.join(this.benchmarksDir, benchmarkId, version);
    const metaPath = path.join(baseDir, 'benchmark.meta.json');
    if (!fs.existsSync(metaPath)) {
      throw new BenchmarkLoadError(
        `Benchmark not found: ${benchmarkId}@${version} (expected ${metaPath})`,
      );
    }

    let meta: Omit<CISBenchmark, 'controls'>;
    try {
      meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    } catch (err) {
      throw new BenchmarkLoadError(`Malformed benchmark.meta.json for ${benchmarkId}@${version}`, err);
    }

    const controls = this.loadControls(path.join(baseDir, 'controls'), benchmarkId, version);

    const benchmark: CISBenchmark = { ...meta, controls };
    this.registry.register(benchmark);
    this.logger.info('Benchmark loaded', {
      benchmarkId,
      version,
      controls: controls.length,
    });
    return benchmark;
  }

  async listAvailable(): Promise<CISBenchmarkSummary[]> {
    if (!fs.existsSync(this.benchmarksDir)) return [];
    const summaries: CISBenchmarkSummary[] = [];
    for (const benchmarkId of fs.readdirSync(this.benchmarksDir)) {
      const idDir = path.join(this.benchmarksDir, benchmarkId);
      if (!fs.statSync(idDir).isDirectory()) continue;
      for (const version of fs.readdirSync(idDir)) {
        const metaPath = path.join(idDir, version, 'benchmark.meta.json');
        if (!fs.existsSync(metaPath)) continue;
        try {
          const benchmark = await this.loadBenchmark(benchmarkId, version);
          summaries.push({
            benchmarkId: benchmark.benchmarkId,
            name: benchmark.name,
            version: benchmark.version,
            platform: benchmark.platform,
            profile: benchmark.profile,
            controlCount: benchmark.controls.length,
          });
        } catch (err) {
          this.logger.warn('Skipping unloadable benchmark', {
            benchmarkId,
            version,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    }
    return summaries;
  }

  private loadControls(controlsDir: string, benchmarkId: string, version: string): ComplianceControl[] {
    if (!fs.existsSync(controlsDir)) {
      throw new BenchmarkLoadError(
        `No controls directory for ${benchmarkId}@${version} (expected ${controlsDir})`,
      );
    }
    const controls: ComplianceControl[] = [];
    const files = fs.readdirSync(controlsDir).filter((f) => f.endsWith('.json'));
    for (const file of files) {
      const filePath = path.join(controlsDir, file);
      let parsed: unknown;
      try {
        parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      } catch (err) {
        throw new BenchmarkLoadError(`Malformed control file: ${filePath}`, err);
      }
      const items = Array.isArray(parsed) ? parsed : [parsed];
      for (const item of items) {
        validateControlShape(item, filePath);
        controls.push(item as ComplianceControl);
      }
    }
    return controls;
  }
}

function validateControlShape(item: unknown, filePath: string): void {
  const c = item as Partial<ComplianceControl> | null;
  if (!c || typeof c !== 'object') {
    throw new BenchmarkLoadError(`Invalid control entry in ${filePath}`);
  }
  if (!c.controlId || !c.title || typeof c.automated !== 'boolean' || !c.remediationMetadata) {
    throw new BenchmarkLoadError(
      `Control in ${filePath} is missing required fields (controlId/title/automated/remediationMetadata)`,
    );
  }
}
