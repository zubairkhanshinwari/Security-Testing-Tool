import type { CISBenchmark, CISBenchmarkSummary } from '../models/CISBenchmark';

/**
 * In-memory registry of loaded benchmarks, keyed by "benchmarkId@version".
 * CISBenchmarkManager populates this from disk; the registry itself has no
 * filesystem knowledge, which keeps it trivially unit-testable.
 */
export class CISBenchmarkRegistry {
  private readonly benchmarks = new Map<string, CISBenchmark>();

  register(benchmark: CISBenchmark): void {
    this.benchmarks.set(key(benchmark.benchmarkId, benchmark.version), benchmark);
  }

  get(benchmarkId: string, version: string): CISBenchmark | undefined {
    return this.benchmarks.get(key(benchmarkId, version));
  }

  list(): CISBenchmarkSummary[] {
    return [...this.benchmarks.values()].map((b) => ({
      benchmarkId: b.benchmarkId,
      name: b.name,
      version: b.version,
      platform: b.platform,
      profile: b.profile,
      controlCount: b.controls.length,
    }));
  }

  clear(): void {
    this.benchmarks.clear();
  }
}

function key(benchmarkId: string, version: string): string {
  return `${benchmarkId}@${version}`;
}
