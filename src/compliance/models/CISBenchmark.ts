import type { ComplianceControl } from './ComplianceControl';

export interface CISBenchmark {
  benchmarkId: string;
  name: string;
  version: string;
  platform: 'ubuntu-linux';
  profile: string;
  controls: ComplianceControl[];
}

export interface CISBenchmarkSummary {
  benchmarkId: string;
  name: string;
  version: string;
  platform: string;
  profile: string;
  controlCount: number;
}
