import { describe, it, expect } from 'vitest';
import path from 'path';
import { CISBenchmarkManager, BenchmarkLoadError } from '../../src/compliance/cis/CISBenchmarkManager';
import { CISBenchmarkRegistry } from '../../src/compliance/cis/CISBenchmarkRegistry';
import { createLogger } from '../../src/platform/core/logging/logger';

const BENCHMARKS_DIR = path.join(__dirname, '..', '..', 'src', 'benchmarks');

describe('CISBenchmarkManager', () => {
  it('loads the shipped example CIS Ubuntu Linux benchmark', async () => {
    const manager = new CISBenchmarkManager(BENCHMARKS_DIR, createLogger('test', 'error'));
    const benchmark = await manager.loadBenchmark('cis-ubuntu-linux', '1.0.0');

    expect(benchmark.benchmarkId).toBe('cis-ubuntu-linux');
    expect(benchmark.platform).toBe('ubuntu-linux');
    expect(benchmark.controls.length).toBeGreaterThan(0);
    expect(benchmark.controls.every((c) => c.controlId && c.title)).toBe(true);
  });

  it('caches loaded benchmarks via the registry', async () => {
    const registry = new CISBenchmarkRegistry();
    const manager = new CISBenchmarkManager(BENCHMARKS_DIR, createLogger('test', 'error'), registry);
    const first = await manager.loadBenchmark('cis-ubuntu-linux', '1.0.0');
    const second = await manager.loadBenchmark('cis-ubuntu-linux', '1.0.0');
    expect(second).toBe(first);
    expect(registry.get('cis-ubuntu-linux', '1.0.0')).toBe(first);
  });

  it('throws BenchmarkLoadError for a missing benchmark', async () => {
    const manager = new CISBenchmarkManager(BENCHMARKS_DIR, createLogger('test', 'error'));
    await expect(manager.loadBenchmark('does-not-exist', '9.9.9')).rejects.toThrow(BenchmarkLoadError);
  });

  it('throws BenchmarkLoadError for malformed control files', async () => {
    const manager = new CISBenchmarkManager(
      path.join(__dirname, 'fixtures', 'malformed-benchmarks'),
      createLogger('test', 'error'),
    );
    await expect(manager.loadBenchmark('bad-benchmark', '1.0.0')).rejects.toThrow(BenchmarkLoadError);
  });

  it('lists available benchmarks on disk', async () => {
    const manager = new CISBenchmarkManager(BENCHMARKS_DIR, createLogger('test', 'error'));
    const list = await manager.listAvailable();
    expect(list.some((b) => b.benchmarkId === 'cis-ubuntu-linux' && b.version === '1.0.0')).toBe(true);
  });
});

describe('CISBenchmarkRegistry', () => {
  it('registers and retrieves by benchmarkId + version', () => {
    const registry = new CISBenchmarkRegistry();
    const benchmark = {
      benchmarkId: 'x',
      name: 'X',
      version: '1.0.0',
      platform: 'ubuntu-linux' as const,
      profile: 'server-level-1',
      controls: [],
    };
    registry.register(benchmark);
    expect(registry.get('x', '1.0.0')).toBe(benchmark);
    expect(registry.get('x', '2.0.0')).toBeUndefined();
    expect(registry.list()).toHaveLength(1);
  });
});
