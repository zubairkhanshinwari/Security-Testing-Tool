import { describe, it, expect } from 'vitest';
import { JobController } from '../src/platform/engines/jobs/JobController';

describe('JobController', () => {
  it('cancels a queued/running job', async () => {
    const jc = new JobController(1);
    const job = jc.create({ id: 'j1', targetUrl: 'https://example.com' });
    expect(jc.requestCancel('j1')).toBe(true);
    expect(job.cancelRequested).toBe(true);
    expect(job.abortController.signal.aborted).toBe(true);
  });

  it('limits concurrency', async () => {
    const jc = new JobController(1);
    jc.create({ id: 'a' });
    jc.create({ id: 'b' });
    let aStarted = false;
    let bStarted = false;
    const p1 = jc.runLimited('a', async () => {
      aStarted = true;
      await new Promise((r) => setTimeout(r, 80));
      return 1;
    });
    await new Promise((r) => setTimeout(r, 10));
    const p2 = jc.runLimited('b', async () => {
      bStarted = true;
      return 2;
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(aStarted).toBe(true);
    expect(bStarted).toBe(false);
    await p1;
    await p2;
    expect(bStarted).toBe(true);
  });
});
