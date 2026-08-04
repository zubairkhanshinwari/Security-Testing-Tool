import { EventEmitter } from 'events';
import type { RiskSummary } from '../../core/types/finding';

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface ManagedJob {
  id: string;
  status: JobStatus;
  progress: { stage: string; message: string; percent?: number };
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  targetUrl?: string;
  projectName?: string;
  projectId?: string;
  error?: string;
  stats?: Record<string, unknown>;
  meta?: Record<string, unknown>;
  risk?: RiskSummary | Record<string, unknown>;
  files?: Record<string, string>;
  cancelRequested?: boolean;
  abortController: AbortController;
}

/**
 * In-process job controller: concurrency limits, cancel flags, job registry.
 * Phase-1 foundation for durable/distributed queues later.
 */
export class JobController extends EventEmitter {
  private readonly jobs = new Map<string, ManagedJob>();
  private running = 0;
  private readonly queue: Array<() => void> = [];

  constructor(private readonly maxConcurrent = 1) {
    super();
  }

  create(partial: Omit<ManagedJob, 'status' | 'progress' | 'createdAt' | 'abortController' | 'cancelRequested'>): ManagedJob {
    const job: ManagedJob = {
      ...partial,
      status: 'queued',
      progress: { stage: 'queued', message: 'Queued' },
      createdAt: new Date().toISOString(),
      cancelRequested: false,
      abortController: new AbortController(),
    };
    this.jobs.set(job.id, job);
    return job;
  }

  get(id: string): ManagedJob | undefined {
    return this.jobs.get(id);
  }

  list() {
    return [...this.jobs.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  runningJobs() {
    return this.list().filter((j) => j.status === 'running' || j.status === 'queued');
  }

  requestCancel(id: string): boolean {
    const job = this.jobs.get(id);
    if (!job) return false;
    if (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled') {
      return false;
    }
    job.cancelRequested = true;
    job.abortController.abort();
    job.progress = { stage: 'cancel', message: 'Cancellation requested…' };
    this.emit('cancel', job.id);
    return true;
  }

  update(id: string, patch: Partial<ManagedJob>) {
    const job = this.jobs.get(id);
    if (!job) return;
    Object.assign(job, patch);
  }

  /**
   * Run work under concurrency limit. Rejects if already cancelled before start.
   */
  async runLimited<T>(jobId: string, work: (signal: AbortSignal) => Promise<T>): Promise<T> {
    await this.acquire(jobId);
    const job = this.jobs.get(jobId);
    if (!job) throw new Error('Job not found');
    if (job.cancelRequested) {
      job.status = 'cancelled';
      job.finishedAt = new Date().toISOString();
      this.release();
      throw new Error('Scan cancelled');
    }
    job.status = 'running';
    job.startedAt = new Date().toISOString();
    try {
      return await work(job.abortController.signal);
    } finally {
      this.release();
    }
  }

  private acquire(jobId: string): Promise<void> {
    if (this.running < this.maxConcurrent) {
      this.running += 1;
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      this.queue.push(() => {
        const job = this.jobs.get(jobId);
        if (job?.cancelRequested) {
          resolve();
          return;
        }
        this.running += 1;
        resolve();
      });
    });
  }

  private release() {
    this.running = Math.max(0, this.running - 1);
    const next = this.queue.shift();
    if (next) next();
  }

  toPublic(job: ManagedJob) {
    const { abortController, cancelRequested, ...rest } = job;
    return { ...rest, cancelRequested: Boolean(cancelRequested) };
  }
}
