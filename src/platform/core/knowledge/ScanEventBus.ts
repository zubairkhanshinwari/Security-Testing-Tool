export type ScanEventType =
  | 'stage.start'
  | 'stage.end'
  | 'page.found'
  | 'endpoint.found'
  | 'plan.created'
  | 'finding.draft'
  | 'finding.verified'
  | 'coverage.updated'
  | 'scan.error'
  | 'scan.done';

export interface ScanEvent<T = unknown> {
  type: ScanEventType;
  scanId: string;
  at: string;
  payload?: T;
}

export type ScanEventHandler = (event: ScanEvent) => void;

/**
 * Lightweight in-process event bus for scan engines.
 * Engines publish facts; listeners (planner, metrics, future workers) subscribe.
 */
export class ScanEventBus {
  private readonly handlers = new Map<ScanEventType | '*', Set<ScanEventHandler>>();

  on(type: ScanEventType | '*', handler: ScanEventHandler): () => void {
    if (!this.handlers.has(type)) this.handlers.set(type, new Set());
    this.handlers.get(type)!.add(handler);
    return () => this.handlers.get(type)?.delete(handler);
  }

  emit<T = unknown>(type: ScanEventType, scanId: string, payload?: T): void {
    const event: ScanEvent<T> = {
      type,
      scanId,
      at: new Date().toISOString(),
      payload,
    };
    for (const handler of this.handlers.get(type) || []) {
      try {
        handler(event);
      } catch {
        /* subscriber errors must not break the scan */
      }
    }
    for (const handler of this.handlers.get('*') || []) {
      try {
        handler(event);
      } catch {
        /* ignore */
      }
    }
  }

  clear(): void {
    this.handlers.clear();
  }
}
