import type { ComplianceEvent, ComplianceEventHandler, ComplianceEventType } from './complianceEventTypes';

/**
 * Lightweight in-process event bus for the compliance pipeline.
 * Deliberately mirrors ScanEventBus's mechanism (Map-based on/emit/clear) as a
 * separate class/type union, rather than widening ScanEventType, so the DAST
 * event bus and its consumers are never touched. Pure pub/sub — no business logic.
 */
export class ComplianceEventBus {
  private readonly handlers = new Map<ComplianceEventType | '*', Set<ComplianceEventHandler>>();

  on(type: ComplianceEventType | '*', handler: ComplianceEventHandler): () => void {
    if (!this.handlers.has(type)) this.handlers.set(type, new Set());
    this.handlers.get(type)!.add(handler);
    return () => this.handlers.get(type)?.delete(handler);
  }

  emit<T = unknown>(type: ComplianceEventType, assessmentId: string, payload?: T): void {
    const event: ComplianceEvent<T> = {
      type,
      assessmentId,
      at: new Date().toISOString(),
      payload,
    };
    for (const handler of this.handlers.get(type) || []) {
      try {
        handler(event);
      } catch {
        /* subscriber errors must not break the assessment */
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
