import fs from 'fs';
import path from 'path';
import type { PluginManifest } from '../core/types/finding';
import type { SecurityPlugin } from '../core/types/plugin';
import type { Logger } from '../core/logging/logger';

/**
 * Auto-discovers plugins from modules/<name>/manifest.json and loads scanner entrypoints.
 */
export class PluginManager {
  private plugins: SecurityPlugin[] = [];

  constructor(
    private readonly modulesDir: string,
    private readonly logger: Logger,
    private readonly disabled: string[] = [],
  ) {}

  async autoRegister(): Promise<SecurityPlugin[]> {
    this.plugins = [];
    if (!fs.existsSync(this.modulesDir)) {
      this.logger.warn('Plugins directory missing', { modulesDir: this.modulesDir });
      return [];
    }

    const entries = fs.readdirSync(this.modulesDir, { withFileTypes: true });
    for (const ent of entries) {
      if (!ent.isDirectory()) continue;
      const dir = path.join(this.modulesDir, ent.name);
      const manifestPath = path.join(dir, 'manifest.json');
      if (!fs.existsSync(manifestPath)) continue;

      try {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as PluginManifest;
        if (this.disabled.includes(manifest.id)) {
          this.logger.info('Plugin disabled by config', { id: manifest.id });
          continue;
        }

        const plugin = await this.loadPlugin(dir, manifest);
        if (plugin) {
          this.plugins.push(plugin);
          this.logger.info('Registered plugin', { id: manifest.id, name: manifest.name });
        }
      } catch (err: any) {
        this.logger.error('Failed to register plugin', {
          dir: ent.name,
          error: err?.message || String(err),
        });
      }
    }

    return this.plugins;
  }

  private async loadPlugin(dir: string, manifest: PluginManifest): Promise<SecurityPlugin | null> {
    // Prefer compiled/TS via require of scanner.js or scanner.ts through tsx register
    const candidates = ['scanner.js', 'scanner.ts', 'index.js', 'index.ts'];
    for (const file of candidates) {
      const full = path.join(dir, file);
      if (!fs.existsSync(full)) continue;
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require(full);
      const factory = mod.createPlugin || mod.default || mod.plugin;
      if (typeof factory === 'function') {
        const plugin = factory(manifest);
        if (plugin?.manifest) return plugin;
        return { ...plugin, manifest };
      }
      if (mod && mod.manifest && typeof mod.scan === 'function') {
        return mod as SecurityPlugin;
      }
    }
    this.logger.warn('No scanner entry for plugin', { id: manifest.id, dir });
    return null;
  }

  list(): SecurityPlugin[] {
    return [...this.plugins];
  }

  resolveForTypes(selectedTypes: string[], explicitIds?: string[]): SecurityPlugin[] {
    if (explicitIds?.length) {
      return this.plugins.filter((p) => explicitIds.includes(p.manifest.id));
    }
    if (!selectedTypes?.length) {
      return this.plugins.filter((p) => p.manifest.enabledByDefault || p.manifest.recommended);
    }
    const set = new Set(selectedTypes);

    // If the caller selected a very broad set (Select All), run every registered plugin.
    // Threshold: more unique type ids than a typical recommended pack (~20).
    if (set.size >= 30) {
      return [...this.plugins];
    }

    // Match any overlapping type id; OWASP bundle also pulls recommended plugins.
    return this.plugins.filter((p) => {
      if (p.manifest.securityTypeIds.some((id) => set.has(id))) return true;
      if (set.has('owasp_top10') && (p.manifest.recommended || p.manifest.enabledByDefault)) {
        return true;
      }
      return false;
    });
  }
}
