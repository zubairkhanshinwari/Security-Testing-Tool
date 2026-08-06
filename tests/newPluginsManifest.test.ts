import fs from 'fs';
import path from 'path';
import { describe, expect, it } from 'vitest';

const root = path.join(__dirname, '..', 'modules');

describe('new safe plugins', () => {
  for (const id of ['weak-password', 'file-upload', 'rate-limiting']) {
    it(`${id} has manifest + createPlugin`, async () => {
      const dir = path.join(root, id);
      const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
      expect(manifest.id).toBe(id);
      expect(manifest.securityTypeIds?.length).toBeGreaterThan(0);
      const mod = await import(path.join(dir, 'scanner.js'));
      expect(typeof mod.createPlugin).toBe('function');
      const plugin = mod.createPlugin(manifest);
      expect(plugin.manifest.id).toBe(id);
      expect(typeof plugin.discover).toBe('function');
      expect(typeof plugin.scan).toBe('function');
      expect(typeof plugin.verify).toBe('function');
    });
  }

  it('weak-password maps to weak_password type', () => {
    const m = JSON.parse(
      fs.readFileSync(path.join(root, 'weak-password', 'manifest.json'), 'utf8'),
    );
    expect(m.securityTypeIds).toContain('weak_password');
  });

  it('file-upload is safe-only (no exploit tags)', () => {
    const m = JSON.parse(fs.readFileSync(path.join(root, 'file-upload', 'manifest.json'), 'utf8'));
    expect(m.description.toLowerCase()).toMatch(/safe|non-destructive|does not upload malware/);
  });
});
