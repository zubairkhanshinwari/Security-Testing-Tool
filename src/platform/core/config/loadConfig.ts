import fs from 'fs';
import path from 'path';

export interface AppConfig {
  app: { name: string; version: string; port: number };
  safety: Record<string, unknown>;
  scan: Record<string, unknown>;
  reporting: Record<string, unknown>;
  storage: {
    reportsDir: string;
    dataDir: string;
    projectsDir: string;
    scansDir: string;
  };
  plugins: { directory: string; autoRegister: boolean; disabled: string[] };
  logging: { level: string; json: boolean };
}

function deepMerge<T extends Record<string, any>>(base: T, overlay: Partial<T>): T {
  const out: any = { ...base };
  for (const [k, v] of Object.entries(overlay || {})) {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      out[k] = deepMerge(out[k] || {}, v as any);
    } else {
      out[k] = v;
    }
  }
  return out;
}

export function loadConfig(rootDir = process.cwd()): AppConfig {
  const defaultPath = path.join(rootDir, 'config', 'default.json');
  const envProfile = process.env.SECUREASSESS_ENV || process.env.NODE_ENV || 'development';
  const profilePath = path.join(rootDir, 'config', `${envProfile}.json`);

  const defaults = JSON.parse(fs.readFileSync(defaultPath, 'utf8')) as AppConfig;
  if (fs.existsSync(profilePath)) {
    const profile = JSON.parse(fs.readFileSync(profilePath, 'utf8'));
    return deepMerge(defaults, profile);
  }
  return defaults;
}
