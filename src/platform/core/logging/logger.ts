export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export class Logger {
  constructor(
    private readonly name: string,
    private readonly level: LogLevel = 'info',
    private readonly json = false,
  ) {}

  child(name: string): Logger {
    return new Logger(`${this.name}:${name}`, this.level, this.json);
  }

  private emit(level: LogLevel, message: string, meta?: Record<string, unknown>): void {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[this.level]) return;
    const entry = {
      ts: new Date().toISOString(),
      level,
      component: this.name,
      message,
      ...meta,
    };
    const line = this.json ? JSON.stringify(entry) : `[${entry.ts}] ${level.toUpperCase()} [${this.name}] ${message}`;
    if (level === 'error') console.error(this.json ? line : line, meta || '');
    else if (level === 'warn') console.warn(this.json ? line : line, meta || '');
    else console.log(this.json ? line : line);
  }

  debug(message: string, meta?: Record<string, unknown>): void {
    this.emit('debug', message, meta);
  }
  info(message: string, meta?: Record<string, unknown>): void {
    this.emit('info', message, meta);
  }
  warn(message: string, meta?: Record<string, unknown>): void {
    this.emit('warn', message, meta);
  }
  error(message: string, meta?: Record<string, unknown>): void {
    this.emit('error', message, meta);
  }
}

export function createLogger(name: string, level: LogLevel = 'info', json = false): Logger {
  return new Logger(name, level, json);
}
