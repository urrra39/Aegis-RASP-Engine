export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

let currentLevel: LogLevel = 'info';

export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

function shouldLog(level: LogLevel): boolean {
  return LEVELS[level] >= LEVELS[currentLevel];
}

function timestamp(): string {
  return new Date().toISOString();
}

export const logger = {
  debug(msg: string, meta?: Record<string, unknown>): void {
    if (shouldLog('debug')) {
      console.debug(`[${timestamp()}] [AEGIS:DEBUG] ${msg}`, meta ?? '');
    }
  },
  info(msg: string, meta?: Record<string, unknown>): void {
    if (shouldLog('info')) {
      console.info(`[${timestamp()}] [AEGIS:INFO] ${msg}`, meta ?? '');
    }
  },
  warn(msg: string, meta?: Record<string, unknown>): void {
    if (shouldLog('warn')) {
      console.warn(`[${timestamp()}] [AEGIS:WARN] ${msg}`, meta ?? '');
    }
  },
  error(msg: string, meta?: Record<string, unknown>): void {
    if (shouldLog('error')) {
      console.error(`[${timestamp()}] [AEGIS:ERROR] ${msg}`, meta ?? '');
    }
  },
};
