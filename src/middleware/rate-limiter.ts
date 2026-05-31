/**
 * In-memory sliding-window rate limiter.
 * Protects endpoints from brute-force and abuse.
 */

import { IncomingMessage, ServerResponse } from 'http';
import { logger } from '../utils/logger';

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
}

export function rateLimiter(options: RateLimitOptions) {
  const { windowMs, maxRequests } = options;
  const store = new Map<string, RateLimitEntry>();

  // Periodic cleanup of stale entries
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of store) {
      if (now - entry.windowStart > windowMs * 2) {
        store.delete(key);
      }
    }
  }, windowMs);

  // Allow the process to exit even if interval is active
  if (cleanupInterval.unref) {
    cleanupInterval.unref();
  }

  return (
    req: IncomingMessage,
    res: ServerResponse,
    next: () => void
  ): void => {
    const ip = req.socket.remoteAddress ?? 'unknown';
    const now = Date.now();
    const entry = store.get(ip);

    if (!entry || now - entry.windowStart > windowMs) {
      store.set(ip, { count: 1, windowStart: now });
      next();
      return;
    }

    entry.count++;

    if (entry.count > maxRequests) {
      logger.warn('Rate limit exceeded', { ip, count: entry.count });
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Too many requests. Please try again later.',
        })
      );
      return;
    }

    next();
  };
}
