/**
 * Authentication middleware for admin/dashboard endpoints.
 *
 * Uses constant-time comparison to prevent timing attacks.
 * Token is loaded from config — never hardcoded.
 */

import { IncomingMessage, ServerResponse } from 'http';
import { timingSafeEqual } from 'crypto';
import { logger } from '../utils/logger';

function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return timingSafeEqual(bufA, bufB);
}

export function authMiddleware(adminToken: string) {
  return (
    req: IncomingMessage,
    res: ServerResponse,
    next: () => void
  ): void => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      logger.warn('Missing authorization header', {
        url: req.url,
        ip: req.socket.remoteAddress,
      });
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Authentication required' }));
      return;
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid authorization format. Use: Bearer <token>' }));
      return;
    }

    const token = parts[1];
    if (!constantTimeCompare(token, adminToken)) {
      logger.warn('Invalid admin token', {
        url: req.url,
        ip: req.socket.remoteAddress,
      });
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Forbidden' }));
      return;
    }

    next();
  };
}
