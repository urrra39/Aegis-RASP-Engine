/**
 * Strict CORS middleware.
 *
 * - Never uses Access-Control-Allow-Origin: *
 * - Only reflects origin if it is in the explicit allowlist
 * - Credentials require explicit opt-in per origin
 */

import { IncomingMessage, ServerResponse } from 'http';

export interface CorsOptions {
  allowedOrigins: string[];
  allowedMethods?: string[];
  allowedHeaders?: string[];
  allowCredentials?: boolean;
  maxAge?: number;
}

export function corsMiddleware(options: CorsOptions) {
  const {
    allowedOrigins,
    allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders = ['Content-Type', 'Authorization'],
    allowCredentials = false,
    maxAge = 86400,
  } = options;

  return (
    req: IncomingMessage,
    res: ServerResponse,
    next: () => void
  ): void => {
    const origin = req.headers.origin;

    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');

      if (allowCredentials) {
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }
    }

    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains'
    );

    // Preflight
    if (req.method === 'OPTIONS') {
      res.setHeader(
        'Access-Control-Allow-Methods',
        allowedMethods.join(', ')
      );
      res.setHeader(
        'Access-Control-Allow-Headers',
        allowedHeaders.join(', ')
      );
      res.setHeader('Access-Control-Max-Age', String(maxAge));
      res.writeHead(204);
      res.end();
      return;
    }

    next();
  };
}
