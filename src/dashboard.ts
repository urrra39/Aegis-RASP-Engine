/**
 * Admin dashboard — protected HTTP server for monitoring the RASP agent.
 *
 * All endpoints require Bearer token authentication.
 * No debug endpoints are exposed in production.
 * CORS is strictly configured per the allowlist.
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { AegisConfig } from './config';
import { corsMiddleware, CorsOptions } from './middleware/cors';
import { authMiddleware } from './middleware/auth';
import { rateLimiter, RateLimitOptions } from './middleware/rate-limiter';
import { logger } from './utils/logger';
import { AegisEngine } from './engine';

type Middleware = (
  req: IncomingMessage,
  res: ServerResponse,
  next: () => void
) => void;

function runMiddlewareChain(
  middlewares: Middleware[],
  req: IncomingMessage,
  res: ServerResponse,
  handler: () => void
): void {
  let index = 0;
  function next(): void {
    if (index >= middlewares.length) {
      handler();
      return;
    }
    const mw = middlewares[index++];
    mw(req, res, next);
  }
  next();
}

function parseBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    const MAX_BODY = 1_048_576; // 1 MB

    req.on('data', (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY) {
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export interface DashboardOptions {
  port?: number;
  host?: string;
}

export function createDashboard(
  engine: AegisEngine,
  config: AegisConfig,
  options: DashboardOptions = {}
) {
  const { port = 9090, host = '127.0.0.1' } = options;

  const corsOpts: CorsOptions = {
    allowedOrigins: config.corsAllowedOrigins,
    allowCredentials: false,
  };

  const rateLimitOpts: RateLimitOptions = {
    windowMs: 60_000,
    maxRequests: 60,
  };

  const middlewares: Middleware[] = [
    corsMiddleware(corsOpts),
    rateLimiter(rateLimitOpts),
    authMiddleware(config.adminToken),
  ];

  const server = createServer((req, res) => {
    runMiddlewareChain(middlewares, req, res, async () => {
      try {
        await handleRoute(req, res, engine);
      } catch (err) {
        logger.error('Dashboard request error', {
          error: String(err),
          url: req.url,
        });
        if (!res.writableEnded) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Internal server error' }));
        }
      }
    });
  });

  return {
    start(): Promise<void> {
      return new Promise((resolve) => {
        server.listen(port, host, () => {
          logger.info(`Dashboard listening on ${host}:${port}`);
          resolve();
        });
      });
    },
    stop(): Promise<void> {
      return new Promise((resolve, reject) => {
        server.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    },
    server,
  };
}

async function handleRoute(
  req: IncomingMessage,
  res: ServerResponse,
  engine: AegisEngine
): Promise<void> {
  const url = req.url ?? '/';

  // Health check (no sensitive data)
  if (url === '/api/health' && req.method === 'GET') {
    json(res, 200, {
      status: 'ok',
      modules: {
        sqli: engine.config.enableSqliProtection,
        rce: engine.config.enableRceProtection,
        egress: engine.config.enableEgressFirewall,
      },
    });
    return;
  }

  // Config overview (redacted)
  if (url === '/api/config' && req.method === 'GET') {
    json(res, 200, {
      logLevel: engine.config.logLevel,
      enableSqliProtection: engine.config.enableSqliProtection,
      enableRceProtection: engine.config.enableRceProtection,
      enableEgressFirewall: engine.config.enableEgressFirewall,
      corsAllowedOrigins: engine.config.corsAllowedOrigins,
      allowedEgressHosts: engine.config.allowedEgressHosts,
      // adminToken is intentionally omitted
    });
    return;
  }

  // SQL injection check endpoint
  if (url === '/api/check/sql' && req.method === 'POST') {
    const body = await parseBody(req);
    let parsed: { query?: string };
    try {
      parsed = JSON.parse(body);
    } catch {
      json(res, 400, { error: 'Invalid JSON body' });
      return;
    }
    if (!parsed.query || typeof parsed.query !== 'string') {
      json(res, 400, { error: 'Missing "query" field (string)' });
      return;
    }
    const result = engine.checkSql(parsed.query);
    json(res, 200, {
      isMalicious: result.isMalicious,
      reasons: result.reasons,
    });
    return;
  }

  // 404
  json(res, 404, { error: 'Not found' });
}

function json(
  res: ServerResponse,
  status: number,
  data: Record<string, unknown>
): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}
