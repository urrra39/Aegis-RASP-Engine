import { IncomingMessage, ServerResponse } from 'http';
import { corsMiddleware } from '../src/middleware/cors';

function mockReq(overrides: Partial<IncomingMessage> = {}): IncomingMessage {
  return {
    headers: {},
    method: 'GET',
    ...overrides,
  } as IncomingMessage;
}

function mockRes() {
  const headers: Record<string, string> = {};
  const res = {
    headers,
    statusCode: 200,
    setHeader(name: string, value: string) {
      headers[name] = value;
    },
    writeHead(code: number) {
      res.statusCode = code;
    },
    end() {},
  };
  return res as unknown as ServerResponse & { headers: Record<string, string>; statusCode: number };
}

describe('CORS Middleware', () => {
  const middleware = corsMiddleware({
    allowedOrigins: ['https://app.example.com'],
  });

  it('sets CORS headers for allowed origin', () => {
    const req = mockReq({ headers: { origin: 'https://app.example.com' } });
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res.headers['Access-Control-Allow-Origin']).toBe('https://app.example.com');
    expect(res.headers['Vary']).toBe('Origin');
    expect(next).toHaveBeenCalled();
  });

  it('does not set CORS header for disallowed origin', () => {
    const req = mockReq({ headers: { origin: 'https://evil.com' } });
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res.headers['Access-Control-Allow-Origin']).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it('sets security headers always', () => {
    const req = mockReq();
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res.headers['X-Content-Type-Options']).toBe('nosniff');
    expect(res.headers['X-Frame-Options']).toBe('DENY');
  });

  it('handles preflight OPTIONS request', () => {
    const req = mockReq({
      method: 'OPTIONS',
      headers: { origin: 'https://app.example.com' },
    });
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res.statusCode).toBe(204);
    expect(next).not.toHaveBeenCalled();
  });
});
