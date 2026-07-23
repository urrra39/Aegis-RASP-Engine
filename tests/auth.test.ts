import { IncomingMessage, ServerResponse } from 'http';
import { authMiddleware } from '../src/middleware/auth';

function mockReq(authHeader?: string): IncomingMessage {
  return {
    headers: authHeader ? { authorization: authHeader } : {},
    url: '/test',
    socket: { remoteAddress: '127.0.0.1' },
  } as unknown as IncomingMessage;
}

function mockRes() {
  let statusCode = 200;
  let body = '';
  return {
    get statusCode() { return statusCode; },
    get body() { return body; },
    writeHead(code: number) {
      statusCode = code;
    },
    end(data?: string) {
      body = data ?? '';
    },
    setHeader() {},
  } as unknown as ServerResponse & { statusCode: number; body: string };
}

describe('Auth Middleware', () => {
  const middleware = authMiddleware('test-secret-token');

  it('passes with correct Bearer token', () => {
    const req = mockReq('Bearer test-secret-token');
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('rejects missing authorization header', () => {
    const req = mockReq();
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects invalid token', () => {
    const req = mockReq('Bearer wrong-token-value');
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects non-Bearer auth scheme', () => {
    const req = mockReq('Basic dXNlcjpwYXNz');
    const res = mockRes();
    const next = jest.fn();

    middleware(req, res, next);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });
});
