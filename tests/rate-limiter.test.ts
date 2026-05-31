import { IncomingMessage, ServerResponse } from 'http';
import { rateLimiter } from '../src/middleware/rate-limiter';

function mockReq(ip = '127.0.0.1'): IncomingMessage {
  return {
    socket: { remoteAddress: ip },
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
  } as unknown as ServerResponse & { statusCode: number; body: string };
}

describe('Rate Limiter', () => {
  it('allows requests within the limit', () => {
    const limiter = rateLimiter({ windowMs: 60_000, maxRequests: 5 });
    const next = jest.fn();

    for (let i = 0; i < 5; i++) {
      limiter(mockReq(), mockRes(), next);
    }

    expect(next).toHaveBeenCalledTimes(5);
  });

  it('blocks requests exceeding the limit', () => {
    const limiter = rateLimiter({ windowMs: 60_000, maxRequests: 2 });
    const next = jest.fn();

    for (let i = 0; i < 3; i++) {
      const res = mockRes();
      limiter(mockReq(), res, next);
      if (i === 2) {
        expect(res.statusCode).toBe(429);
      }
    }

    expect(next).toHaveBeenCalledTimes(2);
  });

  it('tracks different IPs independently', () => {
    const limiter = rateLimiter({ windowMs: 60_000, maxRequests: 1 });
    const next = jest.fn();

    limiter(mockReq('1.1.1.1'), mockRes(), next);
    limiter(mockReq('2.2.2.2'), mockRes(), next);

    expect(next).toHaveBeenCalledTimes(2);
  });
});
