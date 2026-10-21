import { HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { AuthRateLimitMiddleware } from './rate-limit.middleware';

function config(values: Record<string, string>): ConfigService {
  return {
    get: (key: string) => values[key],
  } as ConfigService;
}

function request(ip: string, query: Request['query'] = {}): Request {
  return {
    ip,
    query,
    headers: { 'x-forwarded-for': '203.0.113.50' },
    socket: { remoteAddress: ip },
  } as unknown as Request;
}

describe('AuthRateLimitMiddleware', () => {
  const limits = {
    AUTH_RATE_LIMIT_WINDOW_MS: '60000',
    AUTH_RATE_LIMIT_MAX_REQUESTS: '2',
    AUTH_DDOS_BURST_LIMIT: '10',
    AUTH_DDOS_BURST_WINDOW_MS: '10000',
    AUTH_RATE_LIMIT_MAX_BACKOFF_MS: '240000',
  };

  function middleware(): AuthRateLimitMiddleware {
    return new AuthRateLimitMiddleware(config(limits));
  }

  it('allows requests under the IP limit', () => {
    const mw = middleware();
    const next = jest.fn();
    mw.use(
      request('10.0.0.1'),
      { setHeader: jest.fn() } as unknown as Response,
      next,
    );
    mw.use(
      request('10.0.0.1'),
      { setHeader: jest.fn() } as unknown as Response,
      next,
    );
    expect(next).toHaveBeenCalledTimes(2);
  });

  it('backs off gradually for the same IP and leaves other IPs alone', () => {
    const mw = middleware();
    const res = { setHeader: jest.fn() } as unknown as Response;
    const next = jest.fn();

    mw.use(request('10.0.0.2'), res, next);
    mw.use(request('10.0.0.2'), res, next);

    expect(() => mw.use(request('10.0.0.2'), res, next)).toThrow(HttpException);
    const firstWait = Number(
      (res.setHeader as jest.Mock).mock.calls.at(-1)?.[1],
    );

    expect(() => mw.use(request('10.0.0.2'), res, next)).toThrow(HttpException);
    const secondWait = Number(
      (res.setHeader as jest.Mock).mock.calls.at(-1)?.[1],
    );

    expect(secondWait).toBeGreaterThan(firstWait);

    const other = jest.fn();
    mw.use(
      request('10.0.0.3'),
      { setHeader: jest.fn() } as unknown as Response,
      other,
    );
    expect(other).toHaveBeenCalledTimes(1);
  });

  it('ignores a spoofed X-Forwarded-For when req.ip is set', () => {
    const mw = middleware();
    const next = jest.fn();
    const res = { setHeader: jest.fn() } as unknown as Response;
    mw.use(request('10.0.0.4'), res, next);
    mw.use(request('10.0.0.4'), res, next);
    expect(() => mw.use(request('10.0.0.4'), res, next)).toThrow(HttpException);
    expect(next).toHaveBeenCalledTimes(2);
  });

  it('rejects an abusive cache buster before the request is counted as allowed', () => {
    const mw = middleware();
    const res = { setHeader: jest.fn() } as unknown as Response;
    const next = jest.fn();

    expect(() =>
      mw.use(request('10.0.0.5', { cachebuster: 'a'.repeat(80) }), res, next),
    ).toThrow(HttpException);

    expect(next).not.toHaveBeenCalled();
    expect(res.setHeader).toHaveBeenCalledWith(
      'Retry-After',
      expect.any(Number),
    );
    try {
      mw.use(request('10.0.0.5', { cachebuster: 'a'.repeat(80) }), res, next);
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException);
      expect((error as HttpException).getStatus()).toBe(
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  });

  it('allows a short cache-buster value', () => {
    const mw = middleware();
    const next = jest.fn();
    mw.use(
      request('10.0.0.6', { cb: 'v2' }),
      { setHeader: jest.fn() } as unknown as Response,
      next,
    );
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('treats a short burst over the DDoS threshold as a denial-of-service pattern', () => {
    const mw = new AuthRateLimitMiddleware(
      config({
        ...limits,
        AUTH_RATE_LIMIT_MAX_REQUESTS: '100',
        AUTH_DDOS_BURST_LIMIT: '3',
      }),
    );
    const res = { setHeader: jest.fn() } as unknown as Response;
    const next = jest.fn();
    const req = () => request('10.0.0.7');

    mw.use(req(), res, next);
    mw.use(req(), res, next);
    mw.use(req(), res, next);

    expect(() => mw.use(req(), res, next)).toThrow(
      'Request rate indicates a denial-of-service pattern',
    );
  });
});
