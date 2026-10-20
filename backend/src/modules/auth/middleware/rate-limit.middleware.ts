import {
  Injectable,
  NestMiddleware,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response, NextFunction } from 'express';

interface RateLimitRecord {
  count: number;
  resetTime: number;
  violations: number;
  burstCount: number;
  burstWindowStart: number;
  blockedUntil: number;
}

const CACHE_BUSTER_KEYS = new Set([
  '_',
  'cb',
  'cachebuster',
  'cache_buster',
  'nocache',
  'timestamp',
  '_t',
]);

/** Short version-like values. Long or noisy values are treated as busting attacks. */
const CACHE_BUSTER_VALUE = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * IP rate limit for authentication endpoints.
 * Repeated breaches increase the backoff. A short burst, or a cache-busting
 * query string, is treated as a DDoS attempt against the auth surface.
 */
@Injectable()
export class AuthRateLimitMiddleware implements NestMiddleware {
  private readonly store: Record<string, RateLimitRecord> = {};
  private readonly windowMs: number;
  private readonly maxRequests: number;
  private readonly burstLimit: number;
  private readonly burstWindowMs: number;
  private readonly maxBackoffMs: number;

  constructor(private readonly configService: ConfigService) {
    this.windowMs = this.parsePositiveInt(
      this.configService.get<string>('AUTH_RATE_LIMIT_WINDOW_MS'),
      15 * 60 * 1000,
    );
    this.maxRequests = this.parsePositiveInt(
      this.configService.get<string>('AUTH_RATE_LIMIT_MAX_REQUESTS'),
      5,
    );
    this.burstLimit = this.parsePositiveInt(
      this.configService.get<string>('AUTH_DDOS_BURST_LIMIT'),
      20,
    );
    this.burstWindowMs = this.parsePositiveInt(
      this.configService.get<string>('AUTH_DDOS_BURST_WINDOW_MS'),
      10 * 1000,
    );
    this.maxBackoffMs = this.parsePositiveInt(
      this.configService.get<string>('AUTH_RATE_LIMIT_MAX_BACKOFF_MS'),
      60 * 60 * 1000,
    );
  }

  use(req: Request, res: Response, next: NextFunction) {
    const now = Date.now();
    this.prune(now);

    const key = this.getClientIp(req);
    const record = this.touch(key, now);

    if (this.hasInvalidCacheBuster(req)) {
      this.block(record, now, Math.max(record.violations, 2));
      this.reject(
        res,
        record.blockedUntil - now,
        'Rejected cache-busting request',
      );
    }

    if (record.blockedUntil > now) {
      this.block(record, now, record.violations + 1);
      this.reject(
        res,
        record.blockedUntil - now,
        'Too many authentication attempts. Please try again later.',
      );
    }

    if (now > record.resetTime) {
      record.count = 0;
      record.resetTime = now + this.windowMs;
    }

    record.burstCount += 1;
    record.count += 1;

    if (record.burstCount > this.burstLimit) {
      this.block(record, now, Math.max(record.violations + 1, 3));
      this.reject(
        res,
        record.blockedUntil - now,
        'Request rate indicates a denial-of-service pattern',
      );
    }

    if (record.count > this.maxRequests) {
      this.block(record, now, record.violations + 1);
      this.reject(
        res,
        record.blockedUntil - now,
        'Too many authentication attempts. Please try again later.',
      );
    }

    next();
  }

  private touch(key: string, now: number): RateLimitRecord {
    const existing = this.store[key];
    if (!existing) {
      const created: RateLimitRecord = {
        count: 0,
        resetTime: now + this.windowMs,
        violations: 0,
        burstCount: 0,
        burstWindowStart: now,
        blockedUntil: 0,
      };
      this.store[key] = created;
      return created;
    }

    if (now - existing.burstWindowStart > this.burstWindowMs) {
      existing.burstWindowStart = now;
      existing.burstCount = 0;
    }
    return existing;
  }

  private block(
    record: RateLimitRecord,
    now: number,
    violations: number,
  ): void {
    record.violations = violations;
    record.blockedUntil = now + this.backoffMs(violations);
  }

  private backoffMs(violations: number): number {
    const exponent = Math.min(Math.max(violations - 1, 0), 10);
    return Math.min(this.windowMs * 2 ** exponent, this.maxBackoffMs);
  }

  private reject(res: Response, waitMs: number, message: string): never {
    const retryAfter = Math.max(1, Math.ceil(waitMs / 1000));
    res.setHeader('Retry-After', retryAfter);
    throw new HttpException(message, HttpStatus.TOO_MANY_REQUESTS);
  }

  /**
   * Known cache-buster keys must be short and stable. Anything else is an
   * attempt to force a unique URL past a cache and onto the origin.
   */
  private hasInvalidCacheBuster(req: Request): boolean {
    const query = req.query ?? {};
    for (const [key, value] of Object.entries(query)) {
      if (!CACHE_BUSTER_KEYS.has(key.toLowerCase())) {
        continue;
      }
      const values = Array.isArray(value) ? value : [value];
      for (const entry of values) {
        if (typeof entry !== 'string' || !CACHE_BUSTER_VALUE.test(entry)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Key on the address Express already resolved (`req.ip`), which follows
   * trust-proxy settings. A client-supplied X-Forwarded-For is not used, so
   * it cannot shard or evade the limit.
   */
  private getClientIp(req: Request): string {
    return req.ip || req.socket?.remoteAddress || 'unknown';
  }

  private prune(now: number): void {
    const keys = Object.keys(this.store);
    if (keys.length < 1000) {
      return;
    }
    for (const key of keys) {
      const record = this.store[key];
      if (record.resetTime < now && record.blockedUntil < now) {
        delete this.store[key];
      }
    }
  }

  private parsePositiveInt(
    value: string | undefined,
    fallback: number,
  ): number {
    if (!value) {
      return fallback;
    }

    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return fallback;
    }

    return parsed;
  }
}
