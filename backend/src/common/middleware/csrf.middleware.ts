import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

type RequestWithCookies = Request & {
  cookies?: Record<string, string>;
};

const CSRF_COOKIE_NAME = 'XSRF-TOKEN';
const CSRF_HEADER_NAMES = ['x-xsrf-token', 'x-csrf-token'] as const;
const CSRF_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const CSRF_CLOCK_SKEW_MS = 60 * 1000;

/**
 * Issue a double-submit CSRF token: non-HttpOnly cookie plus response header.
 * Safe methods and GET /auth/csrf-token call this. Mutations must echo it.
 */
export function issueDoubleSubmitCsrfToken(
  configService: ConfigService,
  res: Response,
): string {
  const token = createCsrfToken(readCsrfSecret(configService));
  const isProduction = configService.get<string>('NODE_ENV') === 'production';
  const cookieOptions = {
    httpOnly: false,
    secure: isProduction,
    sameSite: 'strict' as const,
    maxAge: CSRF_MAX_AGE_MS,
    path: '/',
  };

  assertCookieSettings(cookieOptions, isProduction);
  res.cookie(CSRF_COOKIE_NAME, token, cookieOptions);
  res.setHeader('X-CSRF-Token', token);
  return token;
}

/**
 * CSRF protection using the double-submit cookie pattern.
 * Safe methods issue a token. Mutations must send the same token in
 * X-XSRF-TOKEN, X-CSRF-Token, or a `_csrf` body field.
 */
@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  private readonly logger = new Logger(CsrfMiddleware.name);
  private readonly enabled: boolean;
  private readonly secret: string;

  constructor(private configService: ConfigService) {
    this.enabled =
      this.configService.get<string>('SECURITY_CSRF_ENABLED') !== 'false';
    this.secret = this.enabled ? readCsrfSecret(this.configService) : '';
  }

  use(req: RequestWithCookies, res: Response, next: NextFunction) {
    if (!this.enabled) {
      return next();
    }

    const method = req.method;
    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      this.ensureToken(req, res);
      return next();
    }

    const path = req.path || '';
    if (
      path.startsWith('/health') ||
      path.startsWith('/api/docs') ||
      path.startsWith('/security.txt') ||
      path.includes('/webhooks/gateway') ||
      path.includes('/anchor/webhook')
    ) {
      return next();
    }

    const cookieToken = readCookie(req, CSRF_COOKIE_NAME);
    const submitted = readSubmittedToken(req);

    if (!submitted || !cookieToken) {
      this.logger.warn(
        `CSRF token missing: headerOrBody=${!!submitted}, cookie=${!!cookieToken}, path=${path}`,
      );
      throw new UnauthorizedException('CSRF token missing or invalid');
    }

    if (!tokensMatch(submitted, cookieToken, this.secret)) {
      this.logger.warn(`CSRF token mismatch for path: ${path}`);
      throw new UnauthorizedException('CSRF token mismatch');
    }

    next();
  }

  private ensureToken(req: RequestWithCookies, res: Response): void {
    const existing = readCookie(req, CSRF_COOKIE_NAME);
    if (existing && isCsrfTokenValid(existing, this.secret)) {
      res.setHeader('X-CSRF-Token', existing);
      return;
    }
    issueDoubleSubmitCsrfToken(this.configService, res);
  }
}

function readCsrfSecret(configService: ConfigService): string {
  const secret =
    configService.get<string>('SECURITY_SESSION_SECRET') ||
    configService.get<string>('JWT_SECRET');
  if (!secret) {
    throw new Error(
      'SECURITY_SESSION_SECRET (or JWT_SECRET) is required when CSRF is enabled',
    );
  }
  return secret;
}

function assertCookieSettings(
  cookieOptions: {
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'strict' | 'lax' | 'none';
  },
  isProduction: boolean,
): void {
  if (cookieOptions.httpOnly !== false) {
    throw new InternalServerErrorException(
      'Invalid CSRF cookie configuration: httpOnly must be false',
    );
  }
  if (isProduction && !cookieOptions.secure) {
    throw new InternalServerErrorException(
      'Invalid CSRF cookie configuration: secure must be true in production',
    );
  }
  if (!['strict', 'lax'].includes(cookieOptions.sameSite)) {
    throw new InternalServerErrorException(
      'Invalid CSRF cookie configuration: sameSite must be strict or lax',
    );
  }
}

function createCsrfToken(secret: string): string {
  const randomBytes = crypto.randomBytes(32).toString('hex');
  const timestamp = Date.now().toString();
  const data = `${randomBytes}:${timestamp}`;
  const hmac = crypto.createHmac('sha256', secret).update(data).digest('hex');
  return `${data}:${hmac}`;
}

function readSubmittedToken(req: RequestWithCookies): string | undefined {
  const headerToken = CSRF_HEADER_NAMES.map((name) =>
    headerValue(req, name),
  ).find((value): value is string => !!value);
  const body = req.body as { _csrf?: unknown } | undefined;
  const bodyToken =
    typeof body?._csrf === 'string' && body._csrf.length > 0
      ? body._csrf
      : undefined;

  if (headerToken && bodyToken && headerToken !== bodyToken) {
    return undefined;
  }
  return headerToken || bodyToken;
}

function tokensMatch(
  submitted: string,
  cookieToken: string,
  secret: string,
): boolean {
  if (!safeEqual(submitted, cookieToken)) {
    return false;
  }
  return isCsrfTokenValid(submitted, secret);
}

function isCsrfTokenValid(token: string, secret: string): boolean {
  const parts = token.split(':');
  if (parts.length !== 3) {
    return false;
  }

  const [randomBytes, timestamp, hmac] = parts;
  if (!/^[a-f0-9]{64}$/.test(randomBytes) || !/^[a-f0-9]{64}$/.test(hmac)) {
    return false;
  }

  const issuedAt = Number(timestamp);
  if (!Number.isInteger(issuedAt)) {
    return false;
  }

  const age = Date.now() - issuedAt;
  if (age > CSRF_MAX_AGE_MS || age < -CSRF_CLOCK_SKEW_MS) {
    return false;
  }

  const expectedHmac = crypto
    .createHmac('sha256', secret)
    .update(`${randomBytes}:${timestamp}`)
    .digest('hex');
  return safeEqual(hmac, expectedHmac);
}

function readCookie(req: RequestWithCookies, name: string): string | undefined {
  const fromParser = req.cookies?.[name];
  if (typeof fromParser === 'string' && fromParser.length > 0) {
    return fromParser;
  }

  const header = req.headers.cookie;
  if (typeof header !== 'string' || header.length === 0) {
    return undefined;
  }

  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) {
      continue;
    }
    const key = part.slice(0, separator).trim();
    if (key !== name) {
      continue;
    }
    const raw = part.slice(separator + 1).trim();
    if (!raw) {
      return undefined;
    }
    try {
      return decodeURIComponent(raw);
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function headerValue(req: Request, name: string): string | undefined {
  const raw = req.headers[name];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}
