/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Secure CORS (Cross-Origin Resource Sharing) Middleware
 * 
 * Protects APIs from unauthorized cross-origin requests:
 * - Replaces insecure wildcard '*' with dynamic origin validation
 * - Supports AI Studio Preview, Cloud Run, and localhost development domains
 * - Explicitly controls allowed methods and headers
 * - Handles OPTIONS preflight cleanly with 204 No Content
 */

import { Request, Response, NextFunction } from 'express';

const ALLOWED_ORIGIN_PATTERNS: RegExp[] = [
  /^https?:\/\/localhost(:[0-9]+)?$/,
  /^https?:\/\/127\.0\.0\.1(:[0-9]+)?$/,
  /^https:\/\/[a-z0-9\-]+\.run\.app$/,
  /^https:\/\/[a-z0-9\.\-]+\.google\.com$/,
  /^https:\/\/ai\.studio$/,
  /^https:\/\/[a-z0-9\.\-]+\.googleusercontent\.com$/
];

export function isAllowedOrigin(origin?: string): boolean {
  if (!origin) return true; // Non-browser / same-origin / CLI requests
  
  // Custom env override
  const customOrigins = (process.env.CORS_ALLOWED_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  if (customOrigins.includes(origin) || customOrigins.includes('*')) {
    return true;
  }

  return ALLOWED_ORIGIN_PATTERNS.some(pattern => pattern.test(origin));
}

export function secureCorsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const origin = req.headers.origin;

  if (origin) {
    if (isAllowedOrigin(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader(
        'Access-Control-Allow-Methods',
        'GET, POST, PUT, PATCH, DELETE, OPTIONS'
      );
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, x-api-key, x-auth-token, X-Requested-With, Cache-Control, Accept'
      );
      res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours preflight cache
    } else {
      // Invalid origin: Do not reflect Access-Control-Allow-Origin
      if (req.method === 'OPTIONS') {
        res.status(403).json({ error: 'CORS origin not permitted.' });
        return;
      }
    }
  }

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  next();
}
