/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * HTTP Security Headers Middleware
 * 
 * Enforces production-grade defensive HTTP headers across all Express responses:
 * - Content-Security-Policy (with frame-ancestors for AI Studio / Cloud Run)
 * - X-Content-Type-Options: nosniff
 * - Strict-Transport-Security (HSTS)
 * - Referrer-Policy: strict-origin-when-cross-origin
 * - Permissions-Policy restrictions
 * - Information disclosure suppression (removes X-Powered-By)
 */

import { Request, Response, NextFunction } from 'express';

export function getSecurityHeaders(): Record<string, string> {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '0',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: blob: https:",
      "connect-src 'self' http: https: ws: wss:",
      "frame-ancestors 'self' https://*.google.com https://*.run.app https://ai.studio https://*.googleusercontent.com"
    ].join('; ')
  };
}

export function applySecurityHeaders(req: Request, res: Response, next: NextFunction): void {
  // Remove information disclosure headers
  res.removeHeader('X-Powered-By');

  // Prevent MIME-sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Modern XSS Protection header (disables buggy legacy browser heuristics)
  res.setHeader('X-XSS-Protection', '0');

  // Restrict referrer information sent on cross-origin navigation
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Enforce HSTS (Strict-Transport-Security) for HTTPS connections
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

  // Feature / Permissions policy to disallow unauthorized hardware access
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');

  // Content-Security-Policy tailored for AI Studio Preview & Production SPA
  const cspDirectives = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' http: https: ws: wss:",
    "frame-ancestors 'self' https://*.google.com https://*.run.app https://ai.studio https://*.googleusercontent.com"
  ];
  res.setHeader('Content-Security-Policy', cspDirectives.join('; '));

  next();
}
