/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Authentication & Role-Based Authorization Middleware
 * 
 * Enforces:
 * - Session token extraction and verification
 * - Role-Based Access Control (RBAC: ADMIN, ANALYST, VIEWER)
 * - Collector Service API Key authentication for edge telemetry collectors
 * - Structured audit logging for all authentication & authorization violations
 */

import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth/authService';
import { UserRole, AuthSession } from '../types/auth';
import { auditService } from '../services/auditService';

export interface AuthenticatedRequest extends Request {
  user?: AuthSession;
  isCollector?: boolean;
}

/**
 * Extracts session token from headers or query parameters
 */
export function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }
  const customHeader = req.headers['x-auth-token'];
  if (typeof customHeader === 'string' && customHeader.trim()) {
    return customHeader.trim();
  }
  if (req.headers.cookie) {
    const match = req.headers.cookie.match(/(?:^|;\s*)soc_session_token=([^;]+)/);
    if (match && match[1]) {
      return decodeURIComponent(match[1]).trim();
    }
  }
  if (req.query && typeof req.query.token === 'string' && req.query.token.trim()) {
    return req.query.token.trim();
  }
  return null;
}

/**
 * Soft authentication: Attaches user if token is valid, does not reject request
 */
export function attachUserIfAuthenticated(req: AuthenticatedRequest, _res: Response, next: NextFunction): void {
  const token = extractToken(req);
  if (token) {
    const session = authService.validateSession(token);
    if (session) {
      req.user = session;
    }
  }
  next();
}

/**
 * Hard authentication: Rejects unauthenticated requests with HTTP 401
 */
export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required. No session token provided in Authorization header.',
      code: 'UNAUTHORIZED',
      timestamp: new Date().toISOString()
    });
  }

  const session = authService.validateSession(token);
  if (!session) {
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    auditService.recordAction({
      action: 'AUTHENTICATION_FAILURE',
      entityType: 'SESSION',
      entityId: token.slice(0, 8) + '...',
      actor: 'AuthGuard',
      details: `Invalid or expired session token provided for ${req.method} ${req.path} from IP ${clientIp}.`,
      metadata: { ipAddress: clientIp, path: req.path, method: req.method }
    });

    return res.status(401).json({
      success: false,
      error: 'Invalid or expired session token. Please log in again.',
      code: 'SESSION_EXPIRED',
      timestamp: new Date().toISOString()
    });
  }

  req.user = session;
  return next();
}

/**
 * Role authorization guard: Rejects users lacking required roles with HTTP 403
 */
export function requireRole(allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required before checking role authorization.',
        code: 'UNAUTHORIZED',
        timestamp: new Date().toISOString()
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
      auditService.recordAction({
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        entityType: 'ENDPOINT',
        entityId: req.path,
        actor: `${req.user.displayName} (${req.user.role})`,
        details: `Access denied to ${req.method} ${req.path}. User role '${req.user.role}' lacks required permissions [${allowedRoles.join(', ')}].`,
        metadata: { ipAddress: clientIp, path: req.path, method: req.method, userRole: req.user.role, requiredRoles: allowedRoles }
      });

      return res.status(403).json({
        success: false,
        error: `Forbidden: role '${req.user.role}' lacks permission for this action. Required role: ${allowedRoles.join(' or ')}.`,
        code: 'FORBIDDEN',
        userRole: req.user.role,
        requiredRoles: allowedRoles,
        timestamp: new Date().toISOString()
      });
    }

    return next();
  };
}

/**
 * Telemetry collector authentication: Allows either a valid collector API key or authenticated ANALYST/ADMIN
 */
export function authenticateCollectorOrRole(allowedRoles: UserRole[] = ['ADMIN', 'ANALYST']) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    // 1. Check for collector API key in x-api-key or Authorization header
    const apiKey = (req.headers['x-api-key'] as string) ||
      (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7).trim() : undefined);

    if (apiKey && authService.verifyCollectorApiKey(apiKey)) {
      req.isCollector = true;
      req.user = {
        token: 'collector-internal-token',
        userId: 'COLLECTOR-SVC',
        username: 'collector-agent',
        role: 'ADMIN',
        displayName: 'Telemetry Collector Service',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        ipAddress: (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1'
      };
      return next();
    }

    // 2. Check for standard user session
    const token = extractToken(req);
    if (token) {
      const session = authService.validateSession(token);
      if (session && allowedRoles.includes(session.role)) {
        req.user = session;
        return next();
      }
    }

    // In local development mode without configured keys, allow loopback localhost if not production
    if (process.env.NODE_ENV !== 'production') {
      const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
      if (ip === '127.0.0.1' || ip === '::1' || ip.includes('127.0.0.1')) {
        req.isCollector = true;
        req.user = {
          token: 'collector-dev-token',
          userId: 'COLLECTOR-DEV',
          username: 'local-collector',
          role: 'ADMIN',
          displayName: 'Localhost Collector',
          createdAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 86400000).toISOString(),
          ipAddress: ip
        };
        return next();
      }
    }

    return res.status(401).json({
      success: false,
      error: 'Telemetry transmission unauthorized. Valid Collector API key or authenticated user token required.',
      code: 'UNAUTHORIZED_COLLECTOR',
      timestamp: new Date().toISOString()
    });
  };
}
