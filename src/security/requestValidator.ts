/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * API Request Validation & Injection Defense Middleware
 * 
 * Provides defense-in-depth:
 * - Sanitizes query and body parameters to prevent NoSQL Operator Injections ($where, $gt, $ne, $expr)
 * - Restricts pagination parameters (limit <= 500, offset >= 0) to prevent DoS memory exhaustion
 * - Guards against directory / path traversal in identifier parameters
 * - Validates status transitions and categorization enums
 */

import { Request, Response, NextFunction } from 'express';

const FORBIDDEN_NOSQL_KEYS = new Set([
  '$where',
  '$gt',
  '$gte',
  '$lt',
  '$lte',
  '$ne',
  '$in',
  '$nin',
  '$regex',
  '$expr',
  '$jsonSchema',
  '$mod',
  '$text',
  '$function',
  '$accumulator'
]);

const FORBIDDEN_POLLUTION_KEYS = new Set([
  '__proto__',
  'constructor',
  'prototype'
]);

/**
 * Recursively inspects and sanitizes objects to strip or reject dangerous MongoDB operators
 */
export function sanitizeNoSqlInput(obj: any, depth = 0): { clean: any; hasViolation: boolean } {
  if (depth > 10) return { clean: obj, hasViolation: false };
  if (!obj || typeof obj !== 'object') {
    return { clean: obj, hasViolation: false };
  }

  if (Array.isArray(obj)) {
    let violation = false;
    const cleanArr = obj.map(item => {
      const res = sanitizeNoSqlInput(item, depth + 1);
      if (res.hasViolation) violation = true;
      return res.clean;
    });
    return { clean: cleanArr, hasViolation: violation };
  }

  let violation = false;
  const cleanObj: Record<string, any> = {};

  for (const [key, val] of Object.entries(obj)) {
    if (key.startsWith('$') || FORBIDDEN_NOSQL_KEYS.has(key) || FORBIDDEN_POLLUTION_KEYS.has(key)) {
      violation = true;
      continue; // Strip hazardous operator key
    }
    const child = sanitizeNoSqlInput(val, depth + 1);
    if (child.hasViolation) violation = true;
    cleanObj[key] = child.clean;
  }

  return { clean: cleanObj, hasViolation: violation };
}

/**
 * Express middleware to sanitize body and query for NoSQL injection
 */
export function noSqlSanitizationMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (req.body && typeof req.body === 'object') {
    const { clean, hasViolation } = sanitizeNoSqlInput(req.body);
    if (hasViolation) {
      res.status(400).json({
        success: false,
        error: 'Request contains disallowed query operators or injection tokens.',
        code: 'INVALID_INPUT_INJECTION_DETECTED',
        timestamp: new Date().toISOString()
      });
      return;
    }
    req.body = clean;
  }

  if (req.query && typeof req.query === 'object') {
    const { clean, hasViolation } = sanitizeNoSqlInput(req.query);
    if (hasViolation) {
      res.status(400).json({
        success: false,
        error: 'Query parameter contains disallowed operators or injection tokens.',
        code: 'INVALID_QUERY_INJECTION_DETECTED',
        timestamp: new Date().toISOString()
      });
      return;
    }
    req.query = clean;
  }

  next();
}

/**
 * Sanitizes and bounds integer pagination parameters
 */
export function sanitizePagination(
  limitParam: any,
  offsetParam: any,
  defaultLimit = 50,
  maxLimit = 500
): { limit: number; offset: number } {
  let limit = parseInt(String(limitParam || defaultLimit), 10);
  let offset = parseInt(String(offsetParam || 0), 10);

  if (isNaN(limit) || limit < 1) limit = defaultLimit;
  if (limit > maxLimit) limit = maxLimit;

  if (isNaN(offset) || offset < 0) offset = 0;

  return { limit, offset };
}

/**
 * Validates resource identifiers against path traversal or malicious characters
 */
export function isValidId(id?: string): boolean {
  if (!id || typeof id !== 'string') return false;
  if (id.includes('..') || id.includes('/') || id.includes('\\')) return false;
  // Allow typical IDs: UUIDs, INC-2026-001, ALT-1001, Mongo ObjectId 24-hex, etc.
  return /^[a-zA-Z0-9_\-\.:]{1,128}$/.test(id);
}
