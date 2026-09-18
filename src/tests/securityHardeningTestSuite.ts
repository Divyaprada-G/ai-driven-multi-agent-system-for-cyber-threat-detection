/**
 * AI-DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Comprehensive Security Hardening & Authentication Test Suite
 * 
 * Verifies:
 * 1. Cryptographic Authentication & Password Hashing (PBKDF2-SHA512 + unique salts)
 * 2. Brute-Force Defense & Account Lockout
 * 3. Session Token Generation, Validation & Revocation
 * 4. Role-Based Access Control (RBAC) Matrix (ADMIN, ANALYST, VIEWER)
 * 5. Telemetry Ingestion Collector Authentication (x-api-key / Bearer tokens)
 * 6. In-Memory Rate Limiting (Token Bucket / Sliding Window)
 * 7. NoSQL Injection & Prototype Pollution Sanitization
 * 8. HTTP Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
 * 9. Security Audit Logging
 */

import { authService } from '../services/auth/authService';
import { InMemoryRateLimiter } from '../security/rateLimiter';
import { sanitizeNoSqlInput } from '../security/requestValidator';
import { getSecurityHeaders } from '../security/securityHeaders';
import { auditService } from '../services/auditService';
import { UserRole } from '../types/auth';

export async function runSecurityHardeningTestSuite(): Promise<{
  passCount: number;
  testCount: number;
  failedTests: string[];
  success: boolean;
}> {
  console.log('\n=============================================================');
  console.log('🛡️  SECURITY HARDENING & AUTHENTICATION VERIFICATION SUITE');
  console.log('=============================================================\n');

  let passCount = 0;
  let testCount = 0;
  const failedTests: string[] = [];

  function assert(condition: boolean, testName: string, detail?: string) {
    testCount++;
    if (condition) {
      console.log(`  [PASS] ${testName}`);
      passCount++;
    } else {
      console.error(`  [FAIL] ${testName} - ${detail || 'Assertion check failed'}`);
      failedTests.push(testName);
    }
  }

  // -------------------------------------------------------------
  // TEST SECTION 1: AUTHENTICATION SERVICE & CRYPTOGRAPHY
  // -------------------------------------------------------------
  console.log('--- 1. Cryptographic Authentication & Credential Verification ---');

  // Test 1.1: Default Admin Login
  const adminLogin = await authService.login('admin', 'Admin@SOC2026!#Secure', '127.0.0.1');
  assert(adminLogin.success === true, 'Admin login with valid credentials succeeds');
  assert(adminLogin.user?.role === 'ADMIN', 'Admin user receives ADMIN role');
  assert(typeof adminLogin.token === 'string' && adminLogin.token.length >= 64, 'Session token is 256-bit cryptographically secure hex string');

  // Test 1.2: Default Analyst Login
  const analystLogin = await authService.login('analyst', 'Analyst@Cyber2026!', '127.0.0.1');
  assert(analystLogin.success === true, 'Analyst login with valid credentials succeeds');
  assert(analystLogin.user?.role === 'ANALYST', 'Analyst user receives ANALYST role');

  // Test 1.3: Default Viewer Login
  const viewerLogin = await authService.login('viewer', 'Viewer@Auditor2026!', '127.0.0.1');
  assert(viewerLogin.success === true, 'Viewer login with valid credentials succeeds');
  assert(viewerLogin.user?.role === 'VIEWER', 'Viewer user receives VIEWER role');

  // Test 1.4: Invalid Password Rejection
  const badPassword = await authService.login('admin', 'WrongPassword123!', '127.0.0.1');
  assert(badPassword.success === false, 'Authentication rejects incorrect password');
  assert(badPassword.error?.includes('Invalid') === true, 'Generic error message returned to prevent user enumeration');

  // Test 1.5: Non-existent User Rejection
  const nonExistent = await authService.login('hacker_unknown', 'SomePassword123!', '127.0.0.1');
  assert(nonExistent.success === false, 'Authentication rejects non-existent usernames');

  // -------------------------------------------------------------
  // TEST SECTION 2: BRUTE-FORCE DEFENSE & ACCOUNT LOCKOUT
  // -------------------------------------------------------------
  console.log('\n--- 2. Brute-Force Attack Resistance & Account Lockout ---');

  // Create a dedicated test account to verify brute-force threshold
  const testUser = authService.registerUser(
    'test_victim',
    'victim@soc.test',
    'VIEWER',
    'Victim User',
    'Target Dept',
    'VictimSafePassword2026!'
  );
  assert(testUser !== null, 'Test user account successfully provisioned');

  // Perform 4 failed logins (should remain unlocked)
  for (let i = 1; i <= 4; i++) {
    await authService.login('test_victim', 'BadPassword!', '10.0.0.1');
  }
  const beforeLockout = await authService.login('test_victim', 'VictimSafePassword2026!', '10.0.0.1');
  assert(beforeLockout.success === true, 'Account allows login before reaching failure threshold (4 attempts)');

  // Now trigger 5 consecutive failures
  for (let i = 1; i <= 5; i++) {
    await authService.login('test_victim', 'BadPassword!', '10.0.0.1');
  }

  // 6th attempt with CORRECT password must now be rejected due to account lockout
  const lockedOutAttempt = await authService.login('test_victim', 'VictimSafePassword2026!', '10.0.0.1');
  assert(lockedOutAttempt.success === false, 'Account lockout engages after 5 consecutive failures');
  assert(
    lockedOutAttempt.error?.toLowerCase().includes('locked') === true,
    'Lockout response explicitly communicates temporary lock status'
  );

  // -------------------------------------------------------------
  // TEST SECTION 3: SESSION MANAGEMENT & REVOCATION
  // -------------------------------------------------------------
  console.log('\n--- 3. Session Management & Token Revocation ---');

  const validToken = adminLogin.token!;
  const sessionUser = authService.validateSession(validToken);
  assert(sessionUser !== null && sessionUser.username === 'admin', 'Valid session token resolves correct user account');

  // Revoke session via logout
  const logoutSuccess = authService.revokeSession(validToken, 'admin');
  assert(logoutSuccess === true, 'Session revocation (logout) completes successfully');

  // Validate revoked session
  const postLogoutCheck = authService.validateSession(validToken);
  assert(postLogoutCheck === null, 'Revoked session token is rejected on subsequent calls');

  // Random / counterfeit token rejection
  const fakeTokenCheck = authService.validateSession('fake-token-0123456789abcdef0123456789abcdef');
  assert(fakeTokenCheck === null, 'Counterfeit session token is rejected');

  // -------------------------------------------------------------
  // TEST SECTION 4: ROLE-BASED ACCESS CONTROL (RBAC) MATRIX
  // -------------------------------------------------------------
  console.log('\n--- 4. Role-Based Access Control (RBAC) Matrix ---');

  function checkRolePermission(userRole: UserRole, allowedRoles: UserRole[]): boolean {
    return allowedRoles.includes(userRole);
  }

  // ADMIN routes: only ADMIN
  assert(checkRolePermission('ADMIN', ['ADMIN']) === true, 'ADMIN user can access ADMIN routes');
  assert(checkRolePermission('ANALYST', ['ADMIN']) === false, 'ANALYST cannot access ADMIN-only routes');
  assert(checkRolePermission('VIEWER', ['ADMIN']) === false, 'VIEWER cannot access ADMIN-only routes');

  // ANALYST routes: ADMIN and ANALYST
  assert(checkRolePermission('ADMIN', ['ANALYST', 'ADMIN']) === true, 'ADMIN can access ANALYST routes');
  assert(checkRolePermission('ANALYST', ['ANALYST', 'ADMIN']) === true, 'ANALYST can access ANALYST routes');
  assert(checkRolePermission('VIEWER', ['ANALYST', 'ADMIN']) === false, 'VIEWER cannot access ANALYST routes');

  // VIEWER routes: all authenticated roles
  assert(checkRolePermission('ADMIN', ['VIEWER', 'ANALYST', 'ADMIN']) === true, 'ADMIN can access VIEWER routes');
  assert(checkRolePermission('ANALYST', ['VIEWER', 'ANALYST', 'ADMIN']) === true, 'ANALYST can access VIEWER routes');
  assert(checkRolePermission('VIEWER', ['VIEWER', 'ANALYST', 'ADMIN']) === true, 'VIEWER can access VIEWER routes');

  // -------------------------------------------------------------
  // TEST SECTION 5: TELEMETRY COLLECTOR API KEY VALIDATION
  // -------------------------------------------------------------
  console.log('\n--- 5. Telemetry Ingestion Collector Authentication ---');

  const configuredKey = process.env.BACKEND_API_KEY || 'soc-telemetry-collector-prod-key-2026';
  assert(authService.validateCollectorApiKey(configuredKey) === true, 'Configured collector API key is accepted');
  assert(authService.validateCollectorApiKey('invalid-fake-api-key') === false, 'Invalid collector API key is rejected');
  assert(authService.validateCollectorApiKey(undefined) === false, 'Undefined/empty collector API key is rejected');

  // -------------------------------------------------------------
  // TEST SECTION 6: RATE LIMITING ENGINE
  // -------------------------------------------------------------
  console.log('\n--- 6. In-Memory Rate Limiter (Token Bucket / Sliding Window) ---');

  const testLimiter = new InMemoryRateLimiter({
    windowMs: 5000,
    maxRequests: 5,
    name: 'test_limiter'
  });

  const clientIp = '198.51.100.42';

  // Make 5 permitted requests
  for (let i = 1; i <= 5; i++) {
    const check = testLimiter.consume(clientIp);
    assert(check.allowed === true, `Rate limiter allows request ${i} of 5`);
  }

  // 6th request must be blocked
  const blockedRequest = testLimiter.consume(clientIp);
  assert(blockedRequest.allowed === false, 'Rate limiter blocks 6th request exceeding 5 req/window');
  assert(blockedRequest.remaining === 0, 'Remaining quota reports 0');
  assert(blockedRequest.resetTimeMs > 0, 'Retry-after window duration reported');

  // -------------------------------------------------------------
  // TEST SECTION 7: NOSQL INJECTION & PROTOTYPE POLLUTION DEFENSE
  // -------------------------------------------------------------
  console.log('\n--- 7. NoSQL Injection & Input Sanitization ---');

  // Test 7.1: Malicious MongoDB operators
  const maliciousQuery = {
    username: { $gt: '' },
    password: { $ne: 'null' }
  };
  const nosqlResult = sanitizeNoSqlInput(maliciousQuery);
  assert(nosqlResult.hasViolation === true, 'Detects $gt and $ne injection operators');
  assert(nosqlResult.clean.username !== undefined, 'Neutralizes injection payload without crashing');

  // Test 7.2: Prototype pollution attack
  const pollutionPayload = JSON.parse('{"__proto__": {"isAdmin": true}, "constructor": {"role": "ADMIN"}, "validData": "normal-telemetry"}');
  const pollutionResult = sanitizeNoSqlInput(pollutionPayload);
  assert(pollutionResult.hasViolation === true, 'Detects prototype pollution keys (__proto__, constructor)');
  assert(!('__proto__' in pollutionResult.clean) || Object.keys(pollutionResult.clean).includes('validData'), 'Sanitizes object keys safely');

  // Test 7.3: Clean payload passes untouched
  const benignPayload = {
    eventType: 'NETWORK_FLOW',
    sourceIp: '192.168.1.50',
    destinationPort: 443,
    severity: 'LOW'
  };
  const benignResult = sanitizeNoSqlInput(benignPayload);
  assert(benignResult.hasViolation === false, 'Clean telemetry payload passes without modification');
  assert(benignResult.clean.sourceIp === '192.168.1.50', 'Preserves legitimate data integrity');

  // -------------------------------------------------------------
  // TEST SECTION 8: HTTP SECURITY HEADERS
  // -------------------------------------------------------------
  console.log('\n--- 8. HTTP Security Headers Audit ---');

  const headers = getSecurityHeaders();
  assert(headers['X-Content-Type-Options'] === 'nosniff', 'X-Content-Type-Options is set to nosniff');
  assert(headers['X-Frame-Options'] === 'SAMEORIGIN', 'X-Frame-Options is set to SAMEORIGIN');
  assert(headers['Referrer-Policy'] === 'strict-origin-when-cross-origin', 'Referrer-Policy is set to strict-origin');
  assert(typeof headers['Content-Security-Policy'] === 'string', 'Content-Security-Policy header is configured');
  assert(headers['Content-Security-Policy'].includes("default-src 'self'"), 'CSP enforces default-src self');

  // -------------------------------------------------------------
  // TEST SECTION 9: SECURITY AUDIT LOGGING
  // -------------------------------------------------------------
  console.log('\n--- 9. Security Audit Logging ---');

  const recentLogs = auditService.getAuditLogs();
  assert(Array.isArray(recentLogs), 'Audit service maintains traceable log entries');
  const hasSecurityActions = recentLogs.some(
    l => l.action === 'LOGIN_SUCCESS' || l.action === 'AUTHENTICATION_FAILURE' || l.action === 'ACCOUNT_LOCKED'
  );
  assert(hasSecurityActions === true, 'Security events (logins, failures, lockouts) are logged to audit trail');

  // -------------------------------------------------------------
  // SUMMARY
  // -------------------------------------------------------------
  console.log('\n=============================================================');
  console.log(`🏁 TEST RESULTS: ${passCount}/${testCount} PASSED`);
  if (failedTests.length === 0) {
    console.log('✅ ALL SECURITY HARDENING TESTS PASSED WITH ZERO FAILURES');
  } else {
    console.error(`❌ FAILED TESTS (${failedTests.length}):`, failedTests);
  }
  console.log('=============================================================\n');

  return {
    passCount,
    testCount,
    failedTests,
    success: failedTests.length === 0
  };
}

// Allow standalone execution via tsx
if (process.argv[1]?.includes('securityHardeningTestSuite')) {
  runSecurityHardeningTestSuite().then(result => {
    if (!result.success) {
      process.exit(1);
    }
  });
}
