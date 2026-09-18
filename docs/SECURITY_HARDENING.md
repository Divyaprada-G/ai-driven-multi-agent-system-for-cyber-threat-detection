# AI-Driven Multi-Agent Cyber Threat Detection System
## Security Hardening & Authentication Architecture Documentation

**Document Version:** 1.0.0  
**Target Environment:** AI Studio Build / Production Node.js Cloud Run Containers  
**Compliance Standard:** Least-Privilege RBAC, Defense-in-Depth, OWASP Top 10 API Security  

---

## 1. Executive Summary

This security hardening implementation transforms the AI-Driven Multi-Agent System for Cyber Threat Detection from an open development prototype into a secured, multi-tenant capable SOC command center. All sensitive operations—including incident lifecycle management, SOAR response actions, multi-agent pipeline orchestration, ML model training, and database queries—are strictly protected by cryptographic authentication, role-based authorization (RBAC), token-bucket rate limiting, and NoSQL injection defenses without breaking real-time telemetry streaming (SSE) or automated edge collector ingestion.

---

## 2. Security Architecture & Threat Model

```
                                  [ INGRESS TRAFFIC ]
                                           │
                        ┌──────────────────┴──────────────────┐
                        │        Security Headers & CORS       │
                        │    (CSP, HSTS, X-Content-Type, etc.) │
                        └──────────────────┬──────────────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        │      Sliding Window Rate Limiter     │
                        │    (Auth: 15/10m | API: 300/1m)     │
                        └──────────────────┬──────────────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        │      NoSQL & Injection Defense      │
                        │    (Strips $gt, $where, __proto__)  │
                        └──────────────────┬──────────────────┘
                                           │
                                ┬──────────┴──────────┬
                                │                     │
                 [ Edge Collectors & Telemetry ]      [ Web Dashboard & SOC Analysts ]
                                │                     │
                        ┌───────┴──────┐      ┌───────┴──────┐
                        │  Collector   │      │ Bearer Auth  │
                        │ API Key Auth │      │  & Sessions  │
                        └───────┬──────┘      └───────┬──────┘
                                │                     │
                                └──────────┬──────────┘
                                           │
                                ┌──────────┴──────────┐
                                │     RBAC Matrix     │
                                │ (ADMIN/ANALYST/VIEW)│
                                └──────────┬──────────┘
                                           │
               ┌────────────────┬──────────┴──────────┬────────────────┐
               │                │                     │                │
        [ Pipeline APIs ] [ Incident Mgmt ]    [ ML Training ]   [ Audit Trail ]
```

---

## 3. Core Security Controls Implemented

### 3.1. Cryptographic Authentication (`src/services/auth/authService.ts`)
- **Key Derivation:** Passwords hashed with **PBKDF2 (HMAC-SHA512)** using 100,000 iterations and 16-byte cryptographically random salt per user.
- **Verification:** Evaluated via constant-time buffer comparison (`crypto.timingSafeEqual`) to prevent timing side-channel attacks.
- **Session Tokens:** 256-bit cryptographically secure hexadecimal tokens (`crypto.randomBytes(32).toString('hex')`) with a 24-hour expiration (`SESSION_TTL_MS`).
- **Brute-Force Attack Defense:** 5 consecutive failed login attempts automatically trigger a 15-minute temporary account lockout (`ACCOUNT_LOCKED`).

### 3.2. Role-Based Access Control (RBAC) Matrix
The system enforces strict least-privilege access across three operational roles:

| API Domain | Path Pattern | Required Role | Description |
| :--- | :--- | :---: | :--- |
| **Telemetry Ingest** | `/api/telemetry/ingest` | `COLLECTOR` or `ADMIN` | Ingestion from Windows/Linux edge agents |
| **Collector Control** | `/api/telemetry/collectors/:id/*` | `ADMIN` | Start/stop/restart background collectors |
| **Telemetry State** | `/api/telemetry/state`, `/stream` | `VIEWER`+ | Real-time dashboards, SSE event feed |
| **Incident Response** | `/api/incidents/:id/actions/*` | `ANALYST`+ | Authorize/deny containment actions |
| **Incident Notes** | `/api/incidents/:id/notes` | `ANALYST`+ | Append forensic investigation findings |
| **Alert Management** | `/api/alerts/:id/*` | `ANALYST`+ | Acknowledge alerts, change status |
| **ML Training** | `/api/ml/train/*` | `ADMIN` | Trigger model training runs |
| **Dataset Upload** | `/api/datasets/upload` | `ADMIN` | Upload CSV/JSON training datasets |
| **Agent Orchestration**| `/api/agents/:id/*` | `ADMIN` | Pause/resume threat detection agents |
| **Audit Log Read** | `/api/audit` | `ANALYST`+ | Inspect SOC audit and compliance logs |
| **User Session** | `/api/auth/me`, `/logout` | Authenticated | Manage active user session |

### 3.3. Defense-in-Depth HTTP Security Headers (`src/security/securityHeaders.ts`)
- `Content-Security-Policy`: Restricts scripts, styles, and assets; configures frame-ancestors to permit Google AI Studio and Cloud Run container embedding.
- `X-Content-Type-Options: nosniff`: Defends against MIME-type sniffing.
- `Strict-Transport-Security`: Enforces HTTPS navigation (`max-age=31536000; includeSubDomains; preload`).
- `X-Frame-Options: SAMEORIGIN`: Defends against clickjacking.
- `Referrer-Policy: strict-origin-when-cross-origin`: Minimizes referrer leakage on outbound navigation.
- `X-Powered-By`: Explicitly suppressed to prevent server technology fingerprinting.

### 3.4. Rate Limiting (`src/security/rateLimiter.ts`)
- **Authentication Routes (`/api/auth/*`):** Maximum 15 requests per 10-minute window per IP.
- **General APIs (`/api/*`):** Maximum 300 requests per minute per IP.
- **Telemetry Ingestion (`/api/telemetry/ingest`):** High-throughput window allowing up to 1,500 requests per minute per collector.
- Returns standard RFC rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`) with HTTP 429 when breached.

### 3.5. Input Validation & Injection Defense (`src/security/requestValidator.ts`)
- Deep recursive scanning and neutralization of hazardous MongoDB query operators (`$where`, `$gt`, `$ne`, `$regex`, `$expr`, etc.).
- Prototype pollution defenses blocking `__proto__`, `constructor`, and `prototype` overwrites.
- Strict validation of pagination bounds (`limit <= 500`, `offset >= 0`) to prevent memory exhaustion DoS.

### 3.6. Sanitized Error Handling
- The Express global error handler interceptor intercepts database exceptions (Mongoose, MongoServerError, PostgreSQL) and returns sanitized, generic error contracts.
- Stack traces and internal filesystem paths are stripped from responses in non-development environments.

### 3.7. Security Audit Trail (`src/services/auditService.ts`)
All security-relevant actions are immutably appended to the audit trail with actor details, timestamps, IP addresses, and before/after metadata:
- `LOGIN_SUCCESS`, `AUTHENTICATION_FAILURE`, `ACCOUNT_LOCKED`, `LOGOUT`
- `UNAUTHORIZED_ACCESS_ATTEMPT`, `RATE_LIMIT_EXCEEDED`
- `COLLECTOR_STARTED`, `COLLECTOR_STOPPED`
- `MODEL_TRAINED`, `DATASET_UPLOADED`
- `RESPONSE_ACTION_AUTHORIZED`, `RESPONSE_ACTION_DENIED`

---

## 4. Pre-Configured Accounts & Credentials

For SOC evaluation and initial configuration, three sample accounts are initialized in `authService`:

| Username | Password | Role | Primary Responsibility |
| :--- | :--- | :---: | :--- |
| `admin` | `Admin@SOC2026!#Secure` | `ADMIN` | Full control, ML model training, collector controls |
| `analyst` | `Analyst@Cyber2026!` | `ANALYST` | Triage alerts, investigate incidents, execute SOAR |
| `viewer` | `Viewer@Auditor2026!` | `VIEWER` | Read-only telemetry viewing and audit reporting |

> **Note:** In production, override default passwords using `.env` variables (`ADMIN_INITIAL_PASSWORD`, etc.).

---

## 5. Collector Authentication (Edge Agents)

Edge telemetry collectors (such as `backend/collector_agent.py` or Windows Sysmon monitors) must authenticate to `/api/telemetry/ingest` using one of two methods:

### Method A: HTTP Header `x-api-key`
```http
POST /api/telemetry/ingest HTTP/1.1
Host: soc-collector.internal.soc:3000
Content-Type: application/json
x-api-key: soc-telemetry-collector-prod-key-2026

{
  "logType": "SYSTEM",
  "events": [ ... ]
}
```

### Method B: HTTP Header `Authorization: Bearer <API_KEY>`
```http
POST /api/telemetry/ingest HTTP/1.1
Host: soc-collector.internal.soc:3000
Content-Type: application/json
Authorization: Bearer soc-telemetry-collector-prod-key-2026
```

---

## 6. Environment Variables Reference

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `BACKEND_API_KEY` | `soc-telemetry-collector-prod-key-2026` | Shared secret for edge telemetry collectors |
| `SESSION_SECRET` | System-generated random key | Secret used for session token signing |
| `ADMIN_INITIAL_PASSWORD` | `Admin@SOC2026!#Secure` | Initial bootstrap password for `admin` account |
| `ANALYST_INITIAL_PASSWORD` | `Analyst@Cyber2026!` | Initial bootstrap password for `analyst` account |
| `VIEWER_INITIAL_PASSWORD` | `Viewer@Auditor2026!` | Initial bootstrap password for `viewer` account |
| `CORS_ALLOWED_ORIGINS` | Permitted origins | Comma-delimited origins allowed for CORS |

---

## 7. Verification & Test Suite Results

The comprehensive automated security test suite can be run at any time via:
```bash
npm run test:security
```

### Execution Log Output (51/51 Tests Passing)
```text
=============================================================
🛡️  SECURITY HARDENING & AUTHENTICATION VERIFICATION SUITE
=============================================================
--- 1. Cryptographic Authentication & Credential Verification ---
  [PASS] Admin login with valid credentials succeeds
  [PASS] Admin user receives ADMIN role
  [PASS] Session token is 256-bit cryptographically secure hex string
  [PASS] Analyst login with valid credentials succeeds
  [PASS] Analyst user receives ANALYST role
  [PASS] Viewer login with valid credentials succeeds
  [PASS] Viewer user receives VIEWER role
  [PASS] Authentication rejects incorrect password
  [PASS] Generic error message returned to prevent user enumeration
  [PASS] Authentication rejects non-existent usernames

--- 2. Brute-Force Attack Resistance & Account Lockout ---
  [PASS] Test user account successfully provisioned
  [PASS] Account allows login before reaching failure threshold (4 attempts)
  [PASS] Account lockout engages after 5 consecutive failures
  [PASS] Lockout response explicitly communicates temporary lock status

--- 3. Session Management & Token Revocation ---
  [PASS] Valid session token resolves correct user account
  [PASS] Session revocation (logout) completes successfully
  [PASS] Revoked session token is rejected on subsequent calls
  [PASS] Counterfeit session token is rejected

--- 4. Role-Based Access Control (RBAC) Matrix ---
  [PASS] ADMIN user can access ADMIN routes
  [PASS] ANALYST cannot access ADMIN-only routes
  [PASS] VIEWER cannot access ADMIN-only routes
  [PASS] ADMIN can access ANALYST routes
  [PASS] ANALYST can access ANALYST routes
  [PASS] VIEWER cannot access ANALYST routes
  [PASS] ADMIN can access VIEWER routes
  [PASS] ANALYST can access VIEWER routes
  [PASS] VIEWER can access VIEWER routes

--- 5. Telemetry Ingestion Collector Authentication ---
  [PASS] Configured collector API key is accepted
  [PASS] Invalid collector API key is rejected
  [PASS] Undefined/empty collector API key is rejected

--- 6. In-Memory Rate Limiter (Token Bucket / Sliding Window) ---
  [PASS] Rate limiter allows request 1 of 5
  [PASS] Rate limiter allows request 2 of 5
  [PASS] Rate limiter allows request 3 of 5
  [PASS] Rate limiter allows request 4 of 5
  [PASS] Rate limiter allows request 5 of 5
  [PASS] Rate limiter blocks 6th request exceeding 5 req/window
  [PASS] Remaining quota reports 0
  [PASS] Retry-after window duration reported

--- 7. NoSQL Injection & Input Sanitization ---
  [PASS] Detects $gt and $ne injection operators
  [PASS] Neutralizes injection payload without crashing
  [PASS] Detects prototype pollution keys (__proto__, constructor)
  [PASS] Sanitizes object keys safely
  [PASS] Clean telemetry payload passes without modification
  [PASS] Preserves legitimate data integrity

--- 8. HTTP Security Headers Audit ---
  [PASS] X-Content-Type-Options is set to nosniff
  [PASS] X-Frame-Options is set to SAMEORIGIN
  [PASS] Referrer-Policy is set to strict-origin
  [PASS] Content-Security-Policy header is configured
  [PASS] CSP enforces default-src self

--- 9. Security Audit Logging ---
  [PASS] Audit service maintains traceable log entries
  [PASS] Security events (logins, failures, lockouts) are logged to audit trail

=============================================================
🏁 TEST RESULTS: 51/51 PASSED
✅ ALL SECURITY HARDENING TESTS PASSED WITH ZERO FAILURES
=============================================================
```

---

## 8. Modified & Added Files Summary

| File Path | Description of Changes |
| :--- | :--- |
| `src/types/auth.ts` | Defined user account, role (`ADMIN`, `ANALYST`, `VIEWER`), session, and auth response contracts |
| `src/services/auth/authService.ts` | Implemented PBKDF2 hashing, timing-safe verification, brute-force lockout, and session tokens |
| `src/middleware/authMiddleware.ts` | Built Express middleware (`requireAuth`, `requireRole`, `authenticateCollectorOrRole`) |
| `src/security/rateLimiter.ts` | Sliding window in-memory rate limiter with per-route policies and audit recording |
| `src/security/securityHeaders.ts` | Defensive HTTP headers middleware (CSP, HSTS, X-Content-Type-Options, etc.) |
| `src/security/requestValidator.ts` | NoSQL injection detection, prototype pollution neutralization, and parameter validation |
| `server.ts` | Mounted global security headers, rate limiters, auth router (`/api/auth/*`), protected endpoints with RBAC, and sanitized error responses |
| `src/components/layout/UserRoleDropdown.tsx` | SOC header interface for switching roles, viewing session tokens, and testing RBAC access |
| `src/components/layout/Header.tsx` | Integrated `UserRoleDropdown` into navigation bar with live user role badge |
| `src/services/apiClient.ts` | Added `ensureAuthenticated` bootstrapping, session token attachment to requests, and auth subscribers |
| `src/App.tsx` | Connected session initialization and reactive re-fetch on role changes |
| `src/tests/securityHardeningTestSuite.ts` | Comprehensive 51-point security verification test suite |
| `package.json` | Added `test:security` and unified `test` scripts |
| `.env.example` | Documented all security variables, secrets, and credential formats |

---

## 9. Security Limitations & Operational Recommendations

1. **In-Memory Session Storage:** Active sessions and rate-limit buckets are maintained in memory for high-performance sub-millisecond lookups. If the container restarts, active sessions require re-authentication. For distributed multi-instance clusters, back sessions with Redis or MongoDB.
2. **TLS Termination:** Production deployments on Google Cloud Run automatically terminate TLS/HTTPS at the load balancer; ensuring strict HSTS headers protects traffic end-to-end.
3. **Secret Rotation:** Telemetry collector API keys (`BACKEND_API_KEY`) and SOC administrator passwords should be rotated every 90 days in accordance with organizational security policies.
