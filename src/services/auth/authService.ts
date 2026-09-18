/**
 * AI-DRIVEN MULTI-AGENT CYBER THREAT DETECTION SYSTEM
 * Secure Authentication & Session Management Service
 * 
 * Implements:
 * - PBKDF2-SHA512 cryptographic password hashing with per-user unique salt
 * - Timing-safe password verification to resist side-channel attacks
 * - Cryptographically random 256-bit session tokens
 * - Exponential backoff / brute-force lockout after 5 consecutive failures
 * - Session revocation on logout
 * - Collector API Key validation for telemetry ingress
 */

import crypto from 'crypto';
import { UserRole, UserAccount, UserAccountInternal, AuthSession, AuthResponse } from '../../types/auth';
import { auditService } from '../auditService';

// Default session lifespan: 8 hours
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
// Max failed login attempts before temporary lockout
const MAX_FAILED_ATTEMPTS = 5;
// Lockout duration: 15 minutes
const LOCKOUT_DURATION_MS = 15 * 60 * 1000;

function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 25000, 64, 'sha512').toString('hex');
}

function timingSafeVerify(enteredPassword: string, storedHash: string, salt: string): boolean {
  try {
    const computedHash = hashPassword(enteredPassword, salt);
    const computedBuf = Buffer.from(computedHash, 'hex');
    const storedBuf = Buffer.from(storedHash, 'hex');
    if (computedBuf.length !== storedBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(computedBuf, storedBuf);
  } catch {
    return false;
  }
}

class AuthService {
  private users: Map<string, UserAccountInternal> = new Map();
  private sessions: Map<string, AuthSession> = new Map();

  constructor() {
    this.seedInitialAccounts();
  }

  private seedInitialAccounts(): void {
    const adminPassword = process.env.ADMIN_INITIAL_PASSWORD || 'Admin@SOC2026!#Secure';
    const analystPassword = process.env.ANALYST_INITIAL_PASSWORD || 'Analyst@Cyber2026!';
    const viewerPassword = process.env.VIEWER_INITIAL_PASSWORD || 'Viewer@Auditor2026!';

    this.createUserInternal(
      'USR-ADMIN-01',
      'admin',
      'admin@soc.defense.net',
      'ADMIN',
      'Security Administrator',
      'SOC Operations & Engineering',
      adminPassword
    );

    this.createUserInternal(
      'USR-ANALYST-01',
      'analyst',
      'analyst@soc.defense.net',
      'ANALYST',
      'Sarah Connor (Tier-2)',
      'Incident Response Team',
      analystPassword
    );

    this.createUserInternal(
      'USR-VIEWER-01',
      'viewer',
      'auditor@compliance.org',
      'VIEWER',
      'Auditor & Compliance View',
      'External Audit & Governance',
      viewerPassword
    );
  }

  private createUserInternal(
    id: string,
    username: string,
    email: string,
    role: UserRole,
    displayName: string,
    department: string,
    plaintextPassword: string
  ): void {
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPassword(plaintextPassword, salt);

    const user: UserAccountInternal = {
      id,
      username: username.toLowerCase().trim(),
      email,
      role,
      displayName,
      department,
      createdAt: new Date().toISOString(),
      failedLoginAttempts: 0,
      isLocked: false,
      passwordHash,
      salt
    };

    this.users.set(user.username, user);
  }

  public toPublicUser(internal: UserAccountInternal): UserAccount {
    const { passwordHash: _p, salt: _s, ...rest } = internal;
    return rest;
  }

  public async authenticate(
    usernameInput: string,
    passwordInput: string,
    ipAddress: string,
    userAgent?: string
  ): Promise<AuthResponse> {
    const username = (usernameInput || '').toLowerCase().trim();
    const user = this.users.get(username);

    if (!user) {
      // Record failed authentication attempt
      auditService.recordAction({
        action: 'AUTHENTICATION_FAILURE',
        entityType: 'USER',
        entityId: username || 'UNKNOWN_USER',
        actor: 'AuthGuard',
        details: `Failed authentication attempt for unknown username '${username}' from IP ${ipAddress}.`,
        metadata: { ipAddress, userAgent, reason: 'USER_NOT_FOUND' }
      });
      return { success: false, error: 'Invalid username or password.', code: 'INVALID_CREDENTIALS' };
    }

    // Check account lockout status
    const now = Date.now();
    if (user.isLocked) {
      if (user.lockUntil && new Date(user.lockUntil).getTime() > now) {
        auditService.recordAction({
          action: 'AUTHENTICATION_FAILURE',
          entityType: 'USER',
          entityId: user.id,
          actor: 'AuthGuard',
          details: `Rejected login attempt on locked account '${user.username}' from IP ${ipAddress}.`,
          metadata: { ipAddress, lockUntil: user.lockUntil, reason: 'ACCOUNT_LOCKED' }
        });
        return {
          success: false,
          error: `Account is temporarily locked due to excessive failed attempts. Try again after ${new Date(user.lockUntil).toLocaleTimeString()}.`,
          code: 'ACCOUNT_LOCKED'
        };
      } else {
        // Lockout expired, reset counter
        user.isLocked = false;
        user.failedLoginAttempts = 0;
        user.lockUntil = undefined;
      }
    }

    // Verify password using timing-safe comparison
    const isValid = timingSafeVerify(passwordInput || '', user.passwordHash, user.salt);

    if (!isValid) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
        user.isLocked = true;
        user.lockUntil = new Date(now + LOCKOUT_DURATION_MS).toISOString();

        auditService.recordAction({
          action: 'ACCOUNT_LOCKED',
          entityType: 'USER',
          entityId: user.id,
          actor: 'AuthGuard',
          details: `Account '${user.username}' locked for 15 minutes following ${MAX_FAILED_ATTEMPTS} consecutive failed attempts from IP ${ipAddress}.`,
          metadata: { ipAddress, lockUntil: user.lockUntil }
        });

        return {
          success: false,
          error: 'Maximum failed login attempts exceeded. Account is locked for 15 minutes.',
          code: 'ACCOUNT_LOCKED'
        };
      }

      auditService.recordAction({
        action: 'AUTHENTICATION_FAILURE',
        entityType: 'USER',
        entityId: user.id,
        actor: 'AuthGuard',
        details: `Invalid password attempt (${user.failedLoginAttempts}/${MAX_FAILED_ATTEMPTS}) for user '${user.username}' from IP ${ipAddress}.`,
        metadata: { ipAddress, failedAttempts: user.failedLoginAttempts }
      });

      return { success: false, error: 'Invalid username or password.', code: 'INVALID_CREDENTIALS' };
    }

    // Successful authentication: Reset failed counter, generate session
    user.failedLoginAttempts = 0;
    user.isLocked = false;
    user.lockUntil = undefined;
    user.lastLoginAt = new Date().toISOString();

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(now + SESSION_TTL_MS).toISOString();

    const session: AuthSession = {
      token,
      userId: user.id,
      username: user.username,
      role: user.role,
      displayName: user.displayName,
      createdAt: new Date(now).toISOString(),
      expiresAt,
      ipAddress,
      userAgent
    };

    this.sessions.set(token, session);

    auditService.recordAction({
      action: 'LOGIN_SUCCESS',
      entityType: 'USER',
      entityId: user.id,
      actor: `${user.displayName} (${user.role})`,
      details: `User '${user.username}' successfully authenticated with role ${user.role} from IP ${ipAddress}.`,
      metadata: { ipAddress, userAgent, role: user.role }
    });

    return {
      success: true,
      token,
      expiresAt,
      user: this.toPublicUser(user)
    };
  }

  public validateSession(token?: string): AuthSession | null {
    if (!token) return null;
    const session = this.sessions.get(token);
    if (!session) return null;

    // Check expiration
    if (new Date(session.expiresAt).getTime() <= Date.now()) {
      this.sessions.delete(token);
      return null;
    }

    return session;
  }

  public revokeSession(token: string, actor = 'User'): boolean {
    const session = this.sessions.get(token);
    if (session) {
      this.sessions.delete(token);
      auditService.recordAction({
        action: 'LOGOUT',
        entityType: 'USER',
        entityId: session.userId,
        actor: `${session.displayName} (${session.role})`,
        details: `Session revoked for user '${session.username}'.`,
        metadata: { ipAddress: session.ipAddress, revokedBy: actor }
      });
      return true;
    }
    return false;
  }

  public verifyCollectorApiKey(providedKey?: string): boolean {
    if (!providedKey) return false;
    const expectedKey = process.env.BACKEND_API_KEY || 'soc-telemetry-collector-prod-key-2026';
    
    // Constant-time check
    try {
      const a = Buffer.from(providedKey);
      const b = Buffer.from(expectedKey);
      if (a.length !== b.length) return false;
      return crypto.timingSafeEqual(a, b);
    } catch {
      return false;
    }
  }

  public async login(
    usernameInput: string,
    passwordInput: string,
    ipAddress = '127.0.0.1',
    userAgent?: string
  ): Promise<AuthResponse> {
    return this.authenticate(usernameInput, passwordInput, ipAddress, userAgent);
  }

  public registerUser(
    username: string,
    email: string,
    role: UserRole,
    displayName: string,
    department: string,
    passwordPlain: string
  ): UserAccount {
    const id = `USR-${Date.now()}`;
    this.createUserInternal(id, username, email, role, displayName, department, passwordPlain);
    return this.getUser(username)!;
  }

  public validateCollectorApiKey(providedKey?: string): boolean {
    return this.verifyCollectorApiKey(providedKey);
  }

  public getUser(username: string): UserAccount | null {
    const u = this.users.get(username.toLowerCase().trim());
    return u ? this.toPublicUser(u) : null;
  }

  public listUsers(): UserAccount[] {
    return Array.from(this.users.values()).map(u => this.toPublicUser(u));
  }
}

export const authService = new AuthService();
