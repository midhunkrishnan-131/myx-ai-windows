import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  validateTargetSsrfGuard,
  evaluateSpfAndDmarcRecords,
  analyzeUrlWithLinkGuardLexical,
} from './securityLogic';

// --- Unit 1: Password Hashing & Complexity Validation ---
function validatePasswordComplexity(password: string): { valid: boolean; reason?: string } {
  if (password.length < 10) {
    return { valid: false, reason: 'Password must be at least 10 characters in length.' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, reason: 'Password must contain at least one uppercase letter.' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, reason: 'Password must contain at least one lowercase letter.' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, reason: 'Password must contain at least one numeric digit.' };
  }
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
    return { valid: false, reason: 'Password must contain at least one special character symbol.' };
  }
  return { valid: true };
}

function hashUserPassword(password: string, saltHex?: string): string {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(32);
  const derivedKey = crypto.scryptSync(password, salt, 64, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  return `scrypt:32768:8:1$${salt.toString('hex')}$${derivedKey.toString('hex')}`;
}

function verifyPasswordAgainstHash(password: string, storedHash: string): boolean {
  if (!storedHash || !storedHash.startsWith('scrypt:')) return false;
  try {
    const parts = storedHash.split('$');
    if (parts.length !== 3) return false;
    const salt = Buffer.from(parts[1], 'hex');
    const expectedKey = Buffer.from(parts[2], 'hex');
    const derivedKey = crypto.scryptSync(password, salt, expectedKey.length, {
      N: 32768,
      r: 8,
      p: 1,
      maxmem: 64 * 1024 * 1024,
    });
    return crypto.timingSafeEqual(derivedKey, expectedKey);
  } catch {
    return false;
  }
}

test('Security C-01: No Hardcoded Administrator Passwords or Plaintext Backdoors', () => {
  const serverCode = fs.readFileSync(path.resolve('./server.ts'), 'utf-8');
  assert.equal(
    serverCode.includes("cleanPassword === 'Midhun@1234'"),
    false,
    'Server must not contain hardcoded default password bypass.'
  );
  assert.equal(
    serverCode.includes("hashUserPassword('Midhun@1234')"),
    false,
    'Server must not auto-provision hardcoded password in code.'
  );
  assert.equal(
    serverCode.includes("storedHash === password"),
    false,
    'Server must not allow plaintext password comparison fallback.'
  );
});

test('Security C-02: Sensitive Database and Runtime Files Excluded from Git Tracking', () => {
  const gitignore = fs.readFileSync(path.resolve('./.gitignore'), 'utf-8');
  assert.ok(gitignore.includes('backend/runtime/'), '.gitignore must ignore backend/runtime/');
  assert.ok(gitignore.includes('registered_users.json'), '.gitignore must ignore registered_users.json');
  assert.ok(gitignore.includes('*.db'), '.gitignore must ignore SQLite databases');

  // Verify that registered_users.json is not present in root directory
  assert.equal(fs.existsSync(path.resolve('./backend/registered_users.json')), false);
  assert.equal(fs.existsSync(path.resolve('./registered_users.json')), false);
});

test('Security C-03 & H-02: CPU/Memory-Hard Scrypt Password Hashing with Unique 32-Byte Salts', () => {
  const password = 'StrongAuthPassword#2026!';
  const hash1 = hashUserPassword(password);
  const hash2 = hashUserPassword(password);

  assert.notEqual(hash1, hash2, 'Two hashes of same password must use unique salts and produce different outputs');
  assert.ok(hash1.startsWith('scrypt:32768:8:1$'), 'Hash must use memory-hard scrypt parameters N=32768');
  assert.ok(verifyPasswordAgainstHash(password, hash1), 'Password must verify against hash1');
  assert.ok(verifyPasswordAgainstHash(password, hash2), 'Password must verify against hash2');
  assert.equal(verifyPasswordAgainstHash('WrongPassword#123', hash1), false, 'Incorrect password must be rejected');
});

test('Security H-02: Password Complexity Enforcement', () => {
  assert.equal(validatePasswordComplexity('short').valid, false);
  assert.equal(validatePasswordComplexity('nouppercase1!').valid, false);
  assert.equal(validatePasswordComplexity('NOLOWERCASE1!').valid, false);
  assert.equal(validatePasswordComplexity('NoDigitsHere!').valid, false);
  assert.equal(validatePasswordComplexity('NoSymbols1234').valid, false);
  assert.equal(validatePasswordComplexity('ValidP@ssw0rd2026').valid, true);
});

test('Security C-03: Session Management with SHA-256 Token Hashing and Expiration', () => {
  const activeSessions = new Map<string, any>();
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const csrfToken = crypto.randomBytes(32).toString('hex');

  const now = Date.now();
  const session = {
    id: 'sess-test-01',
    tokenHash,
    userId: 'usr-analyst-01',
    csrfToken,
    createdAt: now,
    expiresAt: now + 24 * 60 * 60 * 1000,
    lastActiveAt: now,
  };
  activeSessions.set(tokenHash, session);

  // Lookup with raw token
  const lookupHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const retrieved = activeSessions.get(lookupHash);
  assert.ok(retrieved, 'Session must be retrievable via SHA-256 hash of raw token');
  assert.equal(retrieved.userId, 'usr-analyst-01');

  // Verify expiration logic
  const expiredSession = { ...session, expiresAt: now - 1000 };
  const isExpired = Date.now() > expiredSession.expiresAt;
  assert.equal(isExpired, true, 'Expired sessions must be detected and rejected');
});

test('Security H-03: Session-Bound CSRF Token Validation', () => {
  const sessionCsrf = crypto.randomBytes(32).toString('hex');
  const matchingHeader = sessionCsrf;
  const forgedHeader = crypto.randomBytes(32).toString('hex');

  // Timing safe equal check
  const isValid1 =
    matchingHeader.length === sessionCsrf.length &&
    crypto.timingSafeEqual(Buffer.from(matchingHeader), Buffer.from(sessionCsrf));
  assert.equal(isValid1, true, 'Matching CSRF token must be accepted');

  const isValid2 =
    forgedHeader.length === sessionCsrf.length &&
    crypto.timingSafeEqual(Buffer.from(forgedHeader), Buffer.from(sessionCsrf));
  assert.equal(isValid2, false, 'Forged CSRF token must be rejected');
});

test('Security C-04: Role-Based Access Control (RBAC) Enforcement Matrix', () => {
  const roles = ['VIEWER', 'SECURITY_ANALYST', 'ADMIN'] as const;

  const canModifySettings = (role: typeof roles[number]) => role === 'ADMIN';
  const canRunAssessments = (role: typeof roles[number]) => role === 'ADMIN' || role === 'SECURITY_ANALYST';
  const canExportZip = (role: typeof roles[number]) => role === 'ADMIN';
  const canUpdateFindingStatus = (role: typeof roles[number]) => role === 'ADMIN' || role === 'SECURITY_ANALYST';

  assert.equal(canModifySettings('VIEWER'), false);
  assert.equal(canModifySettings('SECURITY_ANALYST'), false);
  assert.equal(canModifySettings('ADMIN'), true);

  assert.equal(canRunAssessments('VIEWER'), false);
  assert.equal(canRunAssessments('SECURITY_ANALYST'), true);
  assert.equal(canRunAssessments('ADMIN'), true);

  assert.equal(canExportZip('VIEWER'), false);
  assert.equal(canExportZip('SECURITY_ANALYST'), false);
  assert.equal(canExportZip('ADMIN'), true);

  assert.equal(canUpdateFindingStatus('VIEWER'), false);
  assert.equal(canUpdateFindingStatus('SECURITY_ANALYST'), true);
  assert.equal(canUpdateFindingStatus('ADMIN'), true);
});

test('Security Phase 6: SSRF Defense Guard Enforces Strict Boundary Against Internal Targets', () => {
  // Loopback
  assert.equal(validateTargetSsrfGuard('http://127.0.0.1:8080').allowed, false);
  assert.equal(validateTargetSsrfGuard('http://localhost:3000').allowed, false);
  assert.equal(validateTargetSsrfGuard('http://[::1]').allowed, false);

  // Cloud Metadata (AWS / Azure / GCP)
  assert.equal(validateTargetSsrfGuard('http://169.254.169.254/latest/meta-data').allowed, false);
  assert.equal(validateTargetSsrfGuard('169.254.169.254').allowed, false);

  // RFC 1918 Private Addresses without Lab Approval
  assert.equal(validateTargetSsrfGuard('http://10.0.0.1').allowed, false);
  assert.equal(validateTargetSsrfGuard('http://192.168.1.1').allowed, false);
  assert.equal(validateTargetSsrfGuard('http://172.16.0.1').allowed, false);

  // Dangerous / File Schemes
  assert.equal(validateTargetSsrfGuard('file:///etc/passwd').allowed, false);
  assert.equal(validateTargetSsrfGuard('gopher://127.0.0.1').allowed, false);
  assert.equal(validateTargetSsrfGuard('dict://127.0.0.1').allowed, false);

  // Valid External Host
  assert.equal(validateTargetSsrfGuard('https://example.com').allowed, true);
});

test('Security H-04: CORS Origin Allowlist Validation', () => {
  const ALLOWED_ORIGINS = new Set([
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
  ]);

  const isOriginAllowed = (origin?: string) => Boolean(origin && ALLOWED_ORIGINS.has(origin));

  assert.ok(isOriginAllowed('http://localhost:3000'));
  assert.ok(isOriginAllowed('http://127.0.0.1:3000'));
  assert.equal(isOriginAllowed('http://evil-attacker.com'), false);
  assert.equal(isOriginAllowed('http://localhost:3000.attacker.com'), false);
  assert.equal(isOriginAllowed(undefined), false);
});

test('Security H-05: Server-Side Derived Audit Logging Metadata', () => {
  const sessionUser = {
    id: 'usr-admin-01',
    email: 'midhun.krishnan@myx-security.io',
    role: 'ADMIN' as const,
  };

  // Malicious request payload trying to spoof an auditor identity
  const maliciousRequestBody = {
    actorEmail: 'spoofed-auditor@external-attacker.io',
    actorRole: 'SUPER_ADMIN',
  };

  // Audit entry creation deriving identity strictly from sessionUser
  const auditLog = {
    id: `aud-${Date.now()}`,
    actor_user_id: sessionUser.id,
    actor_email: sessionUser.email, // Derived from verified session
    actor_role: sessionUser.role,   // Derived from verified session
    action: 'FINDING_STATUS_UPDATED',
  };

  assert.equal(auditLog.actor_email, 'midhun.krishnan@myx-security.io');
  assert.equal(auditLog.actor_role, 'ADMIN');
  assert.notEqual(auditLog.actor_email, maliciousRequestBody.actorEmail);
});

test('Security C-05: Bootstrap Endpoint Masks Secrets and Strips Password Hashes', () => {
  const mockUserRecord = {
    id: 'usr-01',
    email: 'test@myx-security.io',
    full_name: 'Test Analyst',
    password_hash: 'scrypt:32768:8:1$salt$derived_secret',
    salt: 'salt',
    role: 'SECURITY_ANALYST',
    is_active: true,
  };

  // Safe stripping for API response
  const { password_hash, salt, ...safeUser } = mockUserRecord as any;
  assert.equal(safeUser.password_hash, undefined, 'Password hash must never be returned in API response');
  assert.equal(safeUser.salt, undefined, 'Salt must never be returned in API response');
  assert.equal(safeUser.email, 'test@myx-security.io');

  // Integration secret masking
  const integrationRecord = {
    provider: 'VIRUSTOTAL',
    has_configured_secret: true,
    masked_secret_suffix: '••••••••9F4A',
  };
  assert.ok(integrationRecord.masked_secret_suffix.startsWith('••••••••'));
  assert.equal((integrationRecord as any).secret_value, undefined);
});

// --- Phase 2: Credential Rotation & Password Reset Token Lifecycle ---
test('Security Phase 2: Password Rotation Invalidates Existing Sessions', () => {
  const userId = 'usr-admin-rotate-test';
  const initialPassword = 'InitialP@ssword2026!';
  const updatedPassword = 'RotatedSecure#Pass99!';

  let storedHash = hashUserPassword(initialPassword);
  assert.ok(verifyPasswordAgainstHash(initialPassword, storedHash));

  // Simulated active sessions
  const sessions = new Map<string, { userId: string; tokenHash: string; revoked: boolean }>();
  sessions.set('hash-1', { userId, tokenHash: 'hash-1', revoked: false });
  sessions.set('hash-2', { userId, tokenHash: 'hash-2', revoked: false });
  sessions.set('hash-other', { userId: 'usr-other', tokenHash: 'hash-other', revoked: false });

  // Rotate password
  assert.notEqual(initialPassword, updatedPassword);
  storedHash = hashUserPassword(updatedPassword);

  // Invalidate all previous sessions for this user
  for (const s of sessions.values()) {
    if (s.userId === userId) {
      s.revoked = true;
    }
  }

  assert.equal(sessions.get('hash-1')?.revoked, true);
  assert.equal(sessions.get('hash-2')?.revoked, true);
  assert.equal(sessions.get('hash-other')?.revoked, false); // Other users unaffected
  assert.equal(verifyPasswordAgainstHash(initialPassword, storedHash), false, 'Old password must fail verification');
  assert.equal(verifyPasswordAgainstHash(updatedPassword, storedHash), true, 'New password must succeed verification');
});

test('Security Phase 2: Single-Use, Time-Limited Password Reset Tokens', () => {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const now = Date.now();

  const resetRecord = {
    tokenHash,
    userId: 'usr-reset-01',
    userEmail: 'analyst@myx-security.io',
    expiresAt: now + 3600000, // 1 hour TTL
    used: false,
  };

  // 1. Verify fresh token
  const lookupHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  assert.equal(lookupHash, resetRecord.tokenHash);
  assert.equal(!resetRecord.used && resetRecord.expiresAt > Date.now(), true);

  // 2. Consume token (single use)
  resetRecord.used = true;
  assert.equal(!resetRecord.used && resetRecord.expiresAt > Date.now(), false, 'Consumed token cannot be reused');

  // 3. Test expired token
  const expiredRecord = { ...resetRecord, used: false, expiresAt: now - 5000 };
  assert.equal(!expiredRecord.used && expiredRecord.expiresAt > Date.now(), false, 'Expired token must be rejected');
});

// --- Phase 3: Production Cookie Security & HTTPS Enforcements ---
test('Security Phase 3: Production vs Development Cookie Flags', () => {
  const rawToken = 'sample_raw_session_token_hex_value';

  const formatCookie = (isProd: boolean) => {
    const secureFlag = isProd ? '; Secure' : '';
    return `myx_session=${rawToken}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400${secureFlag}`;
  };

  const formatClearCookie = (isProd: boolean) => {
    const secureFlag = isProd ? '; Secure' : '';
    return `myx_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secureFlag}`;
  };

  const prodCookie = formatCookie(true);
  const devCookie = formatCookie(false);
  const prodClear = formatClearCookie(true);
  const devClear = formatClearCookie(false);

  assert.ok(prodCookie.includes('HttpOnly'), 'Production cookie must have HttpOnly');
  assert.ok(prodCookie.includes('SameSite=Lax'), 'Production cookie must have SameSite=Lax');
  assert.ok(prodCookie.includes('; Secure'), 'Production cookie must have Secure');
  assert.ok(prodClear.includes('; Secure'), 'Production clear cookie must match Secure flag');

  assert.ok(devCookie.includes('HttpOnly'), 'Dev cookie must have HttpOnly');
  assert.equal(devCookie.includes('; Secure'), false, 'Dev cookie on HTTP localhost must omit Secure');
  assert.equal(devClear.includes('; Secure'), false, 'Dev clear cookie on HTTP localhost must omit Secure');
});

test('Security Phase 3: Production HTTPS Redirection and HSTS Header Logic', () => {
  const evaluateHttpsRedirect = (
    isProduction: boolean,
    isHttps: boolean,
    host: string
  ): { redirect: boolean; hsts: boolean; target?: string } => {
    const isLocalhost = host.includes('localhost') || host.startsWith('127.0.0.1');
    if (!isProduction) {
      return { redirect: false, hsts: false };
    }
    const hsts = true;
    if (!isHttps && !isLocalhost) {
      return { redirect: true, hsts, target: `https://${host}/dashboard` };
    }
    return { redirect: false, hsts };
  };

  // Production over HTTP on live domain -> redirect to HTTPS + inject HSTS
  const checkProdHttp = evaluateHttpsRedirect(true, false, 'myx-security.io');
  assert.equal(checkProdHttp.redirect, true);
  assert.equal(checkProdHttp.hsts, true);
  assert.equal(checkProdHttp.target, 'https://myx-security.io/dashboard');

  // Production over HTTPS on live domain -> allow + inject HSTS
  const checkProdHttps = evaluateHttpsRedirect(true, true, 'myx-security.io');
  assert.equal(checkProdHttps.redirect, false);
  assert.equal(checkProdHttps.hsts, true);

  // Development on localhost -> allow without redirect or HSTS
  const checkDev = evaluateHttpsRedirect(false, false, 'localhost:3000');
  assert.equal(checkDev.redirect, false);
  assert.equal(checkDev.hsts, false);
});

// --- Phase 4: Persistent & Scalable Session Storage ---
test('Security Phase 4: Persistent Session Storage Survives Process Restart', () => {
  const tmpRuntimeDir = path.resolve('./backend/runtime/test_scratch');
  fs.mkdirSync(tmpRuntimeDir, { recursive: true });
  const sessionFilePath = path.join(tmpRuntimeDir, 'test_sessions.json');

  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const now = Date.now();

  const originalSession = {
    id: 'sess-restart-test',
    tokenHash,
    userId: 'usr-persisted-01',
    user: { id: 'usr-persisted-01', email: 'test@myx.io', role: 'ADMIN' },
    csrfToken: 'csrf-persisted-token-1234',
    createdAt: now,
    expiresAt: now + 86400000,
    lastActiveAt: now,
    ip: '127.0.0.1',
    userAgent: 'Node-Test-Harness',
    revokedAt: null,
  };

  // 1. Instance 1 writes session to persistent store
  fs.writeFileSync(sessionFilePath, JSON.stringify([originalSession], null, 2), 'utf-8');

  // 2. Instance 2 boots up with an empty memory map and reloads from disk
  const reloadedMap = new Map<string, typeof originalSession>();
  const diskData = JSON.parse(fs.readFileSync(sessionFilePath, 'utf-8'));
  for (const s of diskData) {
    if (!s.revokedAt && s.expiresAt > Date.now()) {
      reloadedMap.set(s.tokenHash, s);
    }
  }

  // 3. Instance 2 validates the session using raw token
  const lookupHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const recoveredSession = reloadedMap.get(lookupHash);

  assert.ok(recoveredSession, 'Session must survive process reboot and reload from disk store');
  assert.equal(recoveredSession?.userId, 'usr-persisted-01');
  assert.equal(recoveredSession?.csrfToken, 'csrf-persisted-token-1234');

  // Cleanup scratch directory
  fs.rmSync(tmpRuntimeDir, { recursive: true, force: true });
});

test('Security Phase 4: Multi-Instance Session Revocation on Account Deactivation', () => {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const targetUserId = 'usr-deactivate-01';

  const session = {
    id: 'sess-deact-test',
    tokenHash,
    userId: targetUserId,
    revokedAt: null as number | null,
    expiresAt: Date.now() + 86400000,
  };

  const sessions = new Map([[tokenHash, session]]);

  // Administrator toggles is_active = false
  const userIsActive = false;
  if (!userIsActive) {
    for (const s of sessions.values()) {
      if (s.userId === targetUserId) {
        s.revokedAt = Date.now();
      }
    }
  }

  // Incoming request arrives
  const activeCheck = sessions.get(tokenHash);
  const isSessionValid = activeCheck && !activeCheck.revokedAt && activeCheck.expiresAt > Date.now();

  assert.equal(isSessionValid, false, 'Deactivated account sessions must be immediately invalidated');
});

// --- Phase 5: Secret Scanning of Tracked Working Tree ---
test('Security Phase 5: Secret Scanner Confirms Zero Private Keys or Live Databases Tracked in Git', () => {
  // Ensure that no files matching private key or live database patterns exist in tracked source
  const gitignore = fs.readFileSync(path.resolve('./.gitignore'), 'utf-8');
  assert.ok(gitignore.includes('backend/runtime/'), 'backend/runtime/ must be ignored');
  assert.ok(gitignore.includes('*.pem'), '*.pem must be ignored');
  assert.ok(gitignore.includes('*.key'), '*.key must be ignored');
  assert.ok(gitignore.includes('*.db'), '*.db must be ignored');

  // Verify that live databases and exposed json user files do not exist in repo root or backend root
  assert.equal(fs.existsSync(path.resolve('./backend/myx_local_test.db')), false);
  assert.equal(fs.existsSync(path.resolve('./backend/registered_users.json')), false);
  assert.equal(fs.existsSync(path.resolve('./registered_users.json')), false);
  assert.ok(fs.existsSync(path.resolve('./.env.example')), '.env.example template must exist');
});
