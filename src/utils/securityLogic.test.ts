import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateTargetSsrfGuard,
  analyzeUrlWithLinkGuardLexical,
  calculateCvss31Score,
  evaluateSpfAndDmarcRecords,
  checkRolePermission,
} from './securityLogic';

test('SSRF Guard unconditionally blocks loopback, localhost, and cloud metadata 169.254.169.254', () => {
  const loopback = validateTargetSsrfGuard('http://127.0.0.1:8080/admin');
  assert.equal(loopback.allowed, false);
  assert.equal(loopback.isLoopback, true);

  const localhostCheck = validateTargetSsrfGuard('https://localhost/health');
  assert.equal(localhostCheck.allowed, false);

  // Even when lab mode and admin approval are true, 169.254.169.254 MUST be blocked
  const metadataCheck = validateTargetSsrfGuard('http://169.254.169.254/latest/meta-data/', true, true);
  assert.equal(metadataCheck.allowed, false);
  assert.equal(metadataCheck.isCloudMetadata, true);
});

test('SSRF Guard blocks RFC 1918 private IPs by default and allows only when lab mode + admin approval are active', () => {
  const defaultPrivate = validateTargetSsrfGuard('https://192.168.1.50:8443', false, false);
  assert.equal(defaultPrivate.allowed, false);
  assert.equal(defaultPrivate.isPrivateRfc1918, true);

  const approvedLab = validateTargetSsrfGuard('https://192.168.1.50:8443', true, true);
  assert.equal(approvedLab.allowed, true);
  assert.equal(approvedLab.isPrivateRfc1918, true);
});

test('SSRF Guard blocks non-HTTP schemes like file:// and gopher://', () => {
  const fileScheme = validateTargetSsrfGuard('file:///etc/passwd');
  assert.equal(fileScheme.allowed, false);

  const gopherScheme = validateTargetSsrfGuard('gopher://10.0.0.1:70');
  assert.equal(gopherScheme.allowed, false);
});

test('LinkGuard AI detects Punycode IDN homograph and executable payload tricks', () => {
  const homograph = analyzeUrlWithLinkGuardLexical('https://xn--pple-43d.com/auth/verify.exe');
  assert.equal(homograph.verdict, 'Suspicious');
  assert.equal(homograph.lexical_signals.is_punycode_idn, true);
  assert.equal(homograph.lexical_signals.suspicious_extension, '.exe');
  assert.ok(homograph.risk_score >= 70);

  const clean = analyzeUrlWithLinkGuardLexical('https://portal.contoso-enterprise.org/docs');
  assert.equal(clean.verdict, 'No Known Threat Detected');
});

test('CVSS v3.1 calculator computes standard vectors accurately', () => {
  // Log4Shell style 10.0 Critical vector
  const crit = calculateCvss31Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
  assert.equal(crit.valid, true);
  assert.equal(crit.baseScore, 10.0);
  assert.equal(crit.severity, 'Critical');

  // Medium severity header misconfiguration vector
  const med = calculateCvss31Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N');
  assert.equal(med.valid, true);
  assert.equal(med.baseScore, 5.4);
  assert.equal(med.severity, 'Medium');
});

test('SPF and DMARC analyzer flags +all pass-all and p=none monitoring policies', () => {
  const weak = evaluateSpfAndDmarcRecords(
    ['v=spf1 include:_spf.google.com +all'],
    ['v=DMARC1; p=none; rua=mailto:soc@example.com']
  );
  assert.equal(weak.spf.status, 'FAIL');
  assert.equal(weak.spf.all_qualifier, '+all');
  assert.equal(weak.dmarc.status, 'WARNING');
  assert.equal(weak.dmarc.policy, 'none');

  const strong = evaluateSpfAndDmarcRecords(
    ['v=spf1 include:_spf.google.com -all'],
    ['v=DMARC1; p=reject; pct=100; adkim=s; aspf=s']
  );
  assert.equal(strong.spf.status, 'PASS');
  assert.equal(strong.dmarc.status, 'PASS');
});

test('RBAC permission engine enforces ADMIN, SECURITY_ANALYST, and VIEWER boundaries', () => {
  assert.equal(checkRolePermission('VIEWER', 'assessments:run'), false);
  assert.equal(checkRolePermission('VIEWER', 'findings:write'), false);
  assert.equal(checkRolePermission('VIEWER', 'findings:read'), true);
  assert.equal(checkRolePermission('SECURITY_ANALYST', 'assessments:run'), true);
  assert.equal(checkRolePermission('SECURITY_ANALYST', 'users:manage'), false);
  assert.equal(checkRolePermission('ADMIN', 'users:manage'), true);
});
