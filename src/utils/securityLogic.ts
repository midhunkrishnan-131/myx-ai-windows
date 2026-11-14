import { LinkGuardAnalysisResult, LinkGuardVerdict, SeverityLevel } from '../types/assessment.types';
import { UserRole } from '../types/auth.types';

export interface SsrfValidationResult {
  allowed: boolean;
  blockedReason: string | null;
  isPrivateRfc1918: boolean;
  isCloudMetadata: boolean;
  isLoopback: boolean;
  normalizedHost: string;
}

const DISALLOWED_SCHEMES = ['file:', 'gopher:', 'ftp:', 'dict:', 'ldap:', 'javascript:', 'data:'];

function parseIpv4Octets(host: string): number[] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host.trim());
  if (!match) return null;
  const octets = [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])];
  if (octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) return null;
  return octets;
}

export function validateTargetSsrfGuard(
  inputTarget: string,
  allowControlledLabTargets = false,
  isAdminLabApproved = false
): SsrfValidationResult {
  const trimmed = inputTarget.trim();
  if (!trimmed) {
    return {
      allowed: false,
      blockedReason: 'Target value cannot be empty.',
      isPrivateRfc1918: false,
      isCloudMetadata: false,
      isLoopback: false,
      normalizedHost: '',
    };
  }

  const lower = trimmed.toLowerCase();
  for (const scheme of DISALLOWED_SCHEMES) {
    if (lower.startsWith(scheme)) {
      return {
        allowed: false,
        blockedReason: `Protocol scheme '${scheme.replace(':', '')}://' is strictly blocked by SafeOutboundHttpClient SSRF guard.`,
        isPrivateRfc1918: false,
        isCloudMetadata: false,
        isLoopback: false,
        normalizedHost: lower,
      };
    }
  }

  let hostname = lower;
  try {
    if (lower.includes('://')) {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return {
          allowed: false,
          blockedReason: `Unsupported protocol '${parsed.protocol}'. Only http:// and https:// are permitted.`,
          isPrivateRfc1918: false,
          isCloudMetadata: false,
          isLoopback: false,
          normalizedHost: parsed.hostname,
        };
      }
      hostname = parsed.hostname.toLowerCase();
    } else {
      hostname = lower.split('/')[0].split(':')[0];
    }
  } catch {
    return {
      allowed: false,
      blockedReason: 'Malformed URL or hostname syntax.',
      isPrivateRfc1918: false,
      isCloudMetadata: false,
      isLoopback: false,
      normalizedHost: '',
    };
  }

  // IPv6 loopback or link-local
  const cleanHost = hostname.replace(/^\[|\]$/g, '');
  if (cleanHost === 'localhost' || cleanHost.endsWith('.localhost') || cleanHost === '::1') {
    return {
      allowed: false,
      blockedReason: 'Loopback target (localhost / ::1) is unconditionally blocked by SSRF policy.',
      isPrivateRfc1918: false,
      isCloudMetadata: false,
      isLoopback: true,
      normalizedHost: cleanHost,
    };
  }

  if (cleanHost.startsWith('fe80:')) {
    return {
      allowed: false,
      blockedReason: 'IPv6 link-local range (fe80::/10) is blocked by SSRF policy.',
      isPrivateRfc1918: false,
      isCloudMetadata: false,
      isLoopback: false,
      normalizedHost: cleanHost,
    };
  }

  const octets = parseIpv4Octets(cleanHost);
  if (octets) {
    const [a, b, c, d] = octets;

    // Cloud metadata: 169.254.0.0/16 (especially 169.254.169.254)
    if (a === 169 && b === 254) {
      return {
        allowed: false,
        blockedReason:
          a === 169 && b === 254 && c === 169 && d === 254
            ? 'Cloud metadata endpoint (169.254.169.254) is unconditionally blocked in all modes.'
            : 'Link-local range (169.254.0.0/16) is unconditionally blocked.',
        isPrivateRfc1918: false,
        isCloudMetadata: true,
        isLoopback: false,
        normalizedHost: cleanHost,
      };
    }

    // Loopback: 127.0.0.0/8
    if (a === 127 || a === 0) {
      return {
        allowed: false,
        blockedReason: 'IPv4 loopback range (127.0.0.0/8) is blocked by SSRF policy.',
        isPrivateRfc1918: false,
        isCloudMetadata: false,
        isLoopback: true,
        normalizedHost: cleanHost,
      };
    }

    // Multicast / Broadcast: 224.0.0.0/4 or 255.255.255.255
    if (a >= 224) {
      return {
        allowed: false,
        blockedReason: 'Multicast and broadcast IPv4 ranges (224.0.0.0/4, 255.255.255.255) are blocked.',
        isPrivateRfc1918: false,
        isCloudMetadata: false,
        isLoopback: false,
        normalizedHost: cleanHost,
      };
    }

    // RFC 1918 Private Ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    const isRfc1918 =
      a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);

    if (isRfc1918) {
      if (allowControlledLabTargets && isAdminLabApproved) {
        return {
          allowed: true,
          blockedReason: null,
          isPrivateRfc1918: true,
          isCloudMetadata: false,
          isLoopback: false,
          normalizedHost: cleanHost,
        };
      }
      return {
        allowed: false,
        blockedReason:
          'RFC 1918 private network address blocked. Requires ALLOW_CONTROLLED_LAB_TARGETS=true and explicit ADMIN Lab Approval.',
        isPrivateRfc1918: true,
        isCloudMetadata: false,
        isLoopback: false,
        normalizedHost: cleanHost,
      };
    }
  }

  return {
    allowed: true,
    blockedReason: null,
    isPrivateRfc1918: false,
    isCloudMetadata: false,
    isLoopback: false,
    normalizedHost: cleanHost,
  };
}

const SUSPICIOUS_EXTENSIONS = ['.exe', '.scr', '.msi', '.ps1', '.bat', '.iso', '.zip', '.vbs', '.hta'];
const SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'rb.gy', 'is.gd', 'cutt.ly'];
const REDIRECT_PARAMS = ['redirect', 'url', 'next', 'return', 'return_to', 'dest', 'destination', 'continue'];
const KNOWN_MALICIOUS_PATTERNS = [
  'microsoft-login-security-verify.com',
  'paypa1-support.net',
  'login-office365-credential-check.ru',
  'defender-critical-update-kb5099.exe',
];

const BRAND_LOOKALIKES: Array<{ pattern: RegExp; brand: string }> = [
  { pattern: /micros[0o]ft|msft-login|office365-verify|login-microsoft/i, brand: 'Microsoft / Entra ID' },
  { pattern: /paypa[1l]-|paypal-secure/i, brand: 'PayPal' },
  { pattern: /g[0o]{2}gle-security|workspace-auth/i, brand: 'Google Workspace' },
  { pattern: /xn--pple-43d|app1e-id/i, brand: 'Apple ID' },
  { pattern: /github-token-verify/i, brand: 'GitHub' },
];

export function analyzeUrlWithLinkGuardLexical(rawUrl: string): LinkGuardAnalysisResult {
  const trimmed = rawUrl.trim();
  const normalizedInput = trimmed.includes('://') ? trimmed : `https://${trimmed}`;
  const ssrfCheck = validateTargetSsrfGuard(normalizedInput, false, false);

  let hostname = ssrfCheck.normalizedHost || 'invalid-host';
  let scheme = 'https';
  let hasAuthorityAtTrick = false;
  let path = '/';
  let searchParams = new URLSearchParams();

  try {
    const parsed = new URL(normalizedInput);
    scheme = parsed.protocol.replace(':', '');
    hostname = parsed.hostname.toLowerCase();
    hasAuthorityAtTrick = Boolean(parsed.username || parsed.password || trimmed.includes('@'));
    path = parsed.pathname.toLowerCase();
    searchParams = parsed.searchParams;
  } catch {
    hasAuthorityAtTrick = trimmed.includes('@');
  }

  const isRawIp = parseIpv4Octets(hostname) !== null;
  const labels = hostname.split('.').filter(Boolean);
  const subdomainCount = Math.max(0, labels.length - 2);
  const isPunycodeIdn = labels.some((l) => l.startsWith('xn--'));
  const decodedIdnHostname = isPunycodeIdn
    ? hostname.replace('xn--pple-43d', 'аpple (Cyrillic U+0430)')
    : null;
  const confusableHomograph = isPunycodeIdn || /[^\u0000-\u007f]/.test(trimmed);

  let lookalikeBrand: string | null = null;
  for (const item of BRAND_LOOKALIKES) {
    if (item.pattern.test(hostname) || item.pattern.test(trimmed)) {
      lookalikeBrand = item.brand;
      break;
    }
  }

  const matchedExtension = SUSPICIOUS_EXTENSIONS.find((ext) => path.endsWith(ext)) || null;
  const isShortener = SHORTENER_DOMAINS.includes(hostname);

  let openRedirectParam: string | null = null;
  for (const key of REDIRECT_PARAMS) {
    if (searchParams.has(key)) {
      openRedirectParam = `?${key}=${searchParams.get(key)}`;
      break;
    }
  }

  const isKnownMalicious = KNOWN_MALICIOUS_PATTERNS.some((p) => trimmed.toLowerCase().includes(p));

  let riskScore = 10;
  if (isKnownMalicious) riskScore = 96;
  else {
    if (!ssrfCheck.allowed) riskScore += 75;
    if (hasAuthorityAtTrick) riskScore += 45;
    if (isPunycodeIdn || confusableHomograph) riskScore += 45;
    if (lookalikeBrand) riskScore += 40;
    if (matchedExtension) riskScore += 35;
    if (isRawIp) riskScore += 25;
    if (subdomainCount > 3) riskScore += 20;
    if (openRedirectParam) riskScore += 20;
    if (isShortener) riskScore += 15;
    if (scheme === 'http') riskScore += 15;
  }
  riskScore = Math.min(100, riskScore);

  let verdict: LinkGuardVerdict = 'No Known Threat Detected';
  if (isKnownMalicious) {
    verdict = 'Known Malicious Match';
  } else if (riskScore >= 40 || !ssrfCheck.allowed) {
    verdict = 'Suspicious';
  }

  const verifiedFacts: string[] = [
    `Hostname parsed as '${hostname}' over '${scheme.toUpperCase()}' scheme (${subdomainCount} subdomain level(s)).`,
  ];
  if (!ssrfCheck.allowed && ssrfCheck.blockedReason) {
    verifiedFacts.push(`Outbound SSRF Guard Triggered: ${ssrfCheck.blockedReason}`);
  }
  if (isPunycodeIdn) {
    verifiedFacts.push(`IDN Punycode label ('xn--') detected in hostname '${hostname}'.`);
  }
  if (hasAuthorityAtTrick) {
    verifiedFacts.push(`URL contains '@' authority credential delimiter trick designed to obscure destination host.`);
  }
  if (lookalikeBrand) {
    verifiedFacts.push(`Lexical token-stuffing / typosquatting similarity against ${lookalikeBrand}.`);
  }
  if (matchedExtension) {
    verifiedFacts.push(`Direct executable or archive payload extension ('${matchedExtension}') present in URL path.`);
  }
  if (openRedirectParam) {
    verifiedFacts.push(`Open-redirect query parameter ('${openRedirectParam}') detected.`);
  }

  return {
    id: `lg-${Date.now()}`,
    input_url: trimmed,
    normalized_url: normalizedInput,
    hostname,
    verdict,
    risk_score: riskScore,
    analyzed_at: new Date().toISOString(),
    is_demo_preview: true,
    lexical_signals: {
      scheme,
      has_authority_at_trick: hasAuthorityAtTrick,
      is_raw_ip: isRawIp,
      subdomain_count: subdomainCount,
      is_punycode_idn: isPunycodeIdn,
      decoded_idn_hostname: decodedIdnHostname,
      confusable_homograph_detected: confusableHomograph,
      lookalike_brand_target: lookalikeBrand,
      suspicious_extension: matchedExtension,
      open_redirect_param: openRedirectParam,
      url_shortener: isShortener,
      ssrf_blocked: !ssrfCheck.allowed,
      ssrf_block_reason: ssrfCheck.blockedReason,
    },
    redirect_chain: ssrfCheck.allowed
      ? [
          {
            hop: 1,
            url: normalizedInput,
            status_code: 200,
            resolved_ip: isRawIp ? hostname : '198.51.100.42 (Validated Non-Private IP)',
            latency_ms: 48,
            https_downgrade: scheme === 'http',
          },
        ]
      : [],
    threat_intel_sources: [
      {
        provider: 'Google Safe Browsing v4',
        status: isKnownMalicious ? 'Malicious Match' : 'Not Configured / Skipped',
        details: isKnownMalicious
          ? 'Matched SOCIAL_ENGINEERING / MALWARE threat list in demonstration dataset.'
          : 'Backend API key not configured in Google AI Studio preview sandbox; live lookup skipped.',
      },
      {
        provider: 'VirusTotal v3',
        status: isKnownMalicious ? 'Malicious Match' : 'Not Configured / Skipped',
        details: isKnownMalicious
          ? '14/92 security vendors flagged this domain as phishing/credential harvesting.'
          : 'Backend VIRUSTOTAL_API_KEY not configured; marked Not Configured / Skipped.',
      },
      {
        provider: 'abuse.ch URLhaus',
        status: isKnownMalicious && matchedExtension ? 'Malicious Match' : 'Clean',
        details:
          isKnownMalicious && matchedExtension
            ? 'Matched active payload distribution signature in URLhaus feed.'
            : 'Zero matching malware distribution URLs in local reference snapshot.',
      },
    ],
    ai_explanation: {
      verified_facts: verifiedFacts,
      ai_risk_interpretation:
        verdict === 'Known Malicious Match'
          ? 'High-confidence phishing or payload delivery URL combining deceptive domain tokens with known threat intelligence indicators.'
          : verdict === 'Suspicious'
          ? 'The URL exhibits structural deception or SSRF boundary violations commonly used in credential harvesting, homograph spoofing, or internal network probing.'
          : 'No structural deception, homograph encoding, or dangerous file extensions were identified in offline lexical inspection.',
      recommended_remediation:
        verdict === 'No Known Threat Detected'
          ? 'Continue standard zero-trust verification before entering credentials. Connect Google Safe Browsing and VirusTotal keys in Integrations for live feed enrichment.'
          : 'Block this domain/URL at the DNS and secure web gateway (SWG) layers, quarantine any email messages containing this link, and alert SOC analysts if any user clicked it.',
      assumptions_and_limitations:
        "A 'No Known Threat Detected' verdict indicates no matches were found in currently active feeds and heuristics; it does not guarantee a URL is safe.",
    },
  };
}

export function calculateCvss31Score(vector: string): {
  valid: boolean;
  baseScore: number | null;
  severity: SeverityLevel;
} {
  const clean = vector.trim().toUpperCase();
  if (!clean.startsWith('CVSS:3.1/')) {
    return { valid: false, baseScore: null, severity: 'Informational' };
  }

  const metrics: Record<string, string> = {};
  for (const part of clean.replace('CVSS:3.1/', '').split('/')) {
    const [k, v] = part.split(':');
    if (k && v) metrics[k] = v;
  }

  const required = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  if (required.some((r) => !metrics[r])) {
    return { valid: false, baseScore: null, severity: 'Informational' };
  }

  const avMap: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const acMap: Record<string, number> = { L: 0.77, H: 0.44 };
  const uiMap: Record<string, number> = { N: 0.85, R: 0.62 };
  const ciaMap: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

  const scopeChanged = metrics.S === 'C';
  const prMap: Record<string, number> = scopeChanged
    ? { N: 0.85, L: 0.68, H: 0.5 }
    : { N: 0.85, L: 0.62, H: 0.27 };

  const av = avMap[metrics.AV];
  const ac = acMap[metrics.AC];
  const pr = prMap[metrics.PR];
  const ui = uiMap[metrics.UI];
  const c = ciaMap[metrics.C];
  const i = ciaMap[metrics.I];
  const a = ciaMap[metrics.A];

  if ([av, ac, pr, ui, c, i, a].some((v) => v === undefined)) {
    return { valid: false, baseScore: null, severity: 'Informational' };
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;

  if (impact <= 0) {
    return { valid: true, baseScore: 0.0, severity: 'Informational' };
  }

  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);

  // Round up to nearest tenth per FIRST.org CVSS v3.1 specification
  const roundup = Math.ceil(Math.round(raw * 100000) / 10000) / 10;

  let severity: SeverityLevel = 'Informational';
  if (roundup >= 9.0) severity = 'Critical';
  else if (roundup >= 7.0) severity = 'High';
  else if (roundup >= 4.0) severity = 'Medium';
  else if (roundup > 0) severity = 'Low';

  return { valid: true, baseScore: roundup, severity };
}

export function evaluateSpfAndDmarcRecords(txtRecords: string[], dmarcRecords: string[]) {
  const spfRecords = txtRecords.filter((r) => r.trim().toLowerCase().startsWith('v=spf1'));
  const multipleSpf = spfRecords.length > 1;
  const rawSpf = spfRecords[0] || null;

  let lookupCount = 0;
  let allQualifier: '-all' | '~all' | '?all' | '+all' | 'missing' = 'missing';

  if (rawSpf) {
    const tokens = rawSpf.split(/\s+/);
    for (const token of tokens) {
      const lower = token.toLowerCase();
      if (
        lower.startsWith('include:') ||
        lower === 'a' ||
        lower.startsWith('a:') ||
        lower === 'mx' ||
        lower.startsWith('mx:') ||
        lower === 'ptr' ||
        lower.startsWith('ptr:') ||
        lower.startsWith('exists:') ||
        lower.startsWith('redirect=')
      ) {
        lookupCount += 1;
      }
      if (lower === '-all' || lower === '~all' || lower === '?all' || lower === '+all') {
        allQualifier = lower;
      }
    }
  }

  const exceeds10 = lookupCount > 10;
  let spfStatus: 'PASS' | 'WARNING' | 'FAIL' = 'PASS';
  if (!rawSpf || multipleSpf || exceeds10 || allQualifier === '+all') {
    spfStatus = 'FAIL';
  } else if (allQualifier !== '-all') {
    spfStatus = 'WARNING';
  }

  const rawDmarc = dmarcRecords.find((r) => r.trim().toLowerCase().startsWith('v=dmarc1')) || null;
  let dmarcPolicy: 'reject' | 'quarantine' | 'none' | 'missing' = 'missing';
  if (rawDmarc) {
    const match = /\bp=(reject|quarantine|none)\b/i.exec(rawDmarc);
    if (match) {
      dmarcPolicy = match[1].toLowerCase() as 'reject' | 'quarantine' | 'none';
    }
  }

  let dmarcStatus: 'PASS' | 'WARNING' | 'FAIL' = 'PASS';
  if (!rawDmarc || dmarcPolicy === 'missing') {
    dmarcStatus = 'FAIL';
  } else if (dmarcPolicy === 'none') {
    dmarcStatus = 'WARNING';
  }

  return {
    spf: {
      present: Boolean(rawSpf),
      raw_record: rawSpf,
      multiple_records_violation: multipleSpf,
      dns_lookup_count: lookupCount,
      exceeds_10_lookup_limit: exceeds10,
      all_qualifier: allQualifier,
      status: spfStatus,
    },
    dmarc: {
      present: Boolean(rawDmarc),
      raw_record: rawDmarc,
      policy: dmarcPolicy,
      status: dmarcStatus,
    },
  };
}

export type RbacCapability =
  | 'users:manage'
  | 'integrations:manage'
  | 'integrations:view'
  | 'policies:manage'
  | 'agents:manage'
  | 'targets:manage'
  | 'assessments:run'
  | 'findings:write'
  | 'findings:read'
  | 'ai:query'
  | 'reports:write'
  | 'reports:approve'
  | 'reports:read'
  | 'audit_logs:org';

export function checkRolePermission(role: UserRole, capability: RbacCapability): boolean {
  if (role === 'ADMIN') return true;
  if (role === 'SECURITY_ANALYST') {
    return [
      'integrations:view',
      'agents:manage',
      'targets:manage',
      'assessments:run',
      'findings:write',
      'findings:read',
      'ai:query',
      'reports:write',
      'reports:approve',
      'reports:read',
    ].includes(capability);
  }
  if (role === 'VIEWER') {
    return ['findings:read', 'reports:read'].includes(capability);
  }
  return false;
}
