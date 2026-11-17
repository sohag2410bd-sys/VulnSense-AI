import type {
  CookieAudit,
  HeaderCheck,
  ScanReport,
  SecurityGrade,
  SeverityLevel,
  VulnerabilityFinding,
} from '../types/recon';

const PRIVATE_HOSTNAME_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^169\.254\./,
  /^0\.0\.0\.0$/,
  /^\[?::1\]?$/,
  /^\[?fe80:/i,
  /^\[?fc00:/i,
  /^\[?fd00:/i,
  /\.local$/i,
  /\.internal$/i,
];

export interface UrlValidationResult {
  valid: boolean;
  normalizedUrl?: string;
  domain?: string;
  error?: string;
}

export function validateTargetUrl(rawInput: string): UrlValidationResult {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { valid: false, error: 'Please enter a target website URL or domain.' };
  }

  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return { valid: false, error: 'Invalid URL format. Example: https://example.com' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: 'Only HTTP and HTTPS targets are supported.' };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname || (!hostname.includes('.') && hostname !== 'localhost')) {
    return { valid: false, error: 'Enter a valid public domain name (e.g., example.com).' };
  }

  if (PRIVATE_HOSTNAME_PATTERNS.some((pattern) => pattern.test(hostname))) {
    return {
      valid: false,
      error: 'Private, loopback, and internal network addresses cannot be scanned.',
    };
  }

  return {
    valid: true,
    normalizedUrl: parsed.toString(),
    domain: hostname,
  };
}

export const SECURITY_HEADER_DEFINITIONS: Array<{
  key: string;
  name: string;
  importance: HeaderCheck['importance'];
  purpose: string;
}> = [
  {
    key: 'content-security-policy',
    name: 'Content-Security-Policy',
    importance: 'Critical',
    purpose: 'Restricts script, style, and resource origins to mitigate XSS and data injection.',
  },
  {
    key: 'strict-transport-security',
    name: 'Strict-Transport-Security',
    importance: 'High',
    purpose: 'Enforces HTTPS connections and prevents SSL stripping downgrade attacks.',
  },
  {
    key: 'x-frame-options',
    name: 'X-Frame-Options',
    importance: 'High',
    purpose: 'Blocks framing in unauthorized origins to prevent clickjacking.',
  },
  {
    key: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    importance: 'Medium',
    purpose: 'Disables MIME-type sniffing with nosniff to prevent content confusion.',
  },
  {
    key: 'referrer-policy',
    name: 'Referrer-Policy',
    importance: 'Medium',
    purpose: 'Controls how much referrer information is shared across cross-origin navigations.',
  },
  {
    key: 'permissions-policy',
    name: 'Permissions-Policy',
    importance: 'Low',
    purpose: 'Restricts browser APIs such as camera, microphone, and geolocation.',
  },
  {
    key: 'cross-origin-opener-policy',
    name: 'Cross-Origin-Opener-Policy',
    importance: 'Low',
    purpose: 'Isolates top-level browsing context against Spectre-class cross-origin leaks.',
  },
  {
    key: 'cross-origin-resource-policy',
    name: 'Cross-Origin-Resource-Policy',
    importance: 'Low',
    purpose: 'Protects static and API resources from unauthorized cross-origin embedding.',
  },
];

export function evaluateSecurityHeaders(rawHeaders: Record<string, string>): HeaderCheck[] {
  const normalized = new Map<string, string>();
  for (const [k, v] of Object.entries(rawHeaders)) {
    normalized.set(k.toLowerCase(), v);
  }

  return SECURITY_HEADER_DEFINITIONS.map((def) => {
    const val = normalized.get(def.key) ?? null;
    return {
      name: def.name,
      key: def.key,
      present: val !== null && val.trim().length > 0,
      value: val,
      importance: def.importance,
      purpose: def.purpose,
    };
  });
}

export function parseSetCookieHeaders(setCookieValues: string[]): CookieAudit[] {
  return setCookieValues
    .map((raw) => raw.trim())
    .filter(Boolean)
    .map((raw) => {
      const parts = raw.split(';').map((p) => p.trim());
      const [nameValue, ...attrs] = parts;
      const eqIdx = nameValue.indexOf('=');
      const name = eqIdx > 0 ? nameValue.slice(0, eqIdx).trim() : nameValue;

      let httpOnly = false;
      let secure = false;
      let sameSite: string | null = null;
      let path: string | null = null;
      let domain: string | null = null;

      for (const attr of attrs) {
        const lower = attr.toLowerCase();
        if (lower === 'httponly') {
          httpOnly = true;
        } else if (lower === 'secure') {
          secure = true;
        } else if (lower.startsWith('samesite=')) {
          sameSite = attr.slice(attr.indexOf('=') + 1).trim();
        } else if (lower.startsWith('path=')) {
          path = attr.slice(attr.indexOf('=') + 1).trim();
        } else if (lower.startsWith('domain=')) {
          domain = attr.slice(attr.indexOf('=') + 1).trim();
        }
      }

      const issues: string[] = [];
      if (!httpOnly) issues.push('Missing HttpOnly flag (accessible via JavaScript)');
      if (!secure) issues.push('Missing Secure flag (transmissible over plaintext HTTP)');
      if (!sameSite) {
        issues.push('Missing SameSite attribute (CSRF exposure risk)');
      } else if (sameSite.toLowerCase() === 'none' && !secure) {
        issues.push('SameSite=None requires Secure flag');
      }

      return {
        name,
        httpOnly,
        secure,
        sameSite,
        path,
        domain,
        issues,
      };
    });
}

export function computeSecurityGrade(score: number): SecurityGrade {
  const clamped = Math.max(0, Math.min(10, score));
  if (clamped >= 9.0) return 'A';
  if (clamped >= 7.5) return 'B';
  if (clamped >= 5.5) return 'C';
  if (clamped >= 3.5) return 'D';
  return 'F';
}

export function normalizeScore(score: number): number {
  if (Number.isNaN(score)) return 5.0;
  const clamped = Math.max(0, Math.min(10, score));
  return Math.round(clamped * 10) / 10;
}

export function countSeverities(findings: VulnerabilityFinding[]): Record<SeverityLevel, number> & { total: number } {
  const counts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    total: findings.length,
  };

  for (const f of findings) {
    if (f.severity in counts) {
      counts[f.severity] += 1;
    }
  }
  return counts;
}

export function sortFindingsBySeverity(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
  const rank: Record<SeverityLevel, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
  };
  return [...findings].sort((a, b) => rank[a.severity] - rank[b.severity]);
}

export function generateMarkdownReport(report: ScanReport): string {
  const { recon, analysis } = report;
  const counts = countSeverities(analysis.findings);
  const sorted = sortFindingsBySeverity(analysis.findings);

  const lines: string[] = [
    `# VulnSense AI Security Assessment Report`,
    ``,
    `- **Target URL:** ${recon.targetUrl}`,
    `- **Final URL:** ${recon.finalUrl}`,
    `- **Domain:** ${recon.domain}`,
    `- **HTTP Status:** ${recon.statusCode} (${recon.responseTimeMs} ms)`,
    `- **Scan Timestamp:** ${recon.collectedAt}`,
    `- **Security Score:** ${analysis.securityScore.toFixed(1)} / 10.0 (Grade: **${analysis.grade}**)`,
    ``,
    `## Executive Summary`,
    ``,
    analysis.executiveSummary,
    ``,
    `## Severity Distribution`,
    ``,
    `| Severity | Count |`,
    `| --- | ---: |`,
    `| CRITICAL | ${counts.CRITICAL} |`,
    `| HIGH | ${counts.HIGH} |`,
    `| MEDIUM | ${counts.MEDIUM} |`,
    `| LOW | ${counts.LOW} |`,
    `| **Total** | **${counts.total}** |`,
    ``,
    `## Vulnerability Findings`,
    ``,
  ];

  if (sorted.length === 0) {
    lines.push('No significant vulnerabilities were identified from passive reconnaissance.');
  } else {
    sorted.forEach((finding, index) => {
      lines.push(
        `### ${index + 1}. [${finding.severity}] ${finding.title}`,
        ``,
        `- **Category:** ${finding.category}`,
        `- **Affected Component:** ${finding.affectedComponent}`,
        ``,
        `**Risk Explanation**`,
        ``,
        finding.riskExplanation,
        ``,
        `**Remediation Steps**`,
        ``,
        ...finding.remediationSteps.map((step) => `- ${step}`),
        ``,
        `**Nginx Configuration Fix**`,
        '```nginx',
        finding.nginxSnippet.trim(),
        '```',
        ``,
        `**Apache Configuration Fix**`,
        '```apache',
        finding.apacheSnippet.trim(),
        '```',
        ``
      );
    });
  }

  lines.push(
    `## HTTP Security Headers Audit`,
    ``,
    `| Header | Status | Value |`,
    `| --- | --- | --- |`,
    ...recon.securityHeaders.map(
      (h) => `| \`${h.name}\` | ${h.present ? 'Present' : 'Missing'} | ${h.value ? `\`${h.value.replace(/\|/g, '\\|')}\`` : '—'} |`
    ),
    ``,
    `## SSL / TLS Posture`,
    ``,
    `- **HTTPS Enabled:** ${recon.tls.enabled ? 'Yes' : 'No'}`,
    `- **Protocol:** ${recon.tls.protocol ?? 'N/A'}`,
    `- **Cipher:** ${recon.tls.cipher ?? 'N/A'}`,
    `- **Certificate Authorized:** ${recon.tls.authorized === null ? 'N/A' : recon.tls.authorized ? 'Yes' : `No (${recon.tls.authorizationError ?? 'Untrusted'})`}`,
    `- **Issuer:** ${recon.tls.issuer ?? 'N/A'}`,
    `- **Days Remaining:** ${recon.tls.daysRemaining ?? 'N/A'}`,
    ``,
    `## Cookie Security Audit`,
    ``
  );

  if (recon.cookies.length === 0) {
    lines.push('No `Set-Cookie` headers were returned on the initial response.');
  } else {
    lines.push(
      `| Cookie | HttpOnly | Secure | SameSite | Issues |`,
      `| --- | --- | --- | --- | --- |`,
      ...recon.cookies.map(
        (c) =>
          `| \`${c.name}\` | ${c.httpOnly ? 'Yes' : 'No'} | ${c.secure ? 'Yes' : 'No'} | ${c.sameSite ?? 'Missing'} | ${c.issues.length > 0 ? c.issues.join('; ') : 'None'} |`
      )
    );
  }

  lines.push(
    ``,
    `## Server Banners & Public Metadata`,
    ``,
    `- **Server Header:** ${recon.metadata.serverBanner ?? 'Not disclosed'}`,
    `- **X-Powered-By:** ${recon.metadata.poweredBy ?? 'Not disclosed'}`,
    `- **robots.txt:** ${recon.metadata.robotsTxtFound ? `Found (HTTP ${recon.metadata.robotsTxtStatus})` : 'Not found'}`,
    `- **security.txt:** ${recon.metadata.securityTxtFound ? 'Found' : 'Not found'}`,
    ``
  );

  return lines.join('\n');
}

export function escapeCsvCell(value: string): string {
  const safe = String(value ?? '');
  if (/[",\r\n]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

export function generateCsvReport(report: ScanReport): string {
  const sorted = sortFindingsBySeverity(report.analysis.findings);
  const header = ['Severity', 'Title', 'Description', 'Remediation Fix'].join(',');
  const rows = sorted.map((finding) => {
    const description = `${finding.affectedComponent}: ${finding.riskExplanation}`;
    const fixParts = [
      finding.remediationSteps.join(' '),
      finding.nginxSnippet ? `Nginx: ${finding.nginxSnippet.replace(/\s+/g, ' ').trim()}` : '',
      finding.apacheSnippet ? `Apache: ${finding.apacheSnippet.replace(/\s+/g, ' ').trim()}` : '',
    ].filter(Boolean);

    return [
      escapeCsvCell(finding.severity),
      escapeCsvCell(finding.title),
      escapeCsvCell(description),
      escapeCsvCell(fixParts.join(' | ')),
    ].join(',');
  });

  return [header, ...rows].join('\r\n');
}

export const SAMPLE_SCAN_REPORT: ScanReport = {
  id: 'sample-baseline',
  isSample: true,
  recon: {
    targetUrl: 'https://demo-target.example.org',
    finalUrl: 'https://demo-target.example.org/',
    domain: 'demo-target.example.org',
    statusCode: 200,
    responseTimeMs: 142,
    redirected: false,
    collectedAt: '2026-11-17T09:15:00.000Z',
    rawHeaders: {
      server: 'nginx/1.18.0 (Ubuntu)',
      'x-powered-by': 'Express',
      'content-type': 'text/html; charset=utf-8',
      'x-content-type-options': 'nosniff',
    },
    securityHeaders: evaluateSecurityHeaders({
      server: 'nginx/1.18.0 (Ubuntu)',
      'x-powered-by': 'Express',
      'content-type': 'text/html; charset=utf-8',
      'x-content-type-options': 'nosniff',
    }),
    tls: {
      enabled: true,
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      authorized: true,
      authorizationError: null,
      subjectCN: 'demo-target.example.org',
      issuer: "Let's Encrypt E5",
      validFrom: '2026-10-01T00:00:00.000Z',
      validTo: '2026-12-30T23:59:59.000Z',
      daysRemaining: 43,
      expired: false,
    },
    cookies: parseSetCookieHeaders([
      'session_id=abc123; Path=/; HttpOnly',
      'prefs=theme=dark; Path=/',
    ]),
    metadata: {
      serverBanner: 'nginx/1.18.0 (Ubuntu)',
      poweredBy: 'Express',
      aspnetVersion: null,
      via: null,
      robotsTxtFound: true,
      robotsTxtStatus: 200,
      robotsTxtPreview: 'User-agent: *\nDisallow: /admin/\nDisallow: /internal-api/',
      disallowedPaths: ['/admin/', '/internal-api/'],
      securityTxtFound: false,
    },
  },
  analysis: {
    securityScore: 4.8,
    grade: 'D',
    executiveSummary:
      'Sample baseline report demonstrating VulnSense AI telemetry: the target enforces TLS 1.3 with a valid certificate, but lacks Content-Security-Policy, HSTS, and X-Frame-Options headers, discloses exact Nginx and Express version banners, and issues session cookies without Secure or SameSite attributes.',
    findings: [
      {
        id: 'finding-csp-missing',
        title: 'Missing Content-Security-Policy (CSP) Header',
        severity: 'CRITICAL',
        category: 'HTTP Security Headers',
        affectedComponent: 'Response Headers (Global)',
        riskExplanation:
          'Without a Content-Security-Policy header, the browser permits inline scripts and arbitrary third-party script execution, significantly widening the blast radius of any Cross-Site Scripting (XSS) vulnerability.',
        remediationSteps: [
          'Define a strict default-src policy restricted to trusted origins.',
          'Eliminate unsafe-inline scripts and move inline handlers to external modules with nonces or hashes.',
          'Deploy initially with Content-Security-Policy-Report-Only before enforcing.',
        ],
        nginxSnippet: `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';" always;`,
        apacheSnippet: `Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';"`,
      },
      {
        id: 'finding-cookie-flags',
        title: 'Session Cookie Missing Secure & SameSite Attributes',
        severity: 'HIGH',
        category: 'Session Management',
        affectedComponent: 'Set-Cookie: session_id',
        riskExplanation:
          'The session_id cookie omits the Secure and SameSite directives, allowing potential transmission over downgraded HTTP links and cross-site request forgery (CSRF) submissions.',
        remediationSteps: [
          'Append Secure, HttpOnly, and SameSite=Lax (or Strict) to all authentication cookies.',
          'Configure Express session middleware with cookie: { secure: true, httpOnly: true, sameSite: "lax" }.',
        ],
        nginxSnippet: `proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Lax";`,
        apacheSnippet: `Header edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Lax"`,
      },
      {
        id: 'finding-hsts-missing',
        title: 'HTTP Strict Transport Security (HSTS) Not Enforced',
        severity: 'HIGH',
        category: 'Transport Layer Security',
        affectedComponent: 'Strict-Transport-Security Header',
        riskExplanation:
          'Absence of HSTS permits man-in-the-middle attackers on untrusted networks to intercept initial plain HTTP navigation attempts via SSL stripping.',
        remediationSteps: [
          'Return Strict-Transport-Security with at least a 1-year max-age (31536000 seconds).',
          'Include includeSubDomains once all subdomains support HTTPS.',
        ],
        nginxSnippet: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
        apacheSnippet: `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`,
      },
      {
        id: 'finding-banner-disclosure',
        title: 'Server & Framework Version Banner Disclosure',
        severity: 'MEDIUM',
        category: 'Information Disclosure',
        affectedComponent: 'Server & X-Powered-By Headers',
        riskExplanation:
          'Headers advertise exact software versions (nginx/1.18.0 Ubuntu and Express), helping automated scanners fingerprint known version-specific CVEs.',
        remediationSteps: [
          'Set server_tokens off; in Nginx configuration.',
          'Disable Express fingerprinting with app.disable("x-powered-by").',
        ],
        nginxSnippet: `server_tokens off;\nproxy_hide_header X-Powered-By;`,
        apacheSnippet: `ServerTokens Prod\nServerSignature Off\nHeader unset X-Powered-By`,
      },
      {
        id: 'finding-xfo-robots',
        title: 'Missing Clickjacking Protection & Sensitive robots.txt Paths',
        severity: 'LOW',
        category: 'Hardening & Metadata',
        affectedComponent: 'X-Frame-Options & /robots.txt',
        riskExplanation:
          'X-Frame-Options is absent and robots.txt publicly enumerates /admin/ and /internal-api/ endpoints for reconnaissance tools.',
        remediationSteps: [
          'Set X-Frame-Options: DENY alongside CSP frame-ancestors.',
          'Protect administrative routes with authentication rather than relying on robots.txt obscurity.',
        ],
        nginxSnippet: `add_header X-Frame-Options "DENY" always;\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
        apacheSnippet: `Header always set X-Frame-Options "DENY"\nHeader always set Referrer-Policy "strict-origin-when-cross-origin"`,
      },
    ],
  },
};
