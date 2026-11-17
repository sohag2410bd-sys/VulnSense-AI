import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeSecurityGrade,
  countSeverities,
  evaluateSecurityHeaders,
  generateCsvReport,
  generateMarkdownReport,
  parseSetCookieHeaders,
  SAMPLE_SCAN_REPORT,
  validateTargetUrl,
} from './recon-utils';

test('validateTargetUrl normalizes public domain and rejects private/SSRF hosts', () => {
  const validDomain = validateTargetUrl('example.com');
  assert.equal(validDomain.valid, true);
  assert.equal(validDomain.normalizedUrl, 'https://example.com/');
  assert.equal(validDomain.domain, 'example.com');

  const localhostRes = validateTargetUrl('http://localhost:3000');
  assert.equal(localhostRes.valid, false);

  const loopbackRes = validateTargetUrl('http://127.0.0.1/admin');
  assert.equal(loopbackRes.valid, false);

  const metadataRes = validateTargetUrl('http://169.254.169.254/latest/meta-data/');
  assert.equal(metadataRes.valid, false);

  const emptyRes = validateTargetUrl('   ');
  assert.equal(emptyRes.valid, false);
});

test('parseSetCookieHeaders parses attributes and flags missing protections', () => {
  const cookies = parseSetCookieHeaders([
    'sid=xyz; Path=/; HttpOnly; Secure; SameSite=Strict',
    'legacy=123; Path=/app',
  ]);

  assert.equal(cookies.length, 2);
  assert.equal(cookies[0].name, 'sid');
  assert.equal(cookies[0].httpOnly, true);
  assert.equal(cookies[0].secure, true);
  assert.equal(cookies[0].sameSite, 'Strict');
  assert.equal(cookies[0].issues.length, 0);

  assert.equal(cookies[1].name, 'legacy');
  assert.equal(cookies[1].httpOnly, false);
  assert.equal(cookies[1].secure, false);
  assert.equal(cookies[1].sameSite, null);
  assert.equal(cookies[1].issues.length, 3);
});

test('evaluateSecurityHeaders checks case-insensitively and preserves values', () => {
  const checks = evaluateSecurityHeaders({
    'Content-Security-Policy': "default-src 'self'",
    'X-Content-Type-Options': 'nosniff',
  });

  const csp = checks.find((c) => c.key === 'content-security-policy');
  const hsts = checks.find((c) => c.key === 'strict-transport-security');

  assert.equal(csp?.present, true);
  assert.equal(csp?.value, "default-src 'self'");
  assert.equal(hsts?.present, false);
  assert.equal(hsts?.value, null);
});

test('computeSecurityGrade maps scores accurately to A-F', () => {
  assert.equal(computeSecurityGrade(9.5), 'A');
  assert.equal(computeSecurityGrade(8.0), 'B');
  assert.equal(computeSecurityGrade(6.0), 'C');
  assert.equal(computeSecurityGrade(4.0), 'D');
  assert.equal(computeSecurityGrade(2.1), 'F');
});

test('countSeverities and generateMarkdownReport produce expected structure', () => {
  const counts = countSeverities(SAMPLE_SCAN_REPORT.analysis.findings);
  assert.equal(counts.CRITICAL, 1);
  assert.equal(counts.HIGH, 2);
  assert.equal(counts.MEDIUM, 1);
  assert.equal(counts.LOW, 1);
  assert.equal(counts.total, 5);

  const md = generateMarkdownReport(SAMPLE_SCAN_REPORT);
  assert.match(md, /# VulnSense AI Security Assessment Report/);
  assert.match(md, /\[CRITICAL\] Missing Content-Security-Policy/);
  assert.match(md, /```nginx/);
  assert.match(md, /```apache/);
  assert.match(md, /demo-target\.example\.org/);
});

test('generateCsvReport outputs Severity, Title, Description, Remediation Fix columns', () => {
  const csv = generateCsvReport(SAMPLE_SCAN_REPORT);
  const lines = csv.split('\r\n');
  assert.equal(lines[0], 'Severity,Title,Description,Remediation Fix');
  assert.equal(lines.length, 6); // header + 5 findings
  assert.match(lines[1], /^CRITICAL,/);
  assert.match(lines[1], /Missing Content-Security-Policy/);
});

