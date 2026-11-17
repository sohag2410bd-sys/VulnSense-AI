import dns from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import type { PassiveReconResult, PublicMetadata, TlsInfo } from '../types/recon';
import {
  evaluateSecurityHeaders,
  parseSetCookieHeaders,
  validateTargetUrl,
} from '../lib/recon-utils';

function isPrivateIpAddress(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    return (
      normalized === '::1' ||
      normalized === '::' ||
      normalized.startsWith('fe80:') ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('::ffff:127.') ||
      normalized.startsWith('::ffff:10.') ||
      normalized.startsWith('::ffff:192.168.') ||
      normalized.startsWith('::ffff:169.254.')
    );
  }
  return false;
}

async function inspectTlsCertificate(hostname: string, port = 443): Promise<TlsInfo> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (info: TlsInfo) => {
      if (!settled) {
        settled = true;
        resolve(info);
      }
    };

    try {
      const socket = tls.connect(
        {
          host: hostname,
          port,
          servername: hostname,
          rejectUnauthorized: false,
          timeout: 7000,
        },
        () => {
          const protocol = socket.getProtocol() ?? null;
          const cipherInfo = socket.getCipher();
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          const authorizationError = socket.authorizationError
            ? String(socket.authorizationError)
            : null;

          const validFrom = cert?.valid_from ? new Date(cert.valid_from).toISOString() : null;
          const validTo = cert?.valid_to ? new Date(cert.valid_to).toISOString() : null;
          let daysRemaining: number | null = null;
          let expired = false;
          if (validTo) {
            const ms = new Date(validTo).getTime() - Date.now();
            daysRemaining = Math.floor(ms / (1000 * 60 * 60 * 24));
            expired = daysRemaining < 0;
          }

          const issuerParts: string[] = [];
          if (cert?.issuer?.O) issuerParts.push(String(cert.issuer.O));
          if (cert?.issuer?.CN) issuerParts.push(String(cert.issuer.CN));

          socket.end();
          finish({
            enabled: true,
            protocol,
            cipher: cipherInfo?.name ?? null,
            authorized,
            authorizationError,
            subjectCN: cert?.subject?.CN ? String(cert.subject.CN) : null,
            issuer: issuerParts.length > 0 ? issuerParts.join(' · ') : null,
            validFrom,
            validTo,
            daysRemaining,
            expired,
          });
        }
      );

      socket.on('timeout', () => {
        socket.destroy();
        finish({
          enabled: false,
          protocol: null,
          cipher: null,
          authorized: false,
          authorizationError: 'TLS handshake timed out',
          subjectCN: null,
          issuer: null,
          validFrom: null,
          validTo: null,
          daysRemaining: null,
          expired: false,
        });
      });

      socket.on('error', (err) => {
        finish({
          enabled: false,
          protocol: null,
          cipher: null,
          authorized: false,
          authorizationError: err.message,
          subjectCN: null,
          issuer: null,
          validFrom: null,
          validTo: null,
          daysRemaining: null,
          expired: false,
        });
      });
    } catch (err) {
      finish({
        enabled: false,
        protocol: null,
        cipher: null,
        authorized: false,
        authorizationError: err instanceof Error ? err.message : 'TLS inspection failed',
        subjectCN: null,
        issuer: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        expired: false,
      });
    }
  });
}

async function fetchPublicMetadata(
  origin: string,
  headersMap: Record<string, string>
): Promise<PublicMetadata> {
  let robotsTxtFound = false;
  let robotsTxtStatus: number | null = null;
  let robotsTxtPreview: string | null = null;
  const disallowedPaths: string[] = [];

  try {
    const robotsRes = await fetch(`${origin}/robots.txt`, {
      method: 'GET',
      headers: { 'User-Agent': 'VulnSense-AI/1.0 (Passive Recon)' },
      signal: AbortSignal.timeout(5000),
    });
    robotsTxtStatus = robotsRes.status;
    const contentType = robotsRes.headers.get('content-type') ?? '';
    if (robotsRes.ok && (contentType.includes('text') || !contentType)) {
      const text = await robotsRes.text();
      const lines = text.split(/\r?\n/);
      robotsTxtFound = true;
      robotsTxtPreview = lines.slice(0, 14).join('\n').slice(0, 1200);
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.toLowerCase().startsWith('disallow:')) {
          const val = trimmed.slice('disallow:'.length).trim();
          if (val && disallowedPaths.length < 15) {
            disallowedPaths.push(val);
          }
        }
      }
    }
  } catch {
    // Non-fatal metadata check
  }

  let securityTxtFound = false;
  try {
    const secRes = await fetch(`${origin}/.well-known/security.txt`, {
      method: 'GET',
      headers: { 'User-Agent': 'VulnSense-AI/1.0 (Passive Recon)' },
      signal: AbortSignal.timeout(4000),
    });
    const ct = secRes.headers.get('content-type') ?? '';
    securityTxtFound = secRes.ok && ct.includes('text');
  } catch {
    // Non-fatal
  }

  return {
    serverBanner: headersMap['server'] ?? null,
    poweredBy: headersMap['x-powered-by'] ?? null,
    aspnetVersion: headersMap['x-aspnet-version'] ?? null,
    via: headersMap['via'] ?? null,
    robotsTxtFound,
    robotsTxtStatus,
    robotsTxtPreview,
    disallowedPaths,
    securityTxtFound,
  };
}

export async function runPassiveRecon(rawInput: string): Promise<PassiveReconResult> {
  const validation = validateTargetUrl(rawInput);
  if (!validation.valid || !validation.normalizedUrl || !validation.domain) {
    throw new Error(validation.error ?? 'Invalid target URL');
  }

  // DNS-level SSRF guard
  try {
    const records = await dns.lookup(validation.domain, { all: true });
    for (const rec of records) {
      if (isPrivateIpAddress(rec.address)) {
        throw new Error(`Blocked scan: ${validation.domain} resolves to private address.`);
      }
    }
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('Blocked scan:')) {
      throw err;
    }
  }

  const start = Date.now();
  const response = await fetch(validation.normalizedUrl, {
    method: 'GET',
    redirect: 'follow',
    headers: {
      'User-Agent': 'VulnSense-AI/1.0 (Passive Security Recon)',
      Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
    },
    signal: AbortSignal.timeout(12000),
  });
  const responseTimeMs = Date.now() - start;

  const rawHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    rawHeaders[key.toLowerCase()] = value;
  });

  const headersWithGetSetCookie = response.headers as unknown as {
    getSetCookie?: () => string[];
  };
  let setCookieList: string[] = [];
  if (typeof headersWithGetSetCookie.getSetCookie === 'function') {
    setCookieList = headersWithGetSetCookie.getSetCookie();
  } else if (rawHeaders['set-cookie']) {
    setCookieList = [rawHeaders['set-cookie']];
  }

  const finalParsed = new URL(response.url || validation.normalizedUrl);
  const origin = `${finalParsed.protocol}//${finalParsed.host}`;

  const [tlsInfo, metadata] = await Promise.all([
    finalParsed.protocol === 'https:'
      ? inspectTlsCertificate(finalParsed.hostname, finalParsed.port ? Number(finalParsed.port) : 443)
      : Promise.resolve<TlsInfo>({
          enabled: false,
          protocol: null,
          cipher: null,
          authorized: false,
          authorizationError: 'Target responded over plaintext HTTP without TLS',
          subjectCN: null,
          issuer: null,
          validFrom: null,
          validTo: null,
          daysRemaining: null,
          expired: false,
        }),
    fetchPublicMetadata(origin, rawHeaders),
  ]);

  return {
    targetUrl: validation.normalizedUrl,
    finalUrl: finalParsed.toString(),
    domain: finalParsed.hostname,
    statusCode: response.status,
    responseTimeMs,
    redirected: response.redirected,
    collectedAt: new Date().toISOString(),
    rawHeaders,
    securityHeaders: evaluateSecurityHeaders(rawHeaders),
    tls: tlsInfo,
    cookies: parseSetCookieHeaders(setCookieList),
    metadata,
  };
}
