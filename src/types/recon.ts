export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type SecurityGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface HeaderCheck {
  name: string;
  key: string;
  present: boolean;
  value: string | null;
  importance: 'Critical' | 'High' | 'Medium' | 'Low';
  purpose: string;
}

export interface TlsInfo {
  enabled: boolean;
  protocol: string | null;
  cipher: string | null;
  authorized: boolean | null;
  authorizationError: string | null;
  subjectCN: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  expired: boolean;
}

export interface CookieAudit {
  name: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string | null;
  path: string | null;
  domain: string | null;
  issues: string[];
}

export interface PublicMetadata {
  serverBanner: string | null;
  poweredBy: string | null;
  aspnetVersion: string | null;
  via: string | null;
  robotsTxtFound: boolean;
  robotsTxtStatus: number | null;
  robotsTxtPreview: string | null;
  disallowedPaths: string[];
  securityTxtFound: boolean;
}

export interface PassiveReconResult {
  targetUrl: string;
  finalUrl: string;
  domain: string;
  statusCode: number;
  responseTimeMs: number;
  redirected: boolean;
  collectedAt: string;
  rawHeaders: Record<string, string>;
  securityHeaders: HeaderCheck[];
  tls: TlsInfo;
  cookies: CookieAudit[];
  metadata: PublicMetadata;
}

export interface VulnerabilityFinding {
  id: string;
  title: string;
  severity: SeverityLevel;
  category: string;
  affectedComponent: string;
  riskExplanation: string;
  remediationSteps: string[];
  nginxSnippet: string;
  apacheSnippet: string;
}

export interface SecurityAnalysisResult {
  securityScore: number;
  grade: SecurityGrade;
  executiveSummary: string;
  findings: VulnerabilityFinding[];
}

export interface ScanReport {
  id: string;
  isSample?: boolean;
  recon: PassiveReconResult;
  analysis: SecurityAnalysisResult;
}

export interface DeliverableFile {
  path: string;
  name: string;
  language: string;
  description: string;
  content: string;
}
