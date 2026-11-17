import { GoogleGenAI, Type } from '@google/genai';
import type { PassiveReconResult, SecurityAnalysisResult } from '../types/recon';
import {
  computeSecurityGrade,
  normalizeScore,
  sortFindingsBySeverity,
} from '../lib/recon-utils';
import { executeWithRetryAndFallback } from '../lib/gemini-retry';

const PRIMARY_GEMINI_MODEL = 'gemini-4-hydrogen';
const FALLBACK_GEMINI_MODEL = 'gemini-3.1-flash-lite';

function getGeminiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY is not configured in the server environment.');
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

export async function analyzeReconWithGemini(
  recon: PassiveReconResult
): Promise<SecurityAnalysisResult> {
  const ai = getGeminiClient();

  const compactTelemetry = {
    targetUrl: recon.targetUrl,
    finalUrl: recon.finalUrl,
    domain: recon.domain,
    statusCode: recon.statusCode,
    redirected: recon.redirected,
    securityHeaders: recon.securityHeaders.map((h) => ({
      name: h.name,
      present: h.present,
      value: h.value,
      importance: h.importance,
    })),
    tls: recon.tls,
    cookies: recon.cookies,
    metadata: {
      serverBanner: recon.metadata.serverBanner,
      poweredBy: recon.metadata.poweredBy,
      aspnetVersion: recon.metadata.aspnetVersion,
      via: recon.metadata.via,
      robotsTxtFound: recon.metadata.robotsTxtFound,
      disallowedPaths: recon.metadata.disallowedPaths,
      securityTxtFound: recon.metadata.securityTxtFound,
    },
  };

  const { result: response } = await executeWithRetryAndFallback({
    primaryModel: PRIMARY_GEMINI_MODEL,
    fallbackModel: FALLBACK_GEMINI_MODEL,
    maxRetriesPerModel: 3,
    baseDelayMs: 1200,
    runModel: (model) =>
      ai.models.generateContent({
        model,
        contents: `Analyze the following passive security reconnaissance telemetry for ${recon.domain} and output a strict JSON security assessment.\n\nTelemetry:\n${JSON.stringify(compactTelemetry, null, 2)}`,
        config: {
          systemInstruction:
            'You are VulnSense AI, a senior application security engineer. Evaluate ONLY the passive reconnaissance evidence provided. Categorize genuine weaknesses and hardening gaps into CRITICAL, HIGH, MEDIUM, and LOW. Do not invent unverified vulnerabilities like SQLi or RCE that cannot be observed from passive headers/TLS/cookies/banners. For each finding provide a concise title, affectedComponent, clear riskExplanation, actionable remediationSteps, and ready-to-paste nginxSnippet and apacheSnippet config blocks. Score securityScore from 0.0 to 10.0 realistically based on missing critical headers (CSP, HSTS, X-Frame-Options), TLS posture, cookie flags, and information disclosure.',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              securityScore: {
                type: Type.NUMBER,
                description: 'Overall security posture score from 0.0 to 10.0.',
              },
              grade: {
                type: Type.STRING,
                description: 'Letter grade: A, B, C, D, or F.',
              },
              executiveSummary: {
                type: Type.STRING,
                description: 'Concise 2-3 sentence executive security assessment summary.',
              },
              findings: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    id: { type: Type.STRING },
                    title: { type: Type.STRING },
                    severity: {
                      type: Type.STRING,
                      description: 'Must be one of CRITICAL, HIGH, MEDIUM, LOW.',
                    },
                    category: { type: Type.STRING },
                    affectedComponent: { type: Type.STRING },
                    riskExplanation: { type: Type.STRING },
                    remediationSteps: {
                      type: Type.ARRAY,
                      items: { type: Type.STRING },
                    },
                    nginxSnippet: { type: Type.STRING },
                    apacheSnippet: { type: Type.STRING },
                  },
                  required: [
                    'id',
                    'title',
                    'severity',
                    'category',
                    'affectedComponent',
                    'riskExplanation',
                    'remediationSteps',
                    'nginxSnippet',
                    'apacheSnippet',
                  ],
                },
              },
            },
            required: ['securityScore', 'grade', 'executiveSummary', 'findings'],
          },
        },
      }),
  });

  const rawText = (response.text ?? '').trim();
  if (!rawText) {
    throw new Error('Gemini returned an empty analysis response.');
  }

  const parsed = JSON.parse(rawText) as {
    securityScore?: number;
    grade?: string;
    executiveSummary?: string;
    findings?: Array<{
      id?: string;
      title?: string;
      severity?: string;
      category?: string;
      affectedComponent?: string;
      riskExplanation?: string;
      remediationSteps?: string[];
      nginxSnippet?: string;
      apacheSnippet?: string;
    }>;
  };

  const score = normalizeScore(Number(parsed.securityScore ?? 5));
  const grade = computeSecurityGrade(score);

  const validSeverities = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
  const normalizedFindings = (parsed.findings ?? []).map((f, idx) => {
    const rawSev = String(f.severity ?? 'MEDIUM').toUpperCase();
    const severity = validSeverities.has(rawSev)
      ? (rawSev as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW')
      : 'MEDIUM';
    return {
      id: f.id?.trim() || `finding-${idx + 1}`,
      title: f.title?.trim() || 'Security Hardening Gap',
      severity,
      category: f.category?.trim() || 'HTTP Hardening',
      affectedComponent: f.affectedComponent?.trim() || recon.domain,
      riskExplanation: f.riskExplanation?.trim() || 'No explanation provided.',
      remediationSteps:
        Array.isArray(f.remediationSteps) && f.remediationSteps.length > 0
          ? f.remediationSteps
          : ['Apply recommended server hardening configuration.'],
      nginxSnippet: f.nginxSnippet?.trim() || '# No Nginx directive required',
      apacheSnippet: f.apacheSnippet?.trim() || '# No Apache directive required',
    };
  });

  return {
    securityScore: score,
    grade,
    executiveSummary:
      parsed.executiveSummary?.trim() ||
      `Passive assessment completed for ${recon.domain}.`,
    findings: sortFindingsBySeverity(normalizedFindings),
  };
}
