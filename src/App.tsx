import { useEffect, useState } from 'react';
import { Download, FileJson, FileSpreadsheet, FileText, Shield, Terminal, Lock, Cookie, Globe } from 'lucide-react';
import type { ScanReport } from './types/recon';
import {
  generateCsvReport,
  generateMarkdownReport,
  SAMPLE_SCAN_REPORT,
  validateTargetUrl,
} from './lib/recon-utils';
import { exportScanReportPdf } from './lib/pdf-export';
import { TopNav, type WorkspaceTab } from './components/TopNav';
import { ScanForm } from './components/ScanForm';
import { MetricsStrip } from './components/MetricsStrip';
import { FindingsSection } from './components/FindingsSection';
import { TelemetrySection } from './components/TelemetrySection';
import { DeliverablesSection } from './components/DeliverablesSection';

function triggerFileDownload(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export default function App() {
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('overview');
  const [targetUrl, setTargetUrl] = useState('');
  const [report, setReport] = useState<ScanReport | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('autostart') === '1') {
      setReport(SAMPLE_SCAN_REPORT);
      setTargetUrl(SAMPLE_SCAN_REPORT.recon.targetUrl);
    }
  }, []);

  const handleRunScan = async (urlOverride?: string) => {
    const candidate = urlOverride ?? targetUrl;
    const validation = validateTargetUrl(candidate);
    if (!validation.valid) {
      setError(validation.error ?? 'Invalid target URL');
      return;
    }

    setError(null);
    setIsScanning(true);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: candidate }),
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || 'Scan failed. Check target reachability and API setup.');
      }

      setReport(payload as ScanReport);
      if (activeTab === 'deliverables') {
        setActiveTab('overview');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to complete passive scan.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleLoadSample = () => {
    setError(null);
    setTargetUrl(SAMPLE_SCAN_REPORT.recon.targetUrl);
    setReport(SAMPLE_SCAN_REPORT);
    if (activeTab === 'deliverables') {
      setActiveTab('overview');
    }
  };

  const handleDownloadMarkdown = () => {
    if (!report) return;
    const md = generateMarkdownReport(report);
    triggerFileDownload(`report_${report.recon.domain}.md`, md, 'text/markdown;charset=utf-8');
  };

  const handleDownloadJson = () => {
    if (!report) return;
    triggerFileDownload(
      `report_${report.recon.domain}.json`,
      JSON.stringify(report, null, 2),
      'application/json;charset=utf-8'
    );
  };

  const handleDownloadCsv = () => {
    if (!report) return;
    const csv = generateCsvReport(report);
    triggerFileDownload(`report_${report.recon.domain}.csv`, csv, 'text/csv;charset=utf-8');
  };

  const handleDownloadPdf = () => {
    if (!report) return;
    exportScanReportPdf(report);
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#080C14] text-slate-100">
      <TopNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        hasReport={report !== null}
        onDownloadMarkdown={handleDownloadMarkdown}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8 space-y-8">
        {activeTab !== 'deliverables' && (
          <ScanForm
            targetUrl={targetUrl}
            onChangeUrl={setTargetUrl}
            onSubmitScan={handleRunScan}
            onLoadSample={handleLoadSample}
            hasReport={report !== null}
            isScanning={isScanning}
            error={error}
          />
        )}

        {activeTab === 'deliverables' ? (
          <DeliverablesSection />
        ) : isScanning ? (
          <section aria-label="Scanning progress" className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {[0, 1, 2, 3].map((idx) => (
                <div
                  key={idx}
                  className="h-28 rounded-xl bg-[#0E1525] border border-slate-800 p-5 animate-pulse"
                >
                  <div className="h-3 w-24 bg-slate-800 rounded" />
                  <div className="h-7 w-20 bg-slate-800 rounded mt-4" />
                </div>
              ))}
            </div>
            <div className="h-44 rounded-xl bg-[#0E1525] border border-slate-800 p-6 animate-pulse">
              <div className="h-4 w-48 bg-slate-800 rounded" />
              <div className="h-3 w-full bg-slate-800 rounded mt-4" />
              <div className="h-3 w-3/4 bg-slate-800 rounded mt-2.5" />
            </div>
          </section>
        ) : !report ? (
          <section
            aria-label="Passive reconnaissance capabilities"
            className="bg-[#0E1525] border border-slate-800 rounded-xl p-6 sm:p-8 space-y-6"
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
              <div>
                <h2 className="text-lg font-semibold text-slate-100">
                  Ready for Passive Target Inspection
                </h2>
                <p className="mt-1 text-sm text-slate-400">
                  Enter a public URL above to execute a live HTTP, TLS, and Gemini AI audit, or
                  load the sample baseline report to inspect the full workflow immediately.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-3 shrink-0">
                <button
                  type="button"
                  onClick={handleLoadSample}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 text-slate-100 hover:bg-slate-700 transition-colors cursor-pointer"
                >
                  Load Sample Baseline
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('deliverables')}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium text-slate-300 border border-slate-700 hover:border-slate-500 transition-colors cursor-pointer"
                >
                  <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>View Python CLI & Flask Code</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 text-sm">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2 font-semibold text-slate-200">
                  <Shield className="w-4 h-4 text-cyan-400" aria-hidden="true" />
                  <span>Security Headers</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Audits CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and
                  Permissions-Policy.
                </p>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center gap-2 font-semibold text-slate-200">
                  <Lock className="w-4 h-4 text-cyan-400" aria-hidden="true" />
                  <span>SSL / TLS Posture</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Inspects negotiated protocol version, cipher suite, certificate issuer, trust chain,
                  and expiration days.
                </p>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center gap-2 font-semibold text-slate-200">
                  <Cookie className="w-4 h-4 text-cyan-400" aria-hidden="true" />
                  <span>Cookie Hardening</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Checks Set-Cookie directives for HttpOnly, Secure, and SameSite protections against
                  session hijacking.
                </p>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center gap-2 font-semibold text-slate-200">
                  <Globe className="w-4 h-4 text-cyan-400" aria-hidden="true" />
                  <span>Banners & Metadata</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Flags Server and X-Powered-By leakage alongside robots.txt and security.txt
                  exposures.
                </p>
              </div>
            </div>
          </section>
        ) : (
          <div className="space-y-8">
            <MetricsStrip report={report} />

            <section className="bg-[#0E1525] border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                    <span>{report.isSample ? 'Sample Baseline Dataset' : 'Live Assessment'}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono">{report.recon.finalUrl}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono tabular-nums">
                      {new Date(report.recon.collectedAt).toLocaleString()}
                    </span>
                  </div>
                  <h2 className="text-lg font-semibold text-slate-100 mt-1">Executive Summary</h2>
                </div>

                <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                  <button
                    type="button"
                    onClick={handleDownloadCsv}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-800 text-slate-100 border border-slate-700 hover:border-cyan-400/60 hover:text-cyan-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <FileSpreadsheet className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Export CSV</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleDownloadPdf}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-800 text-slate-100 border border-slate-700 hover:border-cyan-400/60 hover:text-cyan-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Export PDF</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleDownloadMarkdown}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium text-slate-200 border border-slate-700 hover:border-slate-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Markdown (.md)</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleDownloadJson}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium text-slate-200 border border-slate-700 hover:border-slate-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <FileJson className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>JSON</span>
                  </button>
                </div>
              </div>

              <p className="text-sm text-slate-300 leading-relaxed">
                {report.analysis.executiveSummary}
              </p>
            </section>

            {activeTab === 'overview' && (
              <div className="space-y-8">
                <FindingsSection findings={report.analysis.findings} />
                <TelemetrySection recon={report.recon} />
              </div>
            )}

            {activeTab === 'findings' && (
              <FindingsSection findings={report.analysis.findings} />
            )}

            {activeTab === 'telemetry' && <TelemetrySection recon={report.recon} />}
          </div>
        )}
      </main>

      <footer className="border-t border-slate-800/80 bg-[#0B111E] py-5">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
          <span>VulnSense AI — Authorized Passive Security Reconnaissance & Hardening Toolkit</span>
          <button
            type="button"
            onClick={() => setActiveTab('deliverables')}
            className="text-slate-300 hover:text-cyan-300 underline underline-offset-4 cursor-pointer"
          >
            Termux / Linux Python CLI & Flask Source
          </button>
        </div>
      </footer>
    </div>
  );
}
