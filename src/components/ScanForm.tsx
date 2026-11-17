import { FormEvent } from 'react';
import { Search, ShieldAlert, Loader2 } from 'lucide-react';

interface ScanFormProps {
  targetUrl: string;
  onChangeUrl: (val: string) => void;
  onSubmitScan: (urlOverride?: string) => void;
  onLoadSample: () => void;
  hasReport: boolean;
  isScanning: boolean;
  error: string | null;
}

const PRESET_TARGETS = ['https://example.com', 'https://github.com', 'https://httpbin.org'];

export function ScanForm({
  targetUrl,
  onChangeUrl,
  onSubmitScan,
  onLoadSample,
  hasReport,
  isScanning,
  error,
}: ScanFormProps) {
  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    onSubmitScan();
  };

  return (
    <section className="bg-[#0E1525] border border-slate-800 rounded-xl p-6 sm:p-7">
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6">
        <div className="max-w-2xl">
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-50 [text-wrap:balance]">
            Passive Web Reconnaissance & Security Audit
          </h1>
          <p className="mt-2 text-sm text-slate-400 leading-relaxed">
            Inspect HTTP security headers, TLS certificate posture, cookie attributes, and server
            banners, then generate structured remediation guidance and Nginx/Apache hardening rules.
          </p>
        </div>

        {hasReport && (
          <button
            type="button"
            onClick={onLoadSample}
            disabled={isScanning}
            className="self-start lg:self-auto px-3.5 py-2 rounded-lg text-xs font-medium text-slate-300 border border-slate-700 hover:border-slate-500 hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Load Sample Baseline
          </button>
        )}
      </div>

      <form onSubmit={handleSubmit} className="mt-6 flex flex-col sm:flex-row gap-3">
        <div className="flex-1">
          <label htmlFor="target-url-input" className="sr-only">
            Target website URL
          </label>
          <div className="relative">
            <Search
              className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
              aria-hidden="true"
            />
            <input
              id="target-url-input"
              type="text"
              value={targetUrl}
              onChange={(e) => onChangeUrl(e.target.value)}
              placeholder="Enter target URL or domain (e.g., https://example.com)"
              disabled={isScanning}
              className="w-full h-11 pl-10 pr-4 rounded-lg bg-[#080C14] border border-slate-700 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400 transition-colors font-mono"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={isScanning}
          className="h-11 px-6 rounded-lg bg-cyan-400 text-slate-950 font-semibold text-sm hover:bg-cyan-300 disabled:opacity-60 disabled:cursor-not-allowed transition-colors inline-flex items-center justify-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
        >
          {isScanning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
              <span>Scanning Target...</span>
            </>
          ) : (
            <span>Run Scan</span>
          )}
        </button>
      </form>

      <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-400">
        <span>Quick targets:</span>
        {PRESET_TARGETS.map((preset) => (
          <button
            key={preset}
            type="button"
            disabled={isScanning}
            onClick={() => {
              onChangeUrl(preset);
              onSubmitScan(preset);
            }}
            className="font-mono text-slate-300 hover:text-cyan-300 underline underline-offset-4 decoration-slate-700 hover:decoration-cyan-400 transition-colors cursor-pointer"
          >
            {preset.replace('https://', '')}
          </button>
        ))}
      </div>

      {error && (
        <div
          role="alert"
          className="mt-4 flex items-start gap-2.5 rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-200"
        >
          <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}
    </section>
  );
}
