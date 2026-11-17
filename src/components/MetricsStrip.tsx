import type { ScanReport } from '../types/recon';
import { countSeverities } from '../lib/recon-utils';

interface MetricsStripProps {
  report: ScanReport;
}

function getGradeColorClass(grade: string): string {
  switch (grade) {
    case 'A':
      return 'text-emerald-400';
    case 'B':
      return 'text-cyan-400';
    case 'C':
      return 'text-amber-400';
    case 'D':
    case 'F':
      return 'text-rose-400';
    default:
      return 'text-slate-100';
  }
}

export function MetricsStrip({ report }: MetricsStripProps) {
  const { recon, analysis } = report;
  const counts = countSeverities(analysis.findings);
  const presentHeaders = recon.securityHeaders.filter((h) => h.present).length;
  const totalHeaders = recon.securityHeaders.length;

  return (
    <section aria-label="Security posture metrics" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <div className="bg-[#0E1525] border border-slate-800 rounded-xl p-5">
        <div className="text-xs font-medium text-slate-400">Security Score</div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-3xl font-bold font-mono tabular-nums text-slate-50">
            {analysis.securityScore.toFixed(1)}
          </span>
          <span className="text-sm font-mono text-slate-400">/ 10.0</span>
        </div>
        <div className="mt-3 h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
          <div
            className="h-full bg-cyan-400 transition-all duration-300"
            style={{ width: `${Math.min(100, Math.max(0, analysis.securityScore * 10))}%` }}
          />
        </div>
      </div>

      <div className="bg-[#0E1525] border border-slate-800 rounded-xl p-5">
        <div className="text-xs font-medium text-slate-400">Security Grade</div>
        <div className="mt-2 flex items-baseline gap-3">
          <span className={`text-3xl font-bold font-mono ${getGradeColorClass(analysis.grade)}`}>
            {analysis.grade}
          </span>
          <span className="text-xs text-slate-400">
            {presentHeaders}/{totalHeaders} key headers present
          </span>
        </div>
        <div className="mt-3 text-xs text-slate-400 font-mono truncate" title={recon.domain}>
          Target: {recon.domain}
        </div>
      </div>

      <div className="bg-[#0E1525] border border-slate-800 rounded-xl p-5">
        <div className="text-xs font-medium text-slate-400">Vulnerability Breakdown</div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-3xl font-bold font-mono tabular-nums text-slate-50">
            {counts.total}
          </span>
          <span className="text-xs text-slate-400">total findings</span>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs font-mono tabular-nums">
          <span className="text-rose-400">{counts.CRITICAL} CRIT</span>
          <span className="text-slate-600" aria-hidden="true">·</span>
          <span className="text-amber-400">{counts.HIGH} HIGH</span>
          <span className="text-slate-600" aria-hidden="true">·</span>
          <span className="text-yellow-300">{counts.MEDIUM} MED</span>
          <span className="text-slate-600" aria-hidden="true">·</span>
          <span className="text-cyan-400">{counts.LOW} LOW</span>
        </div>
      </div>

      <div className="bg-[#0E1525] border border-slate-800 rounded-xl p-5">
        <div className="text-xs font-medium text-slate-400">TLS & Transport</div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-slate-50">
            {recon.tls.enabled ? recon.tls.protocol ?? 'TLS Active' : 'No TLS'}
          </span>
        </div>
        <div className="mt-3 text-xs text-slate-400 font-mono tabular-nums">
          {recon.tls.enabled && recon.tls.daysRemaining !== null
            ? `Cert valid ${recon.tls.daysRemaining}d · HTTP ${recon.statusCode} · ${recon.responseTimeMs}ms`
            : `HTTP ${recon.statusCode} · ${recon.responseTimeMs}ms`}
        </div>
      </div>
    </section>
  );
}
