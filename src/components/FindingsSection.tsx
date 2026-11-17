import { useState } from 'react';
import { ChevronDown, ChevronRight, Check, Copy, Search } from 'lucide-react';
import type { SeverityLevel, VulnerabilityFinding } from '../types/recon';

interface FindingsSectionProps {
  findings: VulnerabilityFinding[];
}

type SeverityFilter = 'ALL' | SeverityLevel;

const SEVERITY_TEXT_CLASS: Record<SeverityLevel, string> = {
  CRITICAL: 'text-rose-400',
  HIGH: 'text-amber-400',
  MEDIUM: 'text-yellow-300',
  LOW: 'text-cyan-400',
};

const FILTER_OPTIONS: SeverityFilter[] = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export function FindingsSection({ findings }: FindingsSectionProps) {
  const [filter, setFilter] = useState<SeverityFilter>('ALL');
  const [query, setQuery] = useState('');
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>(() =>
    findings[0] ? { [findings[0].id]: true } : {}
  );
  const [snippetTabById, setSnippetTabById] = useState<Record<string, 'nginx' | 'apache'>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const normalizedQuery = query.trim().toLowerCase();
  const visibleFindings = findings.filter((item) => {
    const matchesSeverity = filter === 'ALL' || item.severity === filter;
    const matchesQuery =
      !normalizedQuery ||
      item.title.toLowerCase().includes(normalizedQuery) ||
      item.category.toLowerCase().includes(normalizedQuery) ||
      item.affectedComponent.toLowerCase().includes(normalizedQuery) ||
      item.riskExplanation.toLowerCase().includes(normalizedQuery);
    return matchesSeverity && matchesQuery;
  });

  const toggleFinding = (id: string) => {
    setExpandedIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopySnippet = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1800);
    } catch {
      // Clipboard API unavailable
    }
  };

  return (
    <section aria-label="Vulnerability findings" className="space-y-4">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-1 p-1 rounded-lg bg-[#0E1525] border border-slate-800">
          {FILTER_OPTIONS.map((opt) => {
            const active = filter === opt;
            return (
              <button
                key={opt}
                type="button"
                onClick={() => setFilter(opt)}
                className={`px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  active
                    ? 'bg-slate-800 text-slate-50'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {opt}
              </button>
            );
          })}
        </div>

        <div className="relative w-full md:w-72">
          <label htmlFor="findings-search" className="sr-only">
            Filter vulnerability findings
          </label>
          <Search
            className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
            aria-hidden="true"
          />
          <input
            id="findings-search"
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter findings..."
            className="w-full h-9 pl-9 pr-3 rounded-lg bg-[#0E1525] border border-slate-800 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
          />
        </div>
      </div>

      {visibleFindings.length === 0 ? (
        <div className="bg-[#0E1525] border border-slate-800 rounded-xl p-8 text-center">
          <p className="text-sm text-slate-300">No findings match the active filter criteria.</p>
          <button
            type="button"
            onClick={() => {
              setFilter('ALL');
              setQuery('');
            }}
            className="mt-3 text-xs font-medium text-cyan-400 hover:text-cyan-300 underline underline-offset-4 cursor-pointer"
          >
            Reset filters
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {visibleFindings.map((finding) => {
            const isExpanded = !!expandedIds[finding.id];
            const activeServerTab = snippetTabById[finding.id] ?? 'nginx';
            const activeSnippet =
              activeServerTab === 'nginx' ? finding.nginxSnippet : finding.apacheSnippet;

            return (
              <div
                key={finding.id}
                className="bg-[#0E1525] border border-slate-800 rounded-xl overflow-hidden"
              >
                <button
                  type="button"
                  aria-expanded={isExpanded}
                  onClick={() => toggleFinding(finding.id)}
                  className="w-full px-5 py-4 text-left flex items-start sm:items-center justify-between gap-4 hover:bg-slate-800/35 transition-colors cursor-pointer"
                >
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                      <span
                        className={`font-mono text-xs font-semibold tracking-wide ${
                          SEVERITY_TEXT_CLASS[finding.severity]
                        }`}
                      >
                        [{finding.severity}]
                      </span>
                      <span className="text-sm font-semibold text-slate-100">
                        {finding.title}
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <span>{finding.category}</span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono text-slate-300">{finding.affectedComponent}</span>
                    </div>
                  </div>

                  <span className="text-slate-400 shrink-0 mt-0.5 sm:mt-0" aria-hidden="true">
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4" />
                    ) : (
                      <ChevronRight className="w-4 h-4" />
                    )}
                  </span>
                </button>

                {isExpanded && (
                  <div className="px-5 pb-5 pt-4 border-t border-slate-800/80 space-y-5">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <div>
                        <h3 className="text-xs font-semibold text-slate-300 mb-2">
                          Risk Explanation
                        </h3>
                        <p className="text-sm text-slate-300 leading-relaxed">
                          {finding.riskExplanation}
                        </p>
                      </div>

                      <div>
                        <h3 className="text-xs font-semibold text-slate-300 mb-2">
                          Remediation Steps
                        </h3>
                        <ul className="space-y-1.5 text-sm text-slate-300 list-disc list-inside">
                          {finding.remediationSteps.map((step, i) => (
                            <li key={i} className="leading-relaxed">
                              {step}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <div className="flex items-center justify-between gap-4">
                        <div className="flex items-center gap-1 p-1 rounded-lg bg-[#080C14] border border-slate-800">
                          <button
                            type="button"
                            onClick={() =>
                              setSnippetTabById((prev) => ({ ...prev, [finding.id]: 'nginx' }))
                            }
                            className={`px-3 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                              activeServerTab === 'nginx'
                                ? 'bg-slate-800 text-slate-50'
                                : 'text-slate-400 hover:text-slate-200'
                            }`}
                          >
                            Nginx Config
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              setSnippetTabById((prev) => ({ ...prev, [finding.id]: 'apache' }))
                            }
                            className={`px-3 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                              activeServerTab === 'apache'
                                ? 'bg-slate-800 text-slate-50'
                                : 'text-slate-400 hover:text-slate-200'
                            }`}
                          >
                            Apache Config
                          </button>
                        </div>

                        <button
                          type="button"
                          onClick={() => handleCopySnippet(finding.id, activeSnippet)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-slate-300 border border-slate-700 hover:border-slate-500 hover:text-slate-100 transition-colors cursor-pointer"
                        >
                          {copiedId === finding.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                              <span>Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                              <span>Copy Snippet</span>
                            </>
                          )}
                        </button>
                      </div>

                      <pre className="p-4 rounded-lg bg-[#080C14] border border-slate-800 text-xs font-mono text-cyan-200 overflow-x-auto leading-relaxed">
                        <code>{activeSnippet}</code>
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
