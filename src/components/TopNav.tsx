import { Download } from 'lucide-react';

export type WorkspaceTab = 'overview' | 'findings' | 'telemetry' | 'deliverables';

interface TopNavProps {
  activeTab: WorkspaceTab;
  onSelectTab: (tab: WorkspaceTab) => void;
  hasReport: boolean;
  onDownloadMarkdown: () => void;
}

const NAV_ITEMS: Array<{ id: WorkspaceTab; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'findings', label: 'Findings' },
  { id: 'telemetry', label: 'Telemetry' },
  { id: 'deliverables', label: 'Python Source' },
];

export function TopNav({
  activeTab,
  onSelectTab,
  hasReport,
  onDownloadMarkdown,
}: TopNavProps) {
  return (
    <header className="border-b border-slate-800/90 bg-[#0B111E]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-8">
        <button
          type="button"
          onClick={() => onSelectTab('overview')}
          className="text-lg font-bold tracking-tight text-slate-50 hover:text-cyan-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          VulnSense AI
        </button>

        <nav aria-label="Primary navigation" className="hidden md:flex items-center gap-6">
          {NAV_ITEMS.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectTab(item.id)}
                className={`py-5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  isActive
                    ? 'border-cyan-400 text-slate-50'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={onDownloadMarkdown}
            disabled={!hasReport}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-400 text-slate-950 hover:bg-cyan-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Export Report</span>
          </button>
        </div>
      </div>

      <nav
        aria-label="Mobile navigation"
        className="md:hidden flex items-center gap-4 px-4 pb-3 overflow-x-auto border-t border-slate-800/60"
      >
        {NAV_ITEMS.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onSelectTab(item.id)}
              className={`pt-2.5 pb-1 text-xs font-medium border-b-2 whitespace-nowrap shrink-0 cursor-pointer ${
                isActive
                  ? 'border-cyan-400 text-slate-50'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              {item.label}
            </button>
          );
        })}
      </nav>
    </header>
  );
}
