import { useEffect, useState } from 'react';
import { Check, Copy, Download, FileCode2, FolderArchive, Terminal } from 'lucide-react';
import type { DeliverableFile } from '../types/recon';

export function DeliverablesSection() {
  const [files, setFiles] = useState<DeliverableFile[]>([]);
  const [selectedPath, setSelectedPath] = useState<string>('scanner.py');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let active = true;
    fetch('/api/deliverables')
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to load Python deliverables');
        return data.files as DeliverableFile[];
      })
      .then((loaded) => {
        if (!active) return;
        setFiles(loaded);
        if (loaded.length > 0) {
          setSelectedPath((prev) =>
            loaded.some((f) => f.path === prev) ? prev : loaded[0].path
          );
        }
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : 'Unable to fetch deliverables');
        setLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  const activeFile = files.find((f) => f.path === selectedPath) ?? files[0] ?? null;

  const handleCopyFile = async () => {
    if (!activeFile) return;
    try {
      await navigator.clipboard.writeText(activeFile.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard unavailable
    }
  };

  const handleDownloadSingleFile = () => {
    if (!activeFile) return;
    const blob = new Blob([activeFile.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = activeFile.name.split('/').pop() ?? activeFile.name;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section aria-label="Python CLI and Flask source deliverables" className="space-y-6">
      <div className="bg-[#0E1525] border border-slate-800 rounded-xl p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <h2 className="text-lg font-semibold text-slate-100">
            Python CLI (Termux & Linux) + Flask Web Deliverables
          </h2>
          <p className="text-sm text-slate-400">
            Complete open-source Python package with adaptive Rich CLI output, Flask backend, Tailwind
            template, and setup documentation.
          </p>
        </div>

        <a
          href="/api/deliverables/zip"
          download="vulnsense-ai-python.zip"
          className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-400 text-slate-950 font-semibold text-xs hover:bg-cyan-300 transition-colors whitespace-nowrap shrink-0"
        >
          <FolderArchive className="w-4 h-4" aria-hidden="true" />
          <span>Download Python Bundle (.zip)</span>
        </a>
      </div>

      {loading ? (
        <div className="bg-[#0E1525] border border-slate-800 rounded-xl p-8 text-sm text-slate-400">
          Loading Python source deliverables...
        </div>
      ) : error ? (
        <div className="bg-[#0E1525] border border-rose-500/40 rounded-xl p-6 text-sm text-rose-300">
          {error}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <aside className="lg:col-span-4 bg-[#0E1525] border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800 text-xs font-semibold text-slate-300">
              Project Structure (vulnsense-ai/)
            </div>
            <div className="divide-y divide-slate-800/60">
              {files.map((file) => {
                const isSelected = activeFile?.path === file.path;
                return (
                  <button
                    key={file.path}
                    type="button"
                    onClick={() => setSelectedPath(file.path)}
                    className={`w-full px-4 py-3 text-left flex items-start gap-3 cursor-pointer ${
                      isSelected
                        ? 'bg-slate-800/70 text-cyan-300'
                        : 'text-slate-300 hover:bg-slate-800/35'
                    }`}
                  >
                    <FileCode2 className="w-4 h-4 shrink-0 mt-0.5 text-slate-400" aria-hidden="true" />
                    <div className="min-w-0">
                      <div className="font-mono text-xs font-semibold truncate">{file.path}</div>
                      <div className="text-xs text-slate-400 line-clamp-2 mt-0.5">
                        {file.description}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>

            <div className="p-4 border-t border-slate-800 bg-[#0B111E] space-y-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
                <span>Quick Run (Termux & Linux)</span>
              </div>
              <pre className="p-3 rounded-lg bg-[#080C14] border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto leading-relaxed">
                <code>{`pip install -r requirements.txt\npython cli.py https://example.com\npython app.py`}</code>
              </pre>
            </div>
          </aside>

          {activeFile && (
            <div className="lg:col-span-8 bg-[#0E1525] border border-slate-800 rounded-xl overflow-hidden">
              <div className="px-5 py-3.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="font-mono text-sm font-semibold text-slate-100">
                    {activeFile.path}
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5">{activeFile.description}</div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={handleCopyFile}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-slate-300 border border-slate-700 hover:border-slate-500 hover:text-slate-100 transition-colors cursor-pointer"
                  >
                    {copied ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>Copy File</span>
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={handleDownloadSingleFile}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-slate-300 border border-slate-700 hover:border-slate-500 hover:text-slate-100 transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Save</span>
                  </button>
                </div>
              </div>

              <pre className="p-5 bg-[#080C14] text-xs font-mono text-slate-200 overflow-x-auto max-h-[620px] leading-relaxed">
                <code>{activeFile.content}</code>
              </pre>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
