import { CheckCircle2, XCircle } from 'lucide-react';
import type { PassiveReconResult } from '../types/recon';

interface TelemetrySectionProps {
  recon: PassiveReconResult;
}

export function TelemetrySection({ recon }: TelemetrySectionProps) {
  return (
    <div className="space-y-6">
      <section className="bg-[#0E1525] border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between gap-4">
          <h2 className="text-base font-semibold text-slate-100">HTTP Security Headers</h2>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            {recon.securityHeaders.filter((h) => h.present).length} / {recon.securityHeaders.length} configured
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs text-slate-400">
                <th className="py-3 px-5 font-medium">Header</th>
                <th className="py-3 px-4 font-medium">Status</th>
                <th className="py-3 px-4 font-medium">Priority</th>
                <th className="py-3 px-5 font-medium">Observed Value</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-xs">
              {recon.securityHeaders.map((hdr) => (
                <tr key={hdr.key} className="hover:bg-slate-800/25 transition-colors">
                  <td className="py-3 px-5 font-mono text-slate-100 whitespace-nowrap">
                    {hdr.name}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    {hdr.present ? (
                      <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium">
                        <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>Present</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-rose-400 font-medium">
                        <XCircle className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>Missing</span>
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-slate-300 whitespace-nowrap">{hdr.importance}</td>
                  <td className="py-3 px-5 font-mono text-slate-300 max-w-md truncate" title={hdr.value ?? ''}>
                    {hdr.value ?? '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="bg-[#0E1525] border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="text-base font-semibold text-slate-100">SSL / TLS Certificate Posture</h2>
          <dl className="divide-y divide-slate-800/70 text-xs">
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-400">HTTPS Enabled</dt>
              <dd className="font-mono text-slate-100">{recon.tls.enabled ? 'Yes' : 'No'}</dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Protocol Version</dt>
              <dd className="font-mono text-slate-100">{recon.tls.protocol ?? 'N/A'}</dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Cipher Suite</dt>
              <dd className="font-mono text-slate-100 truncate max-w-xs">{recon.tls.cipher ?? 'N/A'}</dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Trust Verification</dt>
              <dd className={`font-mono ${recon.tls.authorized ? 'text-emerald-400' : 'text-rose-400'}`}>
                {recon.tls.authorized === null
                  ? 'N/A'
                  : recon.tls.authorized
                  ? 'Trusted'
                  : recon.tls.authorizationError ?? 'Untrusted'}
              </dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Issuer</dt>
              <dd className="font-mono text-slate-200 truncate max-w-xs">{recon.tls.issuer ?? 'N/A'}</dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Days Remaining</dt>
              <dd className="font-mono tabular-nums text-slate-100">
                {recon.tls.daysRemaining !== null ? `${recon.tls.daysRemaining} days` : 'N/A'}
              </dd>
            </div>
          </dl>
        </section>

        <section className="bg-[#0E1525] border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="text-base font-semibold text-slate-100">Server Banners & Public Metadata</h2>
          <dl className="divide-y divide-slate-800/70 text-xs">
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Server Header</dt>
              <dd className="font-mono text-slate-100">{recon.metadata.serverBanner ?? 'Not disclosed'}</dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-400">X-Powered-By</dt>
              <dd className="font-mono text-slate-100">{recon.metadata.poweredBy ?? 'Not disclosed'}</dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-400">robots.txt</dt>
              <dd className="font-mono text-slate-100">
                {recon.metadata.robotsTxtFound
                  ? `Present (HTTP ${recon.metadata.robotsTxtStatus})`
                  : 'Not found'}
              </dd>
            </div>
            <div className="py-2.5 flex items-center justify-between gap-4">
              <dt className="text-slate-400">security.txt</dt>
              <dd className="font-mono text-slate-100">
                {recon.metadata.securityTxtFound ? 'Present' : 'Not found'}
              </dd>
            </div>
          </dl>

          {recon.metadata.robotsTxtPreview && (
            <div className="pt-2">
              <div className="text-xs font-medium text-slate-400 mb-1.5">robots.txt Preview</div>
              <pre className="p-3 rounded-lg bg-[#080C14] border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto max-h-36">
                <code>{recon.metadata.robotsTxtPreview}</code>
              </pre>
            </div>
          )}
        </section>
      </div>

      <section className="bg-[#0E1525] border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between gap-4">
          <h2 className="text-base font-semibold text-slate-100">Cookie Security Audit</h2>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            {recon.cookies.length} Set-Cookie {recon.cookies.length === 1 ? 'header' : 'headers'}
          </span>
        </div>

        {recon.cookies.length === 0 ? (
          <div className="p-5 text-xs text-slate-400">
            No Set-Cookie headers were issued during the initial passive GET request.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-400">
                  <th className="py-3 px-5 font-medium">Cookie Name</th>
                  <th className="py-3 px-4 font-medium">HttpOnly</th>
                  <th className="py-3 px-4 font-medium">Secure</th>
                  <th className="py-3 px-4 font-medium">SameSite</th>
                  <th className="py-3 px-5 font-medium">Audit Notes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-xs">
                {recon.cookies.map((cookie, idx) => (
                  <tr key={`${cookie.name}-${idx}`} className="hover:bg-slate-800/25">
                    <td className="py-3 px-5 font-mono text-slate-100">{cookie.name}</td>
                    <td className={`py-3 px-4 font-mono ${cookie.httpOnly ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {cookie.httpOnly ? 'Yes' : 'No'}
                    </td>
                    <td className={`py-3 px-4 font-mono ${cookie.secure ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {cookie.secure ? 'Yes' : 'No'}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-200">{cookie.sameSite ?? 'Missing'}</td>
                    <td className="py-3 px-5 text-slate-300">
                      {cookie.issues.length > 0 ? cookie.issues.join(' · ') : 'Hardened flags present'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
