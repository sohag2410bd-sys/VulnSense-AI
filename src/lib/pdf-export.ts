import { jsPDF } from 'jspdf';
import type { ScanReport } from '../types/recon';
import { countSeverities, sortFindingsBySeverity } from './recon-utils';

export function exportScanReportPdf(report: ScanReport): void {
  const { recon, analysis } = report;
  const counts = countSeverities(analysis.findings);
  const findings = sortFindingsBySeverity(analysis.findings);

  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 16;
  const contentWidth = pageWidth - margin * 2;
  let y = 18;

  const ensureSpace = (neededMm: number) => {
    if (y + neededMm > pageHeight - 18) {
      doc.addPage();
      y = 18;
    }
  };

  // Top Header Band
  doc.setFillColor(14, 21, 37);
  doc.rect(0, 0, pageWidth, 34, 'F');
  doc.setTextColor(34, 211, 238);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(17);
  doc.text('VulnSense AI — Security Audit Report', margin, 15);

  doc.setTextColor(203, 213, 225);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.text(`Target: ${recon.targetUrl}`, margin, 22);
  doc.text(
    `Generated: ${new Date(recon.collectedAt).toUTCString()}   |   HTTP ${recon.statusCode} (${recon.responseTimeMs} ms)`,
    margin,
    28
  );

  y = 44;

  // Score & Grade Summary Box
  doc.setDrawColor(203, 213, 225);
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(margin, y, contentWidth, 24, 2, 2, 'FD');

  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text(`Security Score: ${analysis.securityScore.toFixed(1)} / 10.0`, margin + 5, y + 9);
  doc.text(`Security Grade: ${analysis.grade}`, margin + 72, y + 9);
  doc.text(
    `TLS: ${recon.tls.enabled ? recon.tls.protocol ?? 'Active' : 'Disabled'}`,
    margin + 122,
    y + 9
  );

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(51, 65, 85);
  doc.text(
    `Findings: ${counts.total} Total  (Critical: ${counts.CRITICAL}, High: ${counts.HIGH}, Medium: ${counts.MEDIUM}, Low: ${counts.LOW})`,
    margin + 5,
    y + 18
  );

  y += 32;

  // Executive Summary
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.text('Executive Summary', margin, y);
  y += 6;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(51, 65, 85);
  const summaryLines = doc.splitTextToSize(analysis.executiveSummary, contentWidth);
  doc.text(summaryLines, margin, y);
  y += summaryLines.length * 5 + 8;

  // Vulnerability Findings
  ensureSpace(16);
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.text('Identified Vulnerabilities & Remediation', margin, y);
  y += 7;

  if (findings.length === 0) {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.text('No vulnerabilities were flagged during passive reconnaissance.', margin, y);
    y += 8;
  } else {
    findings.forEach((finding, idx) => {
      ensureSpace(34);

      // Severity color badge text
      if (finding.severity === 'CRITICAL') doc.setTextColor(190, 18, 60);
      else if (finding.severity === 'HIGH') doc.setTextColor(180, 83, 9);
      else if (finding.severity === 'MEDIUM') doc.setTextColor(161, 98, 7);
      else doc.setTextColor(14, 116, 144);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10.5);
      const headerText = `${idx + 1}. [${finding.severity}] ${finding.title}`;
      const headerLines = doc.splitTextToSize(headerText, contentWidth);
      doc.text(headerLines, margin, y);
      y += headerLines.length * 5 + 1;

      doc.setTextColor(100, 116, 139);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.text(
        `Category: ${finding.category}   |   Component: ${finding.affectedComponent}`,
        margin,
        y
      );
      y += 5;

      doc.setTextColor(30, 41, 59);
      doc.setFontSize(9.5);
      const riskLines = doc.splitTextToSize(finding.riskExplanation, contentWidth);
      ensureSpace(riskLines.length * 4.5 + 8);
      doc.text(riskLines, margin, y);
      y += riskLines.length * 4.5 + 3;

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.text('Remediation Steps:', margin, y);
      y += 4.5;

      doc.setFont('helvetica', 'normal');
      for (const step of finding.remediationSteps) {
        const stepLines = doc.splitTextToSize(`• ${step}`, contentWidth - 4);
        ensureSpace(stepLines.length * 4.5 + 2);
        doc.text(stepLines, margin + 2, y);
        y += stepLines.length * 4.5;
      }

      y += 2;
      const fixText = `Nginx: ${finding.nginxSnippet.replace(/\n/g, ' ')}`;
      const fixLines = doc.splitTextToSize(fixText, contentWidth - 4);
      ensureSpace(fixLines.length * 4 + 8);
      doc.setFont('courier', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(51, 65, 85);
      doc.text(fixLines, margin + 2, y);
      y += fixLines.length * 4 + 6;
    });
  }

  // Page numbers
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `VulnSense AI Audit Report — ${recon.domain}`,
      margin,
      pageHeight - 10
    );
    doc.text(`Page ${p} of ${totalPages}`, pageWidth - margin - 20, pageHeight - 10);
  }

  doc.save(`report_${recon.domain}.pdf`);
}
