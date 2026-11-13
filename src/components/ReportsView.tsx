import React, { useState } from 'react';
import { jsPDF } from 'jspdf';
import { Copy, Download, FileText, Trash2 } from 'lucide-react';
import type {
  ReportFormat,
  ScanRecord,
  SecurityReport,
  UserPreferences,
} from '../types/phishshield';

interface ReportsViewProps {
  scans: ScanRecord[];
  reports: SecurityReport[];
  userId?: string;
  isVerified: boolean;
  preferences: UserPreferences;
  onSaveReport: (
    report: Omit<SecurityReport, 'id' | 'userId' | 'createdAtMs' | 'updatedAtMs'>
  ) => Promise<string>;
  onDeleteReport: (reportId: string) => Promise<void>;
}

function buildReportContent(
  title: string,
  format: ReportFormat,
  scans: ScanRecord[]
): { summary: string; content: string; highRiskCount: number } {
  const highRiskCount = scans.filter(
    (s) => s.riskLevel === 'Known Malicious' || s.riskLevel === 'High Risk'
  ).length;
  const unknownCount = scans.filter((s) => s.riskLevel === 'Unknown/Unverified').length;

  const summary = `Analyzed ${scans.length} scan record(s): ${highRiskCount} Known Malicious / High Risk, ${unknownCount} Unknown/Unverified. Deterministic heuristic + Gemini static analysis (no external URLs visited).`;

  if (format === 'json') {
    const payload = {
      title,
      generatedAt: new Date().toISOString(),
      policy: 'Unknown URLs are never classified as Safe; external URLs are never visited.',
      totals: {
        scans: scans.length,
        highOrCriticalRisk: highRiskCount,
        unknownOrUnverified: unknownCount,
      },
      records: scans.map((s) => ({
        id: s.id,
        channel: s.scanType,
        targetPreview: s.targetPreview,
        submittedUrl: s.submittedUrl || null,
        riskLevel: s.riskLevel,
        riskScore: s.riskScore,
        heuristicScore: s.heuristicScore ?? s.riskScore,
        reputationResult: s.reputationResult || null,
        reputationProvider: s.reputationProvider || null,
        reputationCheckedAt: s.reputationCheckedAt || null,
        threatCategories: s.threatCategories ?? [],
        indicators: s.indicators,
        verdictSummary: s.verdictSummary,
        analystNote: s.analystNote,
        createdAt: new Date(s.createdAtMs).toISOString(),
      })),
    };
    return { summary, content: JSON.stringify(payload, null, 2), highRiskCount };
  }

  if (format === 'pdf') {
    const lines = [
      title.toUpperCase(),
      `Generated: ${new Date().toISOString()}`,
      `Policy: Unknown URLs are never classified as Safe; external URLs are never visited.`,
      `Summary: ${summary}`,
      ``,
      `SCANNED TARGETS`,
      `------------------------------------------------------------`,
      ...scans.slice(0, 40).flatMap((s, i) => [
        `${i + 1}. [${s.scanType.toUpperCase()}] ${s.targetPreview}`,
        `   Classification: ${s.riskLevel} (${s.riskScore}/100)`,
        ...(s.reputationResult
          ? [
              `   Reputation: ${s.reputationResult} (${s.reputationProvider || 'Provider'})` +
                (s.threatCategories && s.threatCategories.length > 0
                  ? ` · Categories: ${s.threatCategories.join(', ')}`
                  : ''),
            ]
          : []),
        `   Verdict: ${s.verdictSummary}`,
        `   Signals: ${s.indicators.join('; ') || 'None'}`,
        ...(s.analystNote ? [`   Analyst Note: ${s.analystNote}`] : []),
        ``,
      ]),
    ];
    return { summary, content: lines.join('\n'), highRiskCount };
  }

  const lines = [
    `# ${title}`,
    ``,
    `Generated: ${new Date().toISOString()}`,
    `Summary: ${summary}`,
    ``,
    `## Scanned Targets`,
    ...scans.slice(0, 40).map(
      (s, i) =>
        `### ${i + 1}. [${s.scanType.toUpperCase()}] ${s.targetPreview}\n- **Classification:** ${s.riskLevel} (${s.riskScore}/100)${
          s.reputationResult
            ? `\n- **Reputation:** ${s.reputationResult} via ${s.reputationProvider || 'Provider'}${
                s.reputationCheckedAt ? ` (checked ${s.reputationCheckedAt})` : ''
              }${
                s.threatCategories && s.threatCategories.length > 0
                  ? ` — Categories: ${s.threatCategories.join(', ')}`
                  : ''
              }`
            : ''
        }\n- **Verdict:** ${s.verdictSummary}\n- **Signals:** ${s.indicators.join('; ')}${
          s.analystNote ? `\n- **Analyst Note:** ${s.analystNote}` : ''
        }`
    ),
  ];

  return { summary, content: lines.join('\n'), highRiskCount };
}

export const ReportsView: React.FC<ReportsViewProps> = ({
  scans,
  reports,
  userId,
  isVerified,
  preferences,
  onSaveReport,
  onDeleteReport,
}) => {
  const [title, setTitle] = useState('PhishShield Threat Summary Report');
  const [format, setFormat] = useState<ReportFormat>(preferences.defaultReportFormat);
  const [onlyThreats, setOnlyThreats] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [activeReport, setActiveReport] = useState<SecurityReport | null>(null);
  const [copied, setCopied] = useState(false);

  React.useEffect(() => {
    setFormat(preferences.defaultReportFormat);
  }, [preferences.defaultReportFormat]);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    const targetScans = onlyThreats
      ? scans.filter(
          (s) =>
            s.riskLevel === 'Known Malicious' ||
            s.riskLevel === 'High Risk' ||
            s.riskLevel === 'Suspicious'
        )
      : scans;

    if (targetScans.length === 0) {
      setStatusMsg('No scan records match the selected filter. Run a scan first.');
      return;
    }

    setGenerating(true);
    setStatusMsg(null);

    try {
      const cleanTitle = title.trim() || 'PhishShield Threat Summary Report';
      const { summary, content, highRiskCount } = buildReportContent(
        cleanTitle,
        format,
        targetScans
      );

      const id = await onSaveReport({
        title: cleanTitle,
        format,
        scanCount: targetScans.length,
        highRiskCount,
        summary,
        content,
      });

      const created: SecurityReport = {
        id,
        userId: userId || 'demo-session',
        title: cleanTitle,
        format,
        scanCount: targetScans.length,
        highRiskCount,
        summary,
        content,
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
      };
      setActiveReport(created);
      setStatusMsg(
        userId && isVerified
          ? 'Report metadata saved to Cloud Firestore. Ready for local PDF, JSON, or Markdown download.'
          : 'Report generated for this session. Sign in to save metadata to Cloud Firestore.'
      );
    } catch (err) {
      setStatusMsg(err instanceof Error ? err.message : 'Failed to generate report.');
    } finally {
      setGenerating(false);
    }
  };

  const downloadLocalFile = (report: SecurityReport) => {
    const baseName = report.title.toLowerCase().replace(/[^a-z0-9]+/g, '_') || 'phishshield_report';

    if (report.format === 'pdf') {
      const pdf = new jsPDF({ unit: 'pt', format: 'letter' });
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 44;
      const maxWidth = pageWidth - margin * 2;
      let cursorY = 52;

      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(16);
      const titleLines = pdf.splitTextToSize(report.title, maxWidth) as string[];
      pdf.text(titleLines, margin, cursorY);
      cursorY += titleLines.length * 20 + 6;

      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(9.5);
      pdf.setTextColor(80, 90, 105);
      const metaLine = `PhishShield AI Security Report · ${report.scanCount} scan(s) · ${report.highRiskCount} High/Critical`;
      pdf.text(metaLine, margin, cursorY);
      cursorY += 18;

      pdf.setDrawColor(210, 218, 230);
      pdf.line(margin, cursorY, pageWidth - margin, cursorY);
      cursorY += 18;

      pdf.setFont('courier', 'normal');
      pdf.setFontSize(9.5);
      pdf.setTextColor(25, 35, 50);
      const bodyLines = pdf.splitTextToSize(report.content, maxWidth) as string[];
      for (const line of bodyLines) {
        if (cursorY > pageHeight - margin) {
          pdf.addPage();
          cursorY = margin;
        }
        pdf.text(line, margin, cursorY);
        cursorY += 13;
      }

      pdf.save(`${baseName}.pdf`);
      return;
    }

    const mime = report.format === 'json' ? 'application/json' : 'text/markdown';
    const ext = report.format === 'json' ? 'json' : 'md';
    const blob = new Blob([report.content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${baseName}.${ext}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const copyContent = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard blocked
    }
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-5">
        <div className="space-y-1 pb-4 border-b border-slate-800">
          <div className="text-xs text-slate-400">
            Cloud Firestore Metadata &amp; Browser Direct Export (PDF, JSON, Markdown)
          </div>
          <h1 className="text-2xl font-semibold text-slate-50">Security Reports</h1>
        </div>

        <form onSubmit={handleGenerate} className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          <label className="md:col-span-2 block space-y-1.5">
            <span className="text-xs font-medium text-slate-300">Report Title</span>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] px-3.5 py-2.5 text-sm text-slate-100 focus:border-blue-500 focus:outline-none"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-xs font-medium text-slate-300">Export Format</span>
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value as ReportFormat)}
              className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] px-3 py-2.5 text-sm text-slate-100 focus:border-blue-500 focus:outline-none"
            >
              <option value="pdf">PDF Document (.pdf)</option>
              <option value="markdown">Markdown (.md)</option>
              <option value="json">Structured JSON (.json)</option>
            </select>
          </label>

          <button
            type="submit"
            disabled={generating}
            className="rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60 transition-colors whitespace-nowrap cursor-pointer"
          >
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </form>

        <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={onlyThreats}
            onChange={(e) => setOnlyThreats(e.target.checked)}
            className="h-4 w-4 accent-blue-600"
          />
          <span>Include only Suspicious / High Risk / Known Malicious findings</span>
        </label>

        {statusMsg && <p className="text-xs text-sky-400">{statusMsg}</p>}
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <section className="rounded-xl border border-slate-800 bg-[#111827] p-5 space-y-3">
          <h2 className="text-base font-semibold text-slate-100">Saved Reports</h2>
          {reports.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-800 bg-[#0A0F1A] p-6 text-center space-y-2">
              <FileText className="h-5 w-5 text-slate-500 mx-auto" />
              <p className="text-xs text-slate-400">
                No reports generated yet. Create a PDF, Markdown, or JSON report above.
              </p>
            </div>
          ) : (
            <ul className="space-y-2">
              {reports.map((rep) => (
                <li
                  key={rep.id}
                  className={`rounded-lg border p-3 transition-colors flex items-start justify-between gap-3 ${
                    activeReport?.id === rep.id
                      ? 'border-blue-600 bg-[#152036]'
                      : 'border-slate-800 bg-[#0A0F1A] hover:border-slate-700'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => setActiveReport(rep)}
                    className="text-left flex-1 min-w-0 space-y-1 cursor-pointer"
                  >
                    <div className="text-sm font-medium text-slate-100 truncate">{rep.title}</div>
                    <div className="text-xs text-slate-400 font-mono tabular-nums">
                      {rep.format.toUpperCase()} · {rep.scanCount} scans · {rep.highRiskCount} high
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      void onDeleteReport(rep.id);
                      if (activeReport?.id === rep.id) setActiveReport(null);
                    }}
                    aria-label="Delete report"
                    className="text-slate-500 hover:text-red-400 p-1 cursor-pointer"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="lg:col-span-2 rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-4">
          {activeReport ? (
            <>
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-4 border-b border-slate-800">
                <div>
                  <h2 className="text-lg font-semibold text-slate-100">{activeReport.title}</h2>
                  <p className="text-xs text-slate-400">{activeReport.summary}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => void copyContent(activeReport.content)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-[#0A0F1A] px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 cursor-pointer"
                  >
                    <Copy className="h-3.5 w-3.5" />
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => downloadLocalFile(activeReport)}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-500 cursor-pointer"
                  >
                    <Download className="h-3.5 w-3.5" />
                    <span>Download {activeReport.format.toUpperCase()}</span>
                  </button>
                </div>
              </div>
              <pre className="rounded-lg border border-slate-800 bg-[#0A0F1A] p-4 text-xs font-mono text-slate-200 overflow-x-auto max-h-[460px] whitespace-pre-wrap">
                {activeReport.content}
              </pre>
            </>
          ) : (
            <div className="h-72 flex items-center justify-center text-sm text-slate-400 text-center">
              Select a saved report or generate a new export to preview its contents.
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
