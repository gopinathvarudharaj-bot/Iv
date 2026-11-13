import React, { useState } from 'react';
import {
  ArrowRight,
  Bot,
  FileText,
  Link2,
  Mail,
  QrCode,
  SlidersHorizontal,
} from 'lucide-react';
import type {
  NavTab,
  ReportFormat,
  ScanRecord,
  SecurityReport,
  SensitivityLevel,
  UserPreferences,
} from '../types/phishshield';
import { getRiskAppearance } from './RiskResultPanel';

interface DashboardViewProps {
  scans: ScanRecord[];
  reports: SecurityReport[];
  preferences: UserPreferences;
  isSignedIn: boolean;
  isVerified: boolean;
  loadingData: boolean;
  onNavigate: (tab: NavTab) => void;
  onSavePreferences: (
    next: Omit<UserPreferences, 'userId' | 'createdAt' | 'updatedAt'>
  ) => Promise<void>;
  onSelectScanForAssistant: (scan: ScanRecord) => void;
  onOpenAuth: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  scans,
  reports,
  preferences,
  isSignedIn,
  isVerified,
  loadingData,
  onNavigate,
  onSavePreferences,
  onSelectScanForAssistant,
  onOpenAuth,
}) => {
  const [savingPrefs, setSavingPrefs] = useState(false);
  const [prefMessage, setPrefMessage] = useState<string | null>(null);
  const [draftPrefs, setDraftPrefs] = useState({
    sensitivity: preferences.sensitivity,
    autoExplainWithAi: preferences.autoExplainWithAi,
    defaultReportFormat: preferences.defaultReportFormat,
  });

  React.useEffect(() => {
    setDraftPrefs({
      sensitivity: preferences.sensitivity,
      autoExplainWithAi: preferences.autoExplainWithAi,
      defaultReportFormat: preferences.defaultReportFormat,
    });
  }, [preferences]);

  const totalScans = scans.length;
  const highOrCritical = scans.filter(
    (s) => s.riskLevel === 'Known Malicious' || s.riskLevel === 'High Risk'
  ).length;
  const unknownCount = scans.filter(
    (s) => s.riskLevel === 'Unknown/Unverified' || s.riskLevel === 'No Known Threat Found'
  ).length;

  const channelCounts = {
    url: scans.filter((s) => s.scanType === 'url').length,
    email: scans.filter((s) => s.scanType === 'email').length,
    sms: scans.filter((s) => s.scanType === 'sms').length,
    qr: scans.filter((s) => s.scanType === 'qr').length,
  };

  const handleSavePrefs = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingPrefs(true);
    setPrefMessage(null);
    try {
      await onSavePreferences(draftPrefs);
      setPrefMessage(
        isSignedIn && isVerified
          ? 'Preferences synced to Cloud Firestore.'
          : 'Preferences updated for this browser session.'
      );
    } catch (err) {
      setPrefMessage(err instanceof Error ? err.message : 'Unable to save preferences.');
    } finally {
      setSavingPrefs(false);
    }
  };

  return (
    <div className="space-y-8">
      <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
        <div className="space-y-2 max-w-2xl">
          <div className="text-xs text-slate-400">
            Demo Heuristic &amp; Gemini Analysis Workspace · Safe Static Inspection
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-slate-50 text-balance">
            Inspect suspicious links, messages, and QR payloads without visiting untrusted targets
          </h1>
          <p className="text-sm text-slate-300 leading-relaxed">
            PhishShield AI analyzes submitted indicators statically and explains social-engineering
            tactics via the server-side Gemini runtime. Unknown URLs are never visited and never
            declared safe.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => onNavigate('url-scanner')}
            className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 transition-colors whitespace-nowrap cursor-pointer"
          >
            <Link2 className="h-4 w-4" />
            <span>Open URL Scanner</span>
          </button>
          {!isSignedIn && (
            <button
              type="button"
              onClick={onOpenAuth}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-[#0A0F1A] px-4 py-2.5 text-sm font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap cursor-pointer"
            >
              <span>Sign In to Sync</span>
            </button>
          )}
        </div>
      </section>

      <section aria-label="Security Metrics" className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-800 bg-[#111827] p-5 space-y-1">
          <div className="text-xs text-slate-400">Total Scans Logged</div>
          <div className="text-2xl font-semibold font-mono tabular-nums text-slate-50">
            {loadingData ? '—' : totalScans}
          </div>
          <div className="text-xs text-slate-500">
            URL {channelCounts.url} · Email {channelCounts.email} · SMS {channelCounts.sms} · QR{' '}
            {channelCounts.qr}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#111827] p-5 space-y-1">
          <div className="text-xs text-slate-400">Known Malicious / High Risk</div>
          <div className="text-2xl font-semibold font-mono tabular-nums text-red-400">
            {loadingData ? '—' : highOrCritical}
          </div>
          <div className="text-xs text-slate-500">Active threat indicators flagged</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#111827] p-5 space-y-1">
          <div className="text-xs text-slate-400">Unknown / No Threat Found</div>
          <div className="text-2xl font-semibold font-mono tabular-nums text-sky-400">
            {loadingData ? '—' : unknownCount}
          </div>
          <div className="text-xs text-slate-500">Never auto-classified as safe</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#111827] p-5 space-y-1">
          <div className="text-xs text-slate-400">Saved Reports</div>
          <div className="text-2xl font-semibold font-mono tabular-nums text-slate-50">
            {loadingData ? '—' : reports.length}
          </div>
          <div className="text-xs text-slate-500">PDF, JSON &amp; Markdown exports</div>
        </div>
      </section>

      <section aria-label="Detection Modules" className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {[
          {
            tab: 'url-scanner' as NavTab,
            title: 'URL Scanner',
            desc: 'Static lexical, punycode, IP host, and credential-lure inspection.',
            Icon: Link2,
          },
          {
            tab: 'message-scanner' as NavTab,
            title: 'Email / SMS Scanner',
            desc: 'Detect urgency coercion, OTP theft, and embedded phishing links.',
            Icon: Mail,
          },
          {
            tab: 'qr-scanner' as NavTab,
            title: 'QR Scanner',
            desc: 'Decode QR images locally and inspect payment or quishing URLs.',
            Icon: QrCode,
          },
          {
            tab: 'assistant' as NavTab,
            title: 'AI Assistant',
            desc: 'Ask Gemini security analyst questions with attached scan context.',
            Icon: Bot,
          },
        ].map(({ tab, title, desc, Icon }) => (
          <button
            key={tab}
            type="button"
            onClick={() => onNavigate(tab)}
            className="text-left rounded-xl border border-slate-800 bg-[#111827] p-5 hover:border-slate-700 hover:bg-[#151F32] transition-colors flex flex-col justify-between gap-4 cursor-pointer"
          >
            <div className="space-y-2">
              <div className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-800 bg-[#0A0F1A] text-blue-400">
                <Icon className="h-4 w-4" />
              </div>
              <h2 className="text-base font-semibold text-slate-100">{title}</h2>
              <p className="text-xs text-slate-400 leading-relaxed">{desc}</p>
            </div>
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400">
              <span>Launch module</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </span>
          </button>
        ))}
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <section className="xl:col-span-2 rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-slate-100">Recent Scan Activity</h2>
              <p className="text-xs text-slate-400">
                {isSignedIn
                  ? 'Live updates from your private Cloud Firestore scan log.'
                  : 'Showing demo session scans. Sign in to persist scans across sessions.'}
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('history')}
              className="text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap cursor-pointer"
            >
              View all history
            </button>
          </div>

          {loadingData ? (
            <div className="space-y-2">
              {[1, 2, 3].map((row) => (
                <div
                  key={row}
                  className="h-11 rounded-lg bg-slate-800/50 animate-pulse"
                />
              ))}
            </div>
          ) : scans.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-800 bg-[#0A0F1A] p-8 text-center space-y-3">
              <FileText className="h-6 w-6 text-slate-500 mx-auto" />
              <div className="space-y-1">
                <p className="text-sm font-medium text-slate-200">No scans recorded yet</p>
                <p className="text-xs text-slate-400">
                  Run a URL, Email/SMS, or QR scan to see structured findings appear here.
                </p>
              </div>
              <button
                type="button"
                onClick={() => onNavigate('url-scanner')}
                className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 transition-colors cursor-pointer"
              >
                Run First Demo Scan
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-xs text-slate-400">
                    <th className="py-2.5 pr-4 font-medium">Channel</th>
                    <th className="py-2.5 pr-4 font-medium">Target</th>
                    <th className="py-2.5 pr-4 font-medium">Classification</th>
                    <th className="py-2.5 pr-4 font-medium text-right">Score</th>
                    <th className="py-2.5 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 text-sm">
                  {scans.slice(0, 6).map((scan) => {
                    const { textClass, Icon } = getRiskAppearance(scan.riskLevel);
                    return (
                      <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2.5 pr-4 font-mono text-xs uppercase text-slate-300">
                          {scan.scanType}
                        </td>
                        <td className="py-2.5 pr-4 font-mono text-xs text-slate-200 max-w-[260px] truncate">
                          {scan.targetPreview}
                        </td>
                        <td className="py-2.5 pr-4">
                          <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${textClass}`}>
                            <Icon className="h-3.5 w-3.5 shrink-0" />
                            <span>{scan.riskLevel}</span>
                          </span>
                        </td>
                        <td className="py-2.5 pr-4 text-right font-mono tabular-nums text-xs text-slate-200">
                          {scan.riskScore}/100
                        </td>
                        <td className="py-2.5 text-right">
                          <button
                            type="button"
                            onClick={() => onSelectScanForAssistant(scan)}
                            className="text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap cursor-pointer"
                          >
                            Explain
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-4">
          <div className="flex items-center gap-2">
            <SlidersHorizontal className="h-4 w-4 text-blue-400" />
            <h2 className="text-lg font-semibold text-slate-100">Scanner Preferences</h2>
          </div>
          <p className="text-xs text-slate-400">
            Stored per user in Cloud Firestore (`/userPreferences`).
          </p>

          <form onSubmit={handleSavePrefs} className="space-y-4">
            <label className="block space-y-1.5">
              <span className="text-xs font-medium text-slate-300">Heuristic Sensitivity</span>
              <select
                value={draftPrefs.sensitivity}
                onChange={(e) =>
                  setDraftPrefs((p) => ({
                    ...p,
                    sensitivity: e.target.value as SensitivityLevel,
                  }))
                }
                className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] px-3 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none"
              >
                <option value="standard">Standard (Balanced)</option>
                <option value="strict">Strict (+15% heuristic weight)</option>
                <option value="paranoid">Paranoid (+30% heuristic weight)</option>
              </select>
            </label>

            <label className="block space-y-1.5">
              <span className="text-xs font-medium text-slate-300">Default Export Format</span>
              <select
                value={draftPrefs.defaultReportFormat}
                onChange={(e) =>
                  setDraftPrefs((p) => ({
                    ...p,
                    defaultReportFormat: e.target.value as ReportFormat,
                  }))
                }
                className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] px-3 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none"
              >
                <option value="pdf">PDF Document (.pdf)</option>
                <option value="markdown">Markdown (.md)</option>
                <option value="json">Structured JSON (.json)</option>
              </select>
            </label>

            <label className="flex items-center justify-between gap-3 rounded-lg border border-slate-800 bg-[#0A0F1A] px-3.5 py-2.5 cursor-pointer">
              <span className="text-xs text-slate-200">Auto-explain scans with Gemini AI</span>
              <input
                type="checkbox"
                checked={draftPrefs.autoExplainWithAi}
                onChange={(e) =>
                  setDraftPrefs((p) => ({ ...p, autoExplainWithAi: e.target.checked }))
                }
                className="h-4 w-4 accent-blue-600"
              />
            </label>

            {prefMessage && (
              <p className="text-xs text-sky-400 leading-relaxed">{prefMessage}</p>
            )}

            <button
              type="submit"
              disabled={savingPrefs}
              className="w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60 transition-colors cursor-pointer"
            >
              {savingPrefs ? 'Saving Preferences...' : 'Save Preferences'}
            </button>
          </form>
        </section>
      </div>
    </div>
  );
};
