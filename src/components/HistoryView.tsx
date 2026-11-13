import React, { useMemo, useState } from 'react';
import { Archive, Bot, RefreshCw, Search, Trash2, X } from 'lucide-react';
import type { RiskLevel, ScanChannel, ScanRecord } from '../types/phishshield';
import { getRiskAppearance } from './RiskResultPanel';

interface HistoryViewProps {
  scans: ScanRecord[];
  isSignedIn: boolean;
  loadingData: boolean;
  rescoring: boolean;
  rescoreNotice: string | null;
  onRescoreHistory: () => Promise<void>;
  onUpdateScan: (scanId: string, updates: { archived?: boolean; analystNote?: string }) => Promise<void>;
  onDeleteScan: (scanId: string) => Promise<void>;
  onAskAssistant: (scan: ScanRecord) => void;
  onOpenAuth: () => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({
  scans,
  isSignedIn,
  loadingData,
  rescoring,
  rescoreNotice,
  onRescoreHistory,
  onUpdateScan,
  onDeleteScan,
  onAskAssistant,
  onOpenAuth,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [channelFilter, setChannelFilter] = useState<'all' | ScanChannel>('all');
  const [riskFilter, setRiskFilter] = useState<'all' | RiskLevel>('all');
  const [showArchived, setShowArchived] = useState(false);
  const [selectedScan, setSelectedScan] = useState<ScanRecord | null>(null);
  const [noteDraft, setNoteDraft] = useState('');
  const [savingNote, setSavingNote] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const filteredScans = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    return scans.filter((scan) => {
      if (!showArchived && scan.archived) return false;
      if (channelFilter !== 'all' && scan.scanType !== channelFilter) return false;
      if (riskFilter !== 'all' && scan.riskLevel !== riskFilter) return false;
      if (!q) return true;
      return (
        scan.targetPreview.toLowerCase().includes(q) ||
        scan.verdictSummary.toLowerCase().includes(q) ||
        scan.analystNote.toLowerCase().includes(q)
      );
    });
  }, [scans, searchTerm, channelFilter, riskFilter, showArchived]);

  const openDetail = (scan: ScanRecord) => {
    setSelectedScan(scan);
    setNoteDraft(scan.analystNote || '');
    setActionError(null);
  };

  const handleSaveNote = async () => {
    if (!selectedScan) return;
    setSavingNote(true);
    setActionError(null);
    try {
      await onUpdateScan(selectedScan.id, { analystNote: noteDraft });
      setSelectedScan({ ...selectedScan, analystNote: noteDraft });
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to update note.');
    } finally {
      setSavingNote(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 pb-4 border-b border-slate-800">
          <div className="space-y-1">
            <div className="text-xs text-slate-400">
              {isSignedIn
                ? 'Synced with Cloud Firestore (/scans)'
                : 'Local Demo Session History · Sign in to save across sessions'}
            </div>
            <h1 className="text-2xl font-semibold text-slate-50">Scan History</h1>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {scans.length > 0 && (
              <button
                type="button"
                onClick={() => void onRescoreHistory()}
                disabled={rescoring}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-[#0A0F1A] px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-60 transition-colors whitespace-nowrap cursor-pointer"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${rescoring ? 'animate-spin' : ''}`} />
                <span>{rescoring ? 'Re-scoring...' : 'Re-score History'}</span>
              </button>
            )}
            {!isSignedIn && (
              <button
                type="button"
                onClick={onOpenAuth}
                className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 transition-colors whitespace-nowrap cursor-pointer"
              >
                Sign In to Persist Scans
              </button>
            )}
          </div>
        </div>

        {rescoreNotice && (
          <div className="rounded-lg border border-sky-900/60 bg-sky-950/25 px-4 py-2.5 text-xs text-sky-200">
            {rescoreNotice}
          </div>
        )}

        <div className="flex flex-col lg:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search URL, subject, verdict, or analyst note..."
              className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] pl-9 pr-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={channelFilter}
              onChange={(e) => setChannelFilter(e.target.value as 'all' | ScanChannel)}
              className="rounded-lg border border-slate-800 bg-[#0A0F1A] px-3 py-2 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Channels</option>
              <option value="url">URL</option>
              <option value="email">Email</option>
              <option value="sms">SMS</option>
              <option value="qr">QR</option>
            </select>

            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value as 'all' | RiskLevel)}
              className="rounded-lg border border-slate-800 bg-[#0A0F1A] px-3 py-2 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Classifications</option>
              <option value="Known Malicious">Known Malicious</option>
              <option value="High Risk">High Risk</option>
              <option value="Suspicious">Suspicious</option>
              <option value="No Known Threat Found">No Known Threat Found</option>
              <option value="Unknown/Unverified">Unknown/Unverified</option>
            </select>

            <button
              type="button"
              onClick={() => setShowArchived((v) => !v)}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-medium transition-colors whitespace-nowrap cursor-pointer ${
                showArchived
                  ? 'border-blue-600 bg-blue-950/30 text-blue-300'
                  : 'border-slate-800 bg-[#0A0F1A] text-slate-300 hover:border-slate-700'
              }`}
            >
              <Archive className="h-3.5 w-3.5" />
              <span>{showArchived ? 'Showing Archived' : 'Include Archived'}</span>
            </button>
          </div>
        </div>

        {actionError && (
          <div className="rounded-lg border border-red-900/60 bg-red-950/30 px-4 py-2.5 text-xs text-red-300">
            {actionError}
          </div>
        )}

        {loadingData ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-11 rounded-lg bg-slate-800/50 animate-pulse" />
            ))}
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-800 bg-[#0A0F1A] p-10 text-center space-y-2">
            <p className="text-sm font-medium text-slate-200">No matching scans found</p>
            <p className="text-xs text-slate-400">
              Adjust your search filters or run a new URL, Email/SMS, or QR scan.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-400">
                  <th className="py-2.5 pr-4 font-medium">Timestamp</th>
                  <th className="py-2.5 pr-4 font-medium">Channel</th>
                  <th className="py-2.5 pr-4 font-medium">Target</th>
                  <th className="py-2.5 pr-4 font-medium">Classification</th>
                  <th className="py-2.5 pr-4 font-medium text-right">Score</th>
                  <th className="py-2.5 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 text-sm">
                {filteredScans.map((scan) => {
                  const { textClass, Icon } = getRiskAppearance(scan.riskLevel);
                  return (
                    <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 pr-4 font-mono tabular-nums text-xs text-slate-400 whitespace-nowrap">
                        {new Date(scan.createdAtMs).toLocaleString([], {
                          month: 'short',
                          day: '2-digit',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-xs uppercase text-slate-300">
                        {scan.scanType}
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-xs text-slate-200 max-w-[260px] truncate">
                        {scan.targetPreview}
                      </td>
                      <td className="py-2.5 pr-4 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${textClass}`}>
                          <Icon className="h-3.5 w-3.5 shrink-0" />
                          <span>{scan.riskLevel}</span>
                        </span>
                      </td>
                      <td className="py-2.5 pr-4 text-right font-mono tabular-nums text-xs text-slate-200">
                        {scan.riskScore}/100
                      </td>
                      <td className="py-2.5 text-right whitespace-nowrap space-x-3">
                        <button
                          type="button"
                          onClick={() => openDetail(scan)}
                          className="text-xs font-medium text-blue-400 hover:text-blue-300 cursor-pointer"
                        >
                          Inspect
                        </button>
                        <button
                          type="button"
                          onClick={() => onAskAssistant(scan)}
                          className="text-xs font-medium text-slate-300 hover:text-white cursor-pointer"
                        >
                          AI Explain
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            void onDeleteScan(scan.id).catch((err) =>
                              setActionError(err instanceof Error ? err.message : 'Delete failed.')
                            );
                          }}
                          aria-label="Delete scan record"
                          className="inline-flex items-center text-slate-500 hover:text-red-400 cursor-pointer align-middle"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
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

      {selectedScan && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-2xl max-h-[88vh] overflow-y-auto rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-5">
            <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-800">
              <div className="space-y-1 min-w-0">
                <div className="text-xs text-slate-400">
                  {selectedScan.scanType.toUpperCase()} Scan · Score {selectedScan.riskScore}/100 ·{' '}
                  {selectedScan.riskLevel}
                </div>
                <h2 className="text-lg font-semibold text-slate-100 break-all font-mono">
                  {selectedScan.targetPreview}
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setSelectedScan(null)}
                aria-label="Close scan details"
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100 cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-2">
              <div className="text-xs font-medium text-slate-300">Verdict &amp; AI Explanation</div>
              <div className="rounded-lg border border-slate-800 bg-[#0A0F1A] p-4 text-sm text-slate-200 leading-relaxed whitespace-pre-line">
                {selectedScan.aiExplanation || selectedScan.verdictSummary}
              </div>
            </div>

            {(selectedScan.reputationResult ||
              selectedScan.reputationSummary ||
              selectedScan.mlSummary ||
              selectedScan.scoreBreakdownSummary ||
              selectedScan.indicators.length > 0) && (
              <div className="space-y-2">
                <div className="text-xs font-medium text-slate-300">
                  Saved Heuristic Breakdown, Reputation &amp; ML Evidence
                </div>
                <div className="rounded-lg border border-slate-800 bg-[#0A0F1A] p-3.5 space-y-2 text-xs text-slate-300">
                  {selectedScan.submittedUrl && (
                    <p className="text-slate-200 break-all font-mono text-[11px]">
                      <span className="font-sans font-medium text-slate-400">Submitted URL: </span>
                      {selectedScan.submittedUrl}
                    </p>
                  )}
                  {(selectedScan.reputationResult || selectedScan.reputationProvider) && (
                    <p className="text-slate-200">
                      <span className="font-medium text-slate-400">Reputation Result: </span>
                      <span className="font-semibold">
                        {selectedScan.reputationResult || selectedScan.reputationStatus}
                      </span>
                      {selectedScan.reputationProvider
                        ? ` via ${selectedScan.reputationProvider}`
                        : ''}
                      {selectedScan.reputationCheckedAt
                        ? ` (checked ${new Date(selectedScan.reputationCheckedAt).toLocaleString()})`
                        : ''}
                    </p>
                  )}
                  {selectedScan.threatCategories && selectedScan.threatCategories.length > 0 && (
                    <p className="text-red-300 font-mono text-[11px]">
                      <span className="font-sans font-medium text-slate-400">
                        Threat Categories:{' '}
                      </span>
                      {selectedScan.threatCategories.join(', ')}
                    </p>
                  )}
                  {selectedScan.reputationSummary && (
                    <p className="text-slate-300">
                      <span className="font-medium text-slate-400">Reputation Detail: </span>
                      {selectedScan.reputationSummary}
                    </p>
                  )}
                  {(typeof selectedScan.mlProbability === 'number' || selectedScan.mlSummary) && (
                    <p className="text-sky-200">
                      <span className="font-medium text-slate-400">ML Prediction: </span>
                      {typeof selectedScan.mlProbability === 'number'
                        ? `${selectedScan.mlProbability}% phishing probability — `
                        : ''}
                      {selectedScan.mlSummary}
                    </p>
                  )}
                  {selectedScan.scoreBreakdownSummary && (
                    <p className="font-mono text-[11px] text-amber-300/90 break-words">
                      {selectedScan.scoreBreakdownSummary}
                    </p>
                  )}
                  {selectedScan.indicators.length > 0 && (
                    <ul className="list-disc pl-4 space-y-1 text-slate-300">
                      {selectedScan.indicators.map((ind, i) => (
                        <li key={i}>{ind}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )}

            <div className="space-y-2">
              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-300">Analyst Note</span>
                <textarea
                  rows={3}
                  value={noteDraft}
                  onChange={(e) => setNoteDraft(e.target.value)}
                  placeholder="Add investigation notes or remediation status..."
                  className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] p-3 text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                />
              </label>

              <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      void onUpdateScan(selectedScan.id, {
                        archived: !selectedScan.archived,
                      }).then(() =>
                        setSelectedScan({
                          ...selectedScan,
                          archived: !selectedScan.archived,
                        })
                      );
                    }}
                    className="rounded-lg border border-slate-700 bg-[#0A0F1A] px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 cursor-pointer"
                  >
                    {selectedScan.archived ? 'Unarchive Scan' : 'Archive Scan'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      onAskAssistant(selectedScan);
                      setSelectedScan(null);
                    }}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-[#0A0F1A] px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 cursor-pointer"
                  >
                    <Bot className="h-3.5 w-3.5" />
                    <span>Discuss with AI</span>
                  </button>
                </div>

                <button
                  type="button"
                  onClick={() => void handleSaveNote()}
                  disabled={savingNote}
                  className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-60 cursor-pointer"
                >
                  {savingNote ? 'Saving...' : 'Save Note'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
