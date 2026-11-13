import React, { useState } from 'react';
import { Mail, MessageSquare, Search } from 'lucide-react';
import { analyzeMessageApi, retryAiExplanationApi } from '../lib/apiClient';
import { buildMinimizedMessageInputForStorage } from '../lib/scanPayload';
import type { AnalysisResponse, ScanRecord, UserPreferences } from '../types/phishshield';
import { RiskResultPanel } from './RiskResultPanel';

interface MessageScannerViewProps {
  preferences: UserPreferences;
  onPersistScan: (
    scan: Omit<ScanRecord, 'id' | 'userId' | 'createdAtMs' | 'updatedAtMs'>
  ) => Promise<{ savedId?: string; warning?: string }>;
  onAskAssistant: (scanPreview: {
    scanType: string;
    targetPreview: string;
    riskLevel: string;
    riskScore: number;
    indicators: string[];
  }) => void;
}

const SAMPLE_MESSAGES = [
  {
    label: 'Email: Payroll Wire Phish',
    channel: 'email' as const,
    sender: 'hr-payroll-update@gmail.com',
    subject: 'URGENT: Final Notice — Action Required to Prevent Account Lock',
    content:
      'Your employee portal password expires today. Please verify now within 24 hours and confirm your MFA one-time passcode at http://payroll-secure-verify.xyz/sso/login to avoid payroll suspension.',
  },
  {
    label: 'SMS: Package Redelivery Smishing',
    channel: 'sms' as const,
    sender: '+1 (555) 019-2834',
    subject: '',
    content:
      'USPS Notice: Your parcel cannot be delivered due to an unpaid customs fee ($3.25). Pay immediately at https://bit.ly/usps-redelivery-fee-check to reschedule.',
  },
];

export const MessageScannerView: React.FC<MessageScannerViewProps> = ({
  preferences,
  onPersistScan,
  onAskAssistant,
}) => {
  const [channel, setChannel] = useState<'email' | 'sms'>('email');
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [targetPreview, setTargetPreview] = useState('');
  const [savedScanId, setSavedScanId] = useState<string | null>(null);
  const [saveWarning, setSaveWarning] = useState<string | null>(null);
  const [retryingAi, setRetryingAi] = useState(false);
  const [useAi, setUseAi] = useState(preferences.autoExplainWithAi);
  const [lastPayload, setLastPayload] = useState<{
    ch: 'email' | 'sms';
    snd: string;
    subj: string;
    body: string;
  } | null>(null);

  React.useEffect(() => {
    setUseAi(preferences.autoExplainWithAi);
  }, [preferences.autoExplainWithAi]);

  const runAnalysis = async (params: {
    ch: 'email' | 'sms';
    snd: string;
    subj: string;
    body: string;
  }) => {
    if (!params.body.trim()) {
      setError('Paste an email or SMS message body to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    setSavedScanId(null);
    setSaveWarning(null);
    setLastPayload(params);

    try {
      const analysis = await analyzeMessageApi({
        channel: params.ch,
        sender: params.snd,
        subject: params.subj,
        content: params.body,
        sensitivity: preferences.sensitivity,
        useAi,
      });

      const minimized = buildMinimizedMessageInputForStorage({
        channel: params.ch,
        bodyLength: params.body.length,
        extractedUrls: analysis.extractedUrls || [],
      });

      setResult(analysis);
      setTargetPreview(minimized.targetPreview);

      const breakdownSummary = (analysis.scoreBreakdown ?? [])
        .map((b) => `+${b.weight} ${b.label}: ${b.evidence}`)
        .join(' | ');

      const persisted = await onPersistScan({
        scanType: params.ch,
        targetPreview: minimized.targetPreview,
        rawInput: minimized.rawInput,
        riskLevel: analysis.riskLevel,
        riskScore: analysis.riskScore,
        heuristicScore: analysis.heuristicScore,
        submittedUrl:
          analysis.reputation?.submittedUrl || minimized.submittedUrl || analysis.extractedUrls?.[0],
        reputationStatus: analysis.reputation?.status,
        reputationResult: analysis.reputation?.resultLabel,
        reputationProvider: analysis.reputation?.provider,
        reputationCheckedAt: analysis.reputation?.checkedAt,
        threatCategories: analysis.reputation?.threatCategories,
        reputationSummary: analysis.reputation?.summary,
        scoreBreakdownSummary: breakdownSummary,
        mlProbability: analysis.mlPrediction?.phishingProbability,
        mlSummary: analysis.mlPrediction?.summary,
        verdictSummary: analysis.verdictSummary,
        aiExplanation: analysis.aiExplanation,
        indicators: analysis.indicators,
        recommendations: analysis.recommendations,
        isDemoMode: true,
        archived: false,
        analystNote: '',
      });
      if (persisted.savedId) setSavedScanId(persisted.savedId);
      if (persisted.warning) setSaveWarning(persisted.warning);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Message analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleRetryAi = async () => {
    if (!result || !lastPayload || retryingAi) return;
    setRetryingAi(true);
    try {
      const context = `Channel: ${lastPayload.ch.toUpperCase()} | Sender: ${lastPayload.snd.trim() || '(not provided)'} | Subject: ${lastPayload.subj.trim() || '(not provided)'}`;
      const retried = await retryAiExplanationApi({
        mode: lastPayload.ch,
        rawInput: lastPayload.body.trim(),
        heuristics: {
          riskScore: result.riskScore,
          heuristicScore: result.heuristicScore,
          riskLevel: result.riskLevel,
          verdictSummary: result.verdictSummary,
          indicators: result.indicators,
          scoreBreakdown: result.scoreBreakdown,
          reputation: result.reputation,
          mlPrediction: result.mlPrediction,
        },
        extraContext: context,
      });
      setResult((prev) =>
        prev
          ? {
              ...prev,
              aiExplanation: retried.aiExplanation,
              aiStatus: retried.aiStatus,
              aiError: retried.aiError,
              aiErrorCode: retried.aiErrorCode,
              modelUsed: retried.modelUsed,
              requestId: retried.requestId,
              latencyMs: retried.latencyMs,
            }
          : prev
      );
    } catch (err) {
      setResult((prev) =>
        prev
          ? {
              ...prev,
              aiStatus: 'unavailable',
              aiError:
                err instanceof Error
                  ? err.message
                  : 'AI explanation temporarily unavailable.',
            }
          : prev
      );
    } finally {
      setRetryingAi(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void runAnalysis({ ch: channel, snd: sender, subj: subject, body: content });
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 pb-4 border-b border-slate-800">
          <div className="space-y-1">
            <div className="text-xs text-slate-400">
              Social Engineering &amp; Embedded Link Analysis · Sensitivity: {preferences.sensitivity} · Message bodies &amp; sender PII are never saved to Firestore
            </div>
            <h1 className="text-2xl font-semibold text-slate-50">Email &amp; SMS Scam Scanner</h1>
          </div>

          <div className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-[#0A0F1A] p-1 shrink-0">
            <button
              type="button"
              onClick={() => setChannel('email')}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap cursor-pointer ${
                channel === 'email'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Mail className="h-3.5 w-3.5" />
              <span>Email</span>
            </button>
            <button
              type="button"
              onClick={() => setChannel('sms')}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap cursor-pointer ${
                channel === 'sms'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <MessageSquare className="h-3.5 w-3.5" />
              <span>SMS / Text</span>
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <label className="block space-y-1.5">
              <span className="text-xs font-medium text-slate-300">
                {channel === 'email' ? 'Sender Address (Optional)' : 'Sender Number / ID (Optional)'}
              </span>
              <input
                type="text"
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                placeholder={channel === 'email' ? 'security@example-notice.com' : '+1 (555) 010-9911'}
                className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] px-3.5 py-2.5 text-base sm:text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
              />
            </label>

            {channel === 'email' && (
              <label className="block space-y-1.5">
                <span className="text-xs font-medium text-slate-300">Subject Line (Optional)</span>
                <input
                  type="text"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="Immediate verification required"
                  className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] px-3.5 py-2.5 text-base sm:text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                />
              </label>
            )}
          </div>

          <label className="block space-y-1.5">
            <span className="text-xs font-medium text-slate-300">Message Body</span>
            <textarea
              rows={5}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste the suspicious email or text message here..."
              className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] p-3.5 text-base sm:text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
            />
          </label>

          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-slate-400 mr-1">Demo Samples:</span>
              {SAMPLE_MESSAGES.map((sample) => (
                <button
                  key={sample.label}
                  type="button"
                  onClick={() => {
                    setChannel(sample.channel);
                    setSender(sample.sender);
                    setSubject(sample.subject);
                    setContent(sample.content);
                    void runAnalysis({
                      ch: sample.channel,
                      snd: sample.sender,
                      subj: sample.subject,
                      body: sample.content,
                    });
                  }}
                  className="rounded-md border border-slate-800 bg-[#0A0F1A] px-3 py-2 text-xs text-slate-300 hover:border-slate-700 hover:text-white transition-colors cursor-pointer"
                >
                  {sample.label}
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center justify-between sm:justify-end gap-3">
              <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={useAi}
                  onChange={(e) => setUseAi(e.target.checked)}
                  className="h-4 w-4 accent-blue-600"
                />
                <span>Include Gemini AI</span>
              </label>
              <button
                type="submit"
                disabled={loading}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 min-h-[44px] text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Search className="h-4 w-4" />
                <span>{loading ? 'Analyzing...' : `Analyze ${channel.toUpperCase()}`}</span>
              </button>
            </div>
          </div>
        </form>

        {error && (
          <div className="rounded-lg border border-red-900/60 bg-red-950/30 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}
      </section>

      {loading && (
        <div className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-4">
          <div className="h-6 w-48 rounded bg-slate-800 animate-pulse" />
          <div className="h-28 w-full rounded bg-slate-800/50 animate-pulse" />
        </div>
      )}

      {!loading && result && (
        <RiskResultPanel
          result={result}
          channel={channel}
          targetPreview={targetPreview}
          savedScanId={savedScanId}
          saveWarning={saveWarning}
          retryingAi={retryingAi}
          onRetryAi={() => void handleRetryAi()}
          onAskAssistant={() =>
            onAskAssistant({
              scanType: channel,
              targetPreview,
              riskLevel: result.riskLevel,
              riskScore: result.riskScore,
              indicators: result.indicators,
            })
          }
        />
      )}
    </div>
  );
};
