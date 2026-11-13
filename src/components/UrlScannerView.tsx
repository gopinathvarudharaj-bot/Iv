import React, { useState } from 'react';
import { Link2, Search, ShieldOff } from 'lucide-react';
import { analyzeUrlApi, retryAiExplanationApi } from '../lib/apiClient';
import { redactSecretsInText } from '../lib/scanPayload';
import type { AnalysisResponse, ScanRecord, UserPreferences } from '../types/phishshield';
import { RiskResultPanel } from './RiskResultPanel';

interface UrlScannerViewProps {
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

const SAMPLE_URLS = [
  {
    label: 'Lookalike Bank Login',
    url: 'http://secure-login.paypa1-verify.xyz/auth/session?redirect=https://example.org',
  },
  {
    label: 'IP Host Credential Lure',
    url: 'http://198.51.100.42:8443/microsoft-sso/unlock-account',
  },
  {
    label: 'Unfamiliar Domain (Unknown)',
    url: 'https://portal.northbridge-logistics.example/invoices/2026',
  },
];

export const UrlScannerView: React.FC<UrlScannerViewProps> = ({
  preferences,
  onPersistScan,
  onAskAssistant,
}) => {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [scannedTarget, setScannedTarget] = useState('');
  const [savedScanId, setSavedScanId] = useState<string | null>(null);
  const [saveWarning, setSaveWarning] = useState<string | null>(null);
  const [retryingAi, setRetryingAi] = useState(false);
  const [useAi, setUseAi] = useState(preferences.autoExplainWithAi);

  React.useEffect(() => {
    setUseAi(preferences.autoExplainWithAi);
  }, [preferences.autoExplainWithAi]);

  const runScan = async (targetUrl: string) => {
    const clean = targetUrl.trim();
    if (!clean) {
      setError('Enter a URL or domain string to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    setSavedScanId(null);
    setSaveWarning(null);

    try {
      const analysis = await analyzeUrlApi({
        url: clean,
        sensitivity: preferences.sensitivity,
        useAi,
      });
      setResult(analysis);
      setScannedTarget(clean);

      const breakdownSummary = (analysis.scoreBreakdown ?? [])
        .map((b) => `+${b.weight} ${b.label}: ${b.evidence}`)
        .join(' | ');

      const safeTarget = redactSecretsInText(clean);
      const persisted = await onPersistScan({
        scanType: 'url',
        targetPreview: safeTarget.slice(0, 500),
        rawInput: safeTarget,
        riskLevel: analysis.riskLevel,
        riskScore: analysis.riskScore,
        heuristicScore: analysis.heuristicScore,
        submittedUrl: analysis.reputation?.submittedUrl || analysis.normalizedUrl || clean,
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
      setError(err instanceof Error ? err.message : 'Failed to analyze URL.');
    } finally {
      setLoading(false);
    }
  };

  const handleRetryAi = async () => {
    if (!result || !scannedTarget || retryingAi) return;
    setRetryingAi(true);
    try {
      const retried = await retryAiExplanationApi({
        mode: 'url',
        rawInput: scannedTarget,
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
    void runScan(urlInput);
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 pb-4 border-b border-slate-800">
          <div className="space-y-1">
            <div className="text-xs text-slate-400">
              Demo Scanner · Static Inspection Only · Sensitivity: {preferences.sensitivity}
            </div>
            <h1 className="text-2xl font-semibold text-slate-50">URL Phishing Scanner</h1>
          </div>
          <div className="inline-flex items-center gap-2 text-xs text-slate-300">
            <ShieldOff className="h-4 w-4 text-sky-400 shrink-0" />
            <span>Submitted URLs are never visited or crawled</span>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <label className="block space-y-1.5">
            <span className="text-sm font-medium text-slate-200">
              Suspicious URL or Domain String
            </span>
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Link2 className="pointer-events-none absolute left-3.5 top-3.5 h-4 w-4 text-slate-500" />
                <input
                  type="url"
                  inputMode="url"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="https://example-login-check.tld/verify"
                  className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] pl-10 pr-4 py-2.5 min-h-[44px] text-base sm:text-sm font-mono text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 min-h-[44px] text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Search className="h-4 w-4" />
                <span>{loading ? 'Analyzing...' : 'Inspect URL'}</span>
              </button>
            </div>
          </label>

          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-slate-400 mr-1">Demo Samples:</span>
              {SAMPLE_URLS.map((sample) => (
                <button
                  key={sample.label}
                  type="button"
                  onClick={() => {
                    setUrlInput(sample.url);
                    void runScan(sample.url);
                  }}
                  className="rounded-md border border-slate-800 bg-[#0A0F1A] px-3 py-2 text-xs text-slate-300 hover:border-slate-700 hover:text-white transition-colors cursor-pointer"
                >
                  {sample.label}
                </button>
              ))}
            </div>

            <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none shrink-0">
              <input
                type="checkbox"
                checked={useAi}
                onChange={(e) => setUseAi(e.target.checked)}
                className="h-4 w-4 accent-blue-600"
              />
              <span>Include Gemini AI explanation</span>
            </label>
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
          <div className="h-4 w-full rounded bg-slate-800/70 animate-pulse" />
          <div className="h-28 w-full rounded bg-slate-800/50 animate-pulse" />
        </div>
      )}

      {!loading && result && (
        <RiskResultPanel
          result={result}
          channel="url"
          targetPreview={scannedTarget}
          savedScanId={savedScanId}
          saveWarning={saveWarning}
          retryingAi={retryingAi}
          onRetryAi={() => void handleRetryAi()}
          onAskAssistant={() =>
            onAskAssistant({
              scanType: 'url',
              targetPreview: scannedTarget,
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
