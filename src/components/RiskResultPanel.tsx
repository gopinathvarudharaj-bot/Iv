import React from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  Bot,
  CheckCircle2,
  HelpCircle,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import type { AnalysisResponse, RiskLevel, ScanChannel } from '../types/phishshield';

interface RiskResultPanelProps {
  result: AnalysisResponse;
  channel: ScanChannel;
  targetPreview: string;
  savedScanId?: string | null;
  saveWarning?: string | null;
  retryingAi?: boolean;
  onRetryAi?: () => void;
  onAskAssistant: () => void;
}

export function getRiskAppearance(level: RiskLevel | string): {
  textClass: string;
  surfaceClass: string;
  barClass: string;
  Icon: React.ComponentType<{ className?: string }>;
} {
  switch (level) {
    case 'Known Malicious':
    case 'Critical Risk':
      return {
        textClass: 'text-red-400',
        surfaceClass: 'bg-red-950/35 border-red-900/60',
        barClass: 'bg-red-500',
        Icon: AlertOctagon,
      };
    case 'High Risk':
      return {
        textClass: 'text-orange-400',
        surfaceClass: 'bg-orange-950/30 border-orange-900/60',
        barClass: 'bg-orange-500',
        Icon: ShieldAlert,
      };
    case 'Suspicious':
      return {
        textClass: 'text-amber-400',
        surfaceClass: 'bg-amber-950/25 border-amber-900/50',
        barClass: 'bg-amber-500',
        Icon: AlertTriangle,
      };
    case 'No Known Threat Found':
      return {
        textClass: 'text-emerald-400',
        surfaceClass: 'bg-emerald-950/25 border-emerald-900/50',
        barClass: 'bg-emerald-500',
        Icon: CheckCircle2,
      };
    default:
      return {
        textClass: 'text-sky-400',
        surfaceClass: 'bg-sky-950/25 border-sky-900/50',
        barClass: 'bg-sky-500',
        Icon: HelpCircle,
      };
  }
}

export const RiskResultPanel: React.FC<RiskResultPanelProps> = ({
  result,
  channel,
  targetPreview,
  savedScanId,
  saveWarning,
  retryingAi = false,
  onRetryAi,
  onAskAssistant,
}) => {
  const { textClass, surfaceClass, barClass, Icon } = getRiskAppearance(result.riskLevel);
  const aiUnavailable = result.aiStatus === 'unavailable' || Boolean(result.aiError);
  const aiSkipped = result.aiStatus === 'skipped';
  const breakdown = result.scoreBreakdown ?? [];
  const extractedFeatures = result.mlPrediction?.extractedFeatures;

  return (
    <section
      aria-label="Scan Analysis Findings"
      className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-6"
    >
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between pb-5 border-b border-slate-800/80">
        <div className="space-y-1.5 min-w-0">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span>Deterministic Heuristic + Gemini Analysis</span>
            <span aria-hidden="true">·</span>
            <span className="uppercase font-mono">{channel}</span>
            <span aria-hidden="true">·</span>
            <span className="font-mono tabular-nums">
              {new Date(result.analyzedAt).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              })}
            </span>
          </div>
          <div className="flex items-center gap-2.5">
            <Icon className={`h-5 w-5 shrink-0 ${textClass}`} />
            <h3 className={`text-xl font-semibold tracking-tight ${textClass}`}>
              {result.riskLevel}
            </h3>
          </div>
          <p className="text-sm text-slate-300 font-mono break-all">{targetPreview}</p>
        </div>

        <div className="flex flex-wrap items-center gap-3 sm:gap-5 shrink-0">
          <div className={`rounded-lg border px-4 py-2.5 text-right ${surfaceClass}`}>
            <div className="text-xs text-slate-400">Risk Score</div>
            <div className={`text-2xl font-semibold font-mono tabular-nums ${textClass}`}>
              {result.riskScore}
              <span className="text-sm text-slate-500">/100</span>
            </div>
          </div>
          <button
            type="button"
            onClick={onAskAssistant}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 min-h-[44px] text-sm font-medium text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Bot className="h-4 w-4" />
            <span>Ask AI Assistant</span>
          </button>
        </div>
      </div>

      <div className="space-y-2">
        <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
          <div
            className={`h-full transition-all duration-300 ${barClass}`}
            style={{ width: `${Math.max(4, result.riskScore)}%` }}
          />
        </div>
        <p className="text-sm leading-relaxed text-slate-200">{result.verdictSummary}</p>
      </div>

      {(result.reputation || result.mlPrediction || typeof result.heuristicScore === 'number') && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="rounded-lg border border-slate-800 bg-[#0D1322] p-4 flex flex-col justify-between gap-2">
            <div className="space-y-1">
              <div className="text-xs font-medium text-slate-400">
                1. Deterministic Heuristics
              </div>
              <div className="text-sm font-semibold text-slate-100">
                {breakdown.length > 0
                  ? `${breakdown.length} weighted rule${breakdown.length === 1 ? '' : 's'} triggered`
                  : '0 lexical threat rules triggered'}
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Static rule engine (typosquatting edit distance, homoglyphs, URL structure, lures) without visiting targets.
              </p>
              {result.normalizedHost && (
                <p className="text-[11px] font-mono text-slate-400 break-all pt-1">
                  Host: {result.normalizedHost}
                  {result.registrableDomain ? ` · Base: ${result.registrableDomain}` : ''}
                </p>
              )}
            </div>
            <div className="flex items-center justify-between border-t border-slate-800/80 pt-2 mt-1">
              <span className="text-[11px] text-slate-400">Heuristic Score</span>
              <span className="text-sm font-semibold font-mono tabular-nums text-slate-100">
                {typeof result.heuristicScore === 'number' ? result.heuristicScore : result.riskScore}/100
              </span>
            </div>
          </div>

          {result.reputation && (
            <div className="rounded-lg border border-slate-800 bg-[#0D1322] p-4 flex flex-col justify-between gap-2">
              <div className="space-y-1.5">
                <div className="text-xs font-medium text-slate-400">
                  2. Threat Reputation ({result.reputation.provider || result.reputation.source})
                </div>
                <div
                  className={`text-sm font-semibold ${
                    result.reputation.resultLabel === 'Known Malicious'
                      ? 'text-red-400'
                      : result.reputation.resultLabel === 'No Known Threat Found'
                        ? 'text-emerald-400'
                        : 'text-sky-300'
                  }`}
                >
                  {result.reputation.resultLabel}
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">{result.reputation.summary}</p>
                {result.reputation.configured === false && (
                  <p className="rounded border border-amber-900/60 bg-amber-950/30 px-2.5 py-1.5 text-[11px] text-amber-200 leading-relaxed">
                    Reputation checking is not configured on the server. Set GOOGLE_SAFE_BROWSING_API_KEY in server environment secrets.
                  </p>
                )}
                {result.reputation.threatCategories && result.reputation.threatCategories.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {result.reputation.threatCategories.map((cat) => (
                      <span
                        key={cat}
                        className="rounded border border-red-900/60 bg-red-950/40 px-2 py-0.5 text-[10px] font-mono text-red-200"
                      >
                        {cat}
                      </span>
                    ))}
                  </div>
                )}
                {result.reputation.resultLabel === 'No Known Threat Found' && (
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    No match found does NOT classify this URL as safe; heuristics stay separate.
                  </p>
                )}
              </div>
              <div className="flex items-center justify-between gap-2 border-t border-slate-800/80 pt-2 mt-1">
                <span className="text-[11px] text-slate-400">
                  {result.reputation.checkedAt
                    ? `Checked ${new Date(result.reputation.checkedAt).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                      })}`
                    : 'Provider Status'}
                </span>
                <span className="text-xs font-mono text-slate-200 truncate">
                  {result.reputation.errorCode || result.reputation.status}
                </span>
              </div>
            </div>
          )}

          {result.mlPrediction && (
            <div className="rounded-lg border border-slate-800 bg-[#0D1322] p-4 flex flex-col justify-between gap-2">
              <div className="space-y-1.5">
                <div className="text-xs font-medium text-slate-400">
                  3. TypeScript Feature Model ({result.mlPrediction.modelName})
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-slate-100">
                    {result.mlPrediction.predictedLabel}
                  </span>
                  <span className="text-sm font-semibold font-mono tabular-nums text-sky-300">
                    {result.mlPrediction.phishingProbability}%
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {result.mlPrediction.summary}
                </p>
                {result.mlPrediction.topFeatures.length > 0 && (
                  <ul className="space-y-1 pt-1">
                    {result.mlPrediction.topFeatures.slice(0, 4).map((feat, idx) => (
                      <li
                        key={idx}
                        className="flex items-center justify-between gap-2 text-[11px] text-slate-400"
                      >
                        <span className="truncate">{feat.name}</span>
                        <span className="font-mono text-slate-200 shrink-0">{feat.value}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div className="flex items-center justify-between border-t border-slate-800/80 pt-2 mt-1">
                <span className="text-[11px] text-slate-400">Scoring Confidence</span>
                <span className="text-xs font-mono text-slate-200">
                  {result.mlPrediction.confidence}
                </span>
              </div>
            </div>
          )}
        </div>
      )}

      {extractedFeatures && (
        <div className="rounded-lg border border-slate-800 bg-[#0D1322] p-4 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
            <h4 className="text-xs font-semibold text-slate-100">
              Extracted TypeScript URL Features (Server-Side Static Analysis)
            </h4>
            <span className="text-[11px] text-slate-400">
              23 lexical &amp; structural features evaluated without external ML servers
            </span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-[11px]">
            {[
              ['URL Length', extractedFeatures.urlLength],
              ['Host Length', extractedFeatures.hostnameLength],
              ['Subdomains', extractedFeatures.subdomainCount],
              ['Host Hyphens', extractedFeatures.hostHyphenCount],
              ['URL Digits', extractedFeatures.urlDigitCount],
              ['Suspicious Chars', extractedFeatures.suspiciousCharCount],
              ['Lure Keywords', extractedFeatures.totalLureKeywordCount],
              ['IP Host', extractedFeatures.hasIpAddress],
              ['HTTPS', extractedFeatures.isHttps],
              ['Punycode / IDN', extractedFeatures.isPunycodeOrIdn],
              ['Risky TLD', extractedFeatures.hasRiskyTld],
              ['Host Entropy', extractedFeatures.hostnameEntropy],
            ].map(([label, val]) => (
              <div
                key={String(label)}
                className="rounded border border-slate-800/80 bg-[#0A0F1A] px-2.5 py-1.5 flex items-center justify-between gap-2"
              >
                <span className="text-slate-400 truncate">{label}</span>
                <span className="font-mono text-slate-100 shrink-0">{val}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {savedScanId && (
        <div className="flex items-center gap-2 text-xs text-emerald-400">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>Saved to your Cloud Firestore Scan History (ID: {savedScanId})</span>
        </div>
      )}

      {saveWarning && (
        <div className="rounded-lg border border-amber-900/60 bg-amber-950/25 px-3.5 py-2.5 text-xs text-amber-300">
          {saveWarning}
        </div>
      )}

      {aiUnavailable && (
        <div className="rounded-lg border border-amber-900/60 bg-amber-950/25 px-4 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="space-y-0.5 text-xs text-amber-200">
            <p className="font-medium">AI explanation temporarily unavailable</p>
            {result.aiError && <p className="text-amber-300/85">{result.aiError}</p>}
            {result.requestId && (
              <p className="font-mono text-[11px] text-amber-400/75">
                Request ID: {result.requestId}
              </p>
            )}
          </div>
          {onRetryAi && (
            <button
              type="button"
              onClick={onRetryAi}
              disabled={retryingAi}
              className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-amber-700/60 bg-amber-950/50 px-3 py-1.5 text-xs font-medium text-amber-100 hover:bg-amber-900/50 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${retryingAi ? 'animate-spin' : ''}`} />
              <span>{retryingAi ? 'Retrying AI...' : 'Retry AI Explanation'}</span>
            </button>
          )}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-2">
        <div className="space-y-4">
          {breakdown.length > 0 && (
            <div className="space-y-2.5">
              <h4 className="text-sm font-semibold text-slate-100">
                Heuristic Score Breakdown
              </h4>
              <ul className="space-y-2">
                {breakdown.map((item) => (
                  <li
                    key={item.id}
                    className="rounded-lg border border-slate-800 bg-[#0D1322] px-3.5 py-2.5 space-y-1"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-xs font-medium text-slate-100">{item.label}</span>
                      <span className="font-mono text-xs font-semibold tabular-nums text-amber-300 shrink-0">
                        +{item.weight} pts
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">{item.evidence}</p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="space-y-3">
            <h4 className="text-sm font-semibold text-slate-100">Detected Signals &amp; Heuristics</h4>
            <ul className="space-y-2">
              {result.indicators.map((item, idx) => (
                <li
                  key={idx}
                  className="rounded-lg border border-slate-800 bg-[#0D1322] px-3.5 py-2.5 text-sm text-slate-300 leading-relaxed"
                >
                  {item}
                </li>
              ))}
            </ul>
          </div>

          {result.extractedUrls && result.extractedUrls.length > 0 && (
            <div className="pt-2 space-y-2">
              <h4 className="text-sm font-semibold text-slate-100">
                Extracted Links (Non-Clickable · Never Visited)
              </h4>
              <div className="space-y-1.5">
                {result.extractedUrls.map((u, idx) => (
                  <div
                    key={idx}
                    className="rounded-md border border-slate-800 bg-[#0A0F1A] px-3 py-2 text-xs font-mono text-slate-300 break-all select-all"
                  >
                    {u}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="space-y-4">
          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-slate-100">Gemini Security Analyst Explanation</h4>
            {aiUnavailable ? (
              <div className="rounded-lg border border-amber-900/50 bg-[#0D1322] p-4 space-y-3">
                <p className="text-sm font-medium text-amber-200">
                  AI explanation temporarily unavailable
                </p>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {result.aiError ||
                    'The Gemini service could not complete an explanation right now. Your deterministic heuristic findings remain visible on the left.'}
                </p>
                {onRetryAi && (
                  <button
                    type="button"
                    onClick={onRetryAi}
                    disabled={retryingAi}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-[#0A0F1A] px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-60 transition-colors cursor-pointer"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${retryingAi ? 'animate-spin' : ''}`} />
                    <span>{retryingAi ? 'Retrying AI Explanation...' : 'Retry AI Explanation'}</span>
                  </button>
                )}
              </div>
            ) : aiSkipped ? (
              <div className="rounded-lg border border-slate-800 bg-[#0D1322] p-4 space-y-3">
                <p className="text-sm text-slate-300 leading-relaxed">
                  {result.aiExplanation ||
                    'AI explanation was skipped. Deterministic heuristics and TypeScript feature scoring ran statically without calling Gemini.'}
                </p>
                {onRetryAi && (
                  <button
                    type="button"
                    onClick={onRetryAi}
                    disabled={retryingAi}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-[#0A0F1A] px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-60 transition-colors cursor-pointer"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${retryingAi ? 'animate-spin' : ''}`} />
                    <span>{retryingAi ? 'Generating AI...' : 'Generate Gemini AI Explanation'}</span>
                  </button>
                )}
              </div>
            ) : (
              <div className="rounded-lg border border-slate-800 bg-[#0D1322] p-4 text-sm text-slate-200 leading-relaxed whitespace-pre-line">
                {result.aiExplanation}
              </div>
            )}
          </div>

          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-slate-100">Recommended Next Steps</h4>
            <ul className="space-y-2">
              {result.recommendations.map((rec, idx) => (
                <li
                  key={idx}
                  className="rounded-lg border border-slate-800 bg-[#0D1322] px-3.5 py-2.5 text-sm text-slate-300 leading-relaxed"
                >
                  {rec}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
};
