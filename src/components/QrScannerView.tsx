import React, { useRef, useState } from 'react';
import jsQR from 'jsqr';
import QRCode from 'qrcode';
import { QrCode, Upload } from 'lucide-react';
import { analyzeQrApi, retryAiExplanationApi } from '../lib/apiClient';
import { sanitizeQrPayloadForStorage } from '../lib/scanPayload';
import type { AnalysisResponse, ScanRecord, UserPreferences } from '../types/phishshield';
import { RiskResultPanel } from './RiskResultPanel';

interface QrScannerViewProps {
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

export const QrScannerView: React.FC<QrScannerViewProps> = ({
  preferences,
  onPersistScan,
  onAskAssistant,
}) => {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [decodedText, setDecodedText] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [savedScanId, setSavedScanId] = useState<string | null>(null);
  const [saveWarning, setSaveWarning] = useState<string | null>(null);
  const [lastFileName, setLastFileName] = useState<string>('');
  const [retryingAi, setRetryingAi] = useState(false);
  const [useAi, setUseAi] = useState(preferences.autoExplainWithAi);

  React.useEffect(() => {
    setUseAi(preferences.autoExplainWithAi);
  }, [preferences.autoExplainWithAi]);

  const decodeAndAnalyzeBlob = async (blob: Blob, fileName: string) => {
    setLoading(true);
    setError(null);
    setSavedScanId(null);
    setSaveWarning(null);
    setResult(null);
    setLastFileName(fileName);

    try {
      const objectUrl = URL.createObjectURL(blob);
      setPreviewUrl(objectUrl);

      const img = new Image();
      await new Promise<void>((resolve, reject) => {
        img.onload = () => resolve();
        img.onerror = () => reject(new Error('Could not load QR image bytes.'));
        img.src = objectUrl;
      });

      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      if (!ctx) throw new Error('Canvas 2D context unavailable.');
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      const qr = jsQR(imageData.data, imageData.width, imageData.height);
      if (!qr || !qr.data) {
        setDecodedText(null);
        throw new Error(
          'No valid QR code matrix detected in the uploaded image. Try a clearer image or generate a sample QR below.'
        );
      }

      const payload = qr.data.trim();
      setDecodedText(payload);

      const analysis = await analyzeQrApi({
        decodedPayload: payload,
        sourceFileName: fileName,
        sensitivity: preferences.sensitivity,
        useAi,
      });
      setResult(analysis);

      const breakdownSummary = (analysis.scoreBreakdown ?? [])
        .map((b) => `+${b.weight} ${b.label}: ${b.evidence}`)
        .join(' | ');

      const sanitizedPayload = sanitizeQrPayloadForStorage(payload);
      const persisted = await onPersistScan({
        scanType: 'qr',
        targetPreview: sanitizedPayload.slice(0, 500),
        rawInput: sanitizedPayload,
        riskLevel: analysis.riskLevel,
        riskScore: analysis.riskScore,
        heuristicScore: analysis.heuristicScore,
        submittedUrl: analysis.reputation?.submittedUrl || analysis.extractedUrls?.[0],
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
      setError(err instanceof Error ? err.message : 'Failed to decode QR image.');
    } finally {
      setLoading(false);
    }
  };

  const handleRetryAi = async () => {
    if (!result || !decodedText || retryingAi) return;
    setRetryingAi(true);
    try {
      const retried = await retryAiExplanationApi({
        mode: 'qr',
        rawInput: decodedText,
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
        extraContext: lastFileName ? `Source QR image filename: ${lastFileName.slice(0, 120)}` : undefined,
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

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    void decodeAndAnalyzeBlob(file, file.name);
    e.target.value = '';
  };

  const generateSampleQr = async (payload: string, label: string) => {
    try {
      const dataUrl = await QRCode.toDataURL(payload, {
        width: 320,
        margin: 2,
        color: { dark: '#0f172a', light: '#ffffff' },
      });
      const res = await fetch(dataUrl);
      const blob = await res.blob();
      await decodeAndAnalyzeBlob(blob, `${label}.png`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not generate sample QR code.');
    }
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 pb-4 border-b border-slate-800">
          <div className="space-y-1">
            <div className="text-xs text-slate-400">
              Demo Quishing Scanner · Local Browser Pixel Decoding (Never Uploaded)
            </div>
            <h1 className="text-2xl font-semibold text-slate-50">QR Code Threat Scanner</h1>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
          <div className="lg:col-span-2 space-y-4">
            <div className="rounded-xl border border-dashed border-slate-700 bg-[#0A0F1A] p-6 text-center space-y-3">
              <QrCode className="h-8 w-8 text-blue-400 mx-auto" />
              <div className="space-y-1">
                <p className="text-sm font-medium text-slate-200">
                  Upload a QR code image (PNG, JPG, WebP)
                </p>
                <p className="text-xs text-slate-400">
                  Pixels are decoded locally in your browser using jsQR. Images are never uploaded to cloud storage, and decoded links are never opened automatically.
                </p>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp"
                onChange={handleFileChange}
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={loading}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 min-h-[44px] text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60 transition-colors cursor-pointer"
              >
                <Upload className="h-4 w-4" />
                <span>{loading ? 'Decoding QR...' : 'Select QR Image'}</span>
              </button>
              <div className="pt-1">
                <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={useAi}
                    onChange={(e) => setUseAi(e.target.checked)}
                    className="h-4 w-4 accent-blue-600"
                  />
                  <span>Include Gemini AI explanation</span>
                </label>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-slate-400 mr-1">Generate Demo QR Samples:</span>
              <button
                type="button"
                onClick={() =>
                  void generateSampleQr(
                    'http://micros0ft-mfa-reset.top/auth?redirect=https://example.invalid',
                    'sample_quishing_mfa'
                  )
                }
                className="rounded-md border border-slate-800 bg-[#0A0F1A] px-3 py-1.5 text-xs text-slate-300 hover:border-slate-700 hover:text-white transition-colors cursor-pointer"
              >
                Quishing MFA Reset QR
              </button>
              <button
                type="button"
                onClick={() =>
                  void generateSampleQr(
                    'upi://pay?pa=unverified-merchant@okaxis&am=4999',
                    'sample_payment_qr'
                  )
                }
                className="rounded-md border border-slate-800 bg-[#0A0F1A] px-3 py-1.5 text-xs text-slate-300 hover:border-slate-700 hover:text-white transition-colors cursor-pointer"
              >
                Payment URI QR
              </button>
              <button
                type="button"
                onClick={() =>
                  void generateSampleQr(
                    'https://events.harborview-conference.example/schedule',
                    'sample_unknown_qr'
                  )
                }
                className="rounded-md border border-slate-800 bg-[#0A0F1A] px-3 py-1.5 text-xs text-slate-300 hover:border-slate-700 hover:text-white transition-colors cursor-pointer"
              >
                Unknown URL QR
              </button>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-[#0A0F1A] p-4 space-y-3">
            <div className="text-xs font-medium text-slate-300">Decoded QR Preview</div>
            {previewUrl ? (
              <div className="space-y-3">
                <img
                  src={previewUrl}
                  alt="Uploaded QR code preview"
                  referrerPolicy="no-referrer"
                  className="w-40 h-40 object-contain rounded-lg bg-white p-2 mx-auto"
                />
                {decodedText && (
                  <div className="rounded-md border border-slate-800 bg-[#111827] p-2.5 text-xs font-mono text-slate-200 break-all">
                    {decodedText}
                  </div>
                )}
              </div>
            ) : (
              <div className="h-44 flex items-center justify-center text-xs text-slate-500 text-center px-3">
                Upload or generate a QR sample to inspect its decoded payload safely.
              </div>
            )}
          </div>
        </div>

        {error && (
          <div className="rounded-lg border border-red-900/60 bg-red-950/30 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}
      </section>

      {!loading && result && decodedText && (
        <RiskResultPanel
          result={result}
          channel="qr"
          targetPreview={decodedText}
          savedScanId={savedScanId}
          saveWarning={saveWarning}
          retryingAi={retryingAi}
          onRetryAi={() => void handleRetryAi()}
          onAskAssistant={() =>
            onAskAssistant({
              scanType: 'qr',
              targetPreview: decodedText,
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
