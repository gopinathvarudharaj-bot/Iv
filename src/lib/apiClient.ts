import type {
  AnalysisResponse,
  MlPredictionResult,
  RiskLevel,
  ScanChannel,
  SensitivityLevel,
} from '../types/phishshield';

const CLIENT_FETCH_TIMEOUT_MS = 75_000;

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CLIENT_FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    const data = (await response.json().catch(() => ({}))) as T & { error?: string };
    if (!response.ok) {
      throw new Error(data.error || `Request failed with status ${response.status}`);
    }
    return data;
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error('AI explanation temporarily unavailable (client request timed out).');
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export function analyzeUrlApi(payload: {
  url: string;
  sensitivity: SensitivityLevel;
  useAi: boolean;
}): Promise<AnalysisResponse> {
  return postJson<AnalysisResponse>('/api/analyze/url', payload);
}

export function analyzeMessageApi(payload: {
  channel: 'email' | 'sms';
  sender?: string;
  subject?: string;
  content: string;
  sensitivity: SensitivityLevel;
  useAi: boolean;
}): Promise<AnalysisResponse> {
  return postJson<AnalysisResponse>('/api/analyze/message', payload);
}

export function analyzeQrApi(payload: {
  decodedPayload: string;
  sourceFileName?: string;
  sensitivity: SensitivityLevel;
  useAi: boolean;
}): Promise<AnalysisResponse> {
  return postJson<AnalysisResponse>('/api/analyze/qr', payload);
}

export function retryAiExplanationApi(payload: {
  mode: 'url' | 'email' | 'sms' | 'qr';
  rawInput: string;
  heuristics: {
    riskScore: number;
    heuristicScore?: number;
    riskLevel: string;
    verdictSummary: string;
    indicators: string[];
    scoreBreakdown?: Array<{
      id?: string;
      label: string;
      category?: string;
      weight: number;
      evidence: string;
    }>;
    reputation?: {
      status: string;
      resultLabel?: string;
      statusLabel: string;
      provider?: string;
      source?: string;
      configured?: boolean;
      checkedAt?: string;
      threatCategories?: string[];
      matchedDomain?: string;
      matchedUrl?: string;
      summary: string;
      errorCode?: string;
    };
    mlPrediction?: MlPredictionResult;
  };
  extraContext?: string;
}): Promise<{
  aiExplanation: string;
  aiStatus: 'success' | 'unavailable';
  aiError?: string;
  aiErrorCode?: string;
  modelUsed?: string;
  requestId?: string;
  latencyMs?: number;
  analyzedAt: string;
}> {
  return postJson('/api/analyze/explain', payload);
}

export interface RescoredScanItem {
  id: string;
  riskScore: number;
  heuristicScore: number;
  riskLevel: RiskLevel;
  submittedUrl?: string;
  reputationStatus: string;
  reputationResult: string;
  reputationProvider: string;
  reputationCheckedAt: string;
  threatCategories: string[];
  reputationSummary: string;
  scoreBreakdownSummary: string;
  mlProbability: number;
  mlSummary: string;
  verdictSummary: string;
  indicators: string[];
  recommendations: string[];
}

export function rescoreScansApi(payload: {
  scans: Array<{
    id: string;
    scanType: ScanChannel;
    rawInput: string;
    targetPreview: string;
    submittedUrl?: string;
    riskScore?: number;
    heuristicScore?: number;
    verdictSummary?: string;
    indicators?: string[];
    recommendations?: string[];
    mlProbability?: number;
    mlSummary?: string;
  }>;
  sensitivity: SensitivityLevel;
}): Promise<{ updated: RescoredScanItem[] }> {
  return postJson<{ updated: RescoredScanItem[] }>('/api/scans/rescore', payload);
}

export function sendAssistantChatApi(payload: {
  messages: Array<{ role: 'user' | 'model'; text: string }>;
  scanContext?: {
    scanType: string;
    targetPreview: string;
    riskLevel: string;
    riskScore: number;
    indicators: string[];
  };
}): Promise<{ reply: string; modelUsed?: string; requestId?: string; latencyMs?: number }> {
  return postJson<{ reply: string; modelUsed?: string; requestId?: string; latencyMs?: number }>(
    '/api/assistant/chat',
    payload
  );
}
