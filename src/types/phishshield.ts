export type NavTab =
  | 'dashboard'
  | 'url-scanner'
  | 'message-scanner'
  | 'qr-scanner'
  | 'assistant'
  | 'history'
  | 'reports';

export type ScanChannel = 'url' | 'email' | 'sms' | 'qr';

export type RiskLevel =
  | 'Known Malicious'
  | 'High Risk'
  | 'Suspicious'
  | 'No Known Threat Found'
  | 'Unknown/Unverified';

export type SensitivityLevel = 'standard' | 'strict' | 'paranoid';

export type ReportFormat = 'pdf' | 'json' | 'markdown';

export interface ScoreContribution {
  id: string;
  label: string;
  category: string;
  weight: number;
  evidence: string;
}

export type ReputationLabel =
  | 'Known Malicious'
  | 'No Known Threat Found'
  | 'Unknown / Unverified';

export interface ReputationResult {
  status: 'confirmed_malicious' | 'no_known_threat' | 'unverified';
  resultLabel: ReputationLabel;
  statusLabel: string;
  provider: string;
  source?: string;
  configured: boolean;
  checkedAt: string;
  submittedUrl?: string;
  matchedDomain?: string;
  matchedUrl?: string;
  threatCategories: string[];
  summary: string;
  isConfirmedMalicious: boolean;
  errorCode?: string;
  latencyMs?: number;
}

export interface MlFeatureSignal {
  name: string;
  value: string;
  impact: 'increases_risk' | 'neutral' | 'reduces_risk';
}

export interface UrlExtractedFeatures {
  urlLength: number;
  hostnameLength: number;
  pathLength: number;
  queryLength: number;
  subdomainCount: number;
  dotCount: number;
  hostHyphenCount: number;
  urlDigitCount: number;
  hostDigitRatio: number;
  hasIpAddress: number;
  hasNonStandardPort: number;
  isHttps: number;
  isPunycodeOrIdn: number;
  suspiciousCharCount: number;
  hasAtSymbol: number;
  hasDoubleSlashRedirect: number;
  hostLureKeywordCount: number;
  totalLureKeywordCount: number;
  isUrlShortener: number;
  hasRiskyTld: number;
  hostnameEntropy: number;
  maxConsecutiveRepeat: number;
  brandTyposquatMatch: number;
}

export interface MlPredictionResult {
  modelName: string;
  phishingProbability: number;
  predictedLabel: 'Likely Phishing' | 'Suspicious Lexical Profile' | 'Low-Risk Lexical Profile';
  confidence: 'High' | 'Medium' | 'Low';
  topFeatures: MlFeatureSignal[];
  extractedFeatures?: UrlExtractedFeatures;
  summary: string;
}

export const BLUEPRINT_LIMITS = {
  ID_MAX: 128,
  ID_REGEX: /^[a-zA-Z0-9_-]+$/,
  DISPLAY_NAME_MAX: 120,
  EMAIL_MAX: 254,
  PHOTO_URL_MAX: 1000,
  TARGET_PREVIEW_MAX: 500,
  RAW_INPUT_MAX: 8000,
  VERDICT_SUMMARY_MAX: 2000,
  AI_EXPLANATION_MAX: 8000,
  INDICATORS_MAX: 20,
  INDICATOR_ITEM_MAX: 300,
  RECOMMENDATIONS_MAX: 15,
  RECOMMENDATION_ITEM_MAX: 300,
  REPUTATION_STATUS_MAX: 64,
  REPUTATION_RESULT_MAX: 64,
  REPUTATION_PROVIDER_MAX: 120,
  REPUTATION_CHECKED_AT_MAX: 64,
  SUBMITTED_URL_MAX: 2000,
  THREAT_CATEGORIES_MAX: 10,
  THREAT_CATEGORY_ITEM_MAX: 64,
  REPUTATION_SUMMARY_MAX: 500,
  SCORE_BREAKDOWN_SUMMARY_MAX: 4000,
  ML_SUMMARY_MAX: 300,
  ANALYST_NOTE_MAX: 1000,
  REPORT_TITLE_MAX: 180,
  REPORT_SUMMARY_MAX: 4000,
  REPORT_CONTENT_MAX: 40000,
} as const;

export interface UserProfile {
  uid: string;
  displayName: string;
  email: string;
  photoURL?: string;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface UserPreferences {
  userId: string;
  sensitivity: SensitivityLevel;
  autoExplainWithAi: boolean;
  defaultReportFormat: ReportFormat;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface ScanRecord {
  id: string;
  userId: string;
  scanType: ScanChannel;
  targetPreview: string;
  rawInput: string;
  riskLevel: RiskLevel;
  riskScore: number;
  heuristicScore?: number;
  submittedUrl?: string;
  reputationStatus?: string;
  reputationResult?: string;
  reputationProvider?: string;
  reputationCheckedAt?: string;
  threatCategories?: string[];
  reputationSummary?: string;
  scoreBreakdownSummary?: string;
  mlProbability?: number;
  mlSummary?: string;
  verdictSummary: string;
  aiExplanation: string;
  indicators: string[];
  recommendations: string[];
  isDemoMode: boolean;
  archived: boolean;
  analystNote: string;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface SecurityReport {
  id: string;
  userId: string;
  title: string;
  format: ReportFormat;
  scanCount: number;
  highRiskCount: number;
  summary: string;
  content: string;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface AnalysisResponse {
  riskScore: number;
  heuristicScore?: number;
  riskLevel: RiskLevel;
  verdictSummary: string;
  indicators: string[];
  scoreBreakdown?: ScoreContribution[];
  reputation?: ReputationResult;
  mlPrediction?: MlPredictionResult;
  recommendations: string[];
  extractedUrls: string[];
  normalizedUrl?: string;
  parsedHost?: string;
  normalizedHost?: string;
  registrableDomain?: string;
  aiExplanation: string;
  aiStatus?: 'success' | 'unavailable' | 'skipped';
  aiError?: string;
  aiErrorCode?: string;
  modelUsed?: string;
  requestId?: string;
  latencyMs?: number;
  isDemoMode: boolean;
  analyzedAt: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'model';
  text: string;
  timestampMs: number;
}
