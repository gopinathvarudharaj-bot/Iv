import dotenv from 'dotenv';
import express from 'express';
import type { Request, Response } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ThinkingLevel } from '@google/genai';
import {
  createGeminiClientFromEnv,
  createRequestId,
  executeGeminiWithRetry,
  GEMINI_FLASH_MODEL,
  generateGeminiExplanationWithClient,
} from './server/geminiResilience.ts';

import {
  analyzeUrlRisk,
  applyReputationToAnalysis,
  applySensitivityMultiplier,
  classifyFromScores,
  type MlPredictionResult,
  type ReputationResult,
  type RiskClassification,
  type ScoreContribution,
  type SensitivityLevel,
} from './server/urlRiskEngine.ts';
import {
  buildNoUrlReputationResult,
  checkUrlReputationWithSafeBrowsing,
  checkUrlsReputationWithSafeBrowsing,
  GOOGLE_SAFE_BROWSING_PROVIDER,
  isSafeBrowsingConfigured,
} from './server/threatReputation.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = 3000;

type RiskLevel = RiskClassification;
type Sensitivity = SensitivityLevel;

interface HeuristicAnalysis {
  riskScore: number;
  heuristicScore: number;
  riskLevel: RiskLevel;
  verdictSummary: string;
  indicators: string[];
  scoreBreakdown: ScoreContribution[];
  reputation: ReputationResult;
  mlPrediction: MlPredictionResult;
  recommendations: string[];
  extractedUrls: string[];
  normalizedUrl?: string;
  parsedHost?: string;
  normalizedHost?: string;
  registrableDomain?: string;
}

function extractUrlsFromText(text: string): string[] {
  const matches = text.match(/https?:\/\/[^\s"'<>()]+/gi) || [];
  const bareMatches =
    text.match(/\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|xyz|top|tk|ml|ga|cf|zip|mov|info|click|link|ru|cn|invalid)(?:\/[^\s"'<>()]*)?/gi) ||
    [];
  const combined = [...matches, ...bareMatches].map((u) => u.trim());
  return Array.from(new Set(combined)).slice(0, 12);
}

async function analyzeUrlWithReputation(
  rawUrl: string,
  sensitivity: Sensitivity
): Promise<HeuristicAnalysis> {
  const base = analyzeUrlRisk(rawUrl, sensitivity);
  const targetUrl = base.normalizedUrl || rawUrl;
  const rep = await checkUrlReputationWithSafeBrowsing(targetUrl);
  return applyReputationToAnalysis(base, {
    ...rep,
    source: rep.provider,
  });
}

async function analyzeMessageWithReputation(
  channel: 'email' | 'sms',
  sender: string,
  subject: string,
  content: string,
  sensitivity: Sensitivity
): Promise<HeuristicAnalysis> {
  const combined = `${sender}\n${subject}\n${content}`;
  const lower = combined.toLowerCase();
  const scoreBreakdown: ScoreContribution[] = [];

  const extractedUrls = extractUrlsFromText(combined);

  const urgencyTerms = [
    'urgent',
    'immediately',
    'suspended',
    'within 24 hours',
    'account locked',
    'final notice',
    'action required',
    'verify now',
    'unauthorized login',
    'expires today',
    'legal action',
  ];
  const matchedUrgency = urgencyTerms.filter((t) => lower.includes(t));
  if (matchedUrgency.length > 0) {
    const w = Math.min(34, 14 + matchedUrgency.length * 8);
    scoreBreakdown.push({
      id: 'message_urgency',
      label: 'Coercive Urgency Language',
      category: 'lure',
      weight: w,
      evidence: `Detected coercive urgency phrases (${matchedUrgency.slice(0, 3).join(', ')}).`,
    });
  }

  const financialTerms = [
    'wire transfer',
    'gift card',
    'bitcoin',
    'crypto',
    'invoice attached',
    'overdue payment',
    'refund',
    'tax rebate',
    'customs fee',
    'redelivery fee',
  ];
  const matchedFinancial = financialTerms.filter((t) => lower.includes(t));
  if (matchedFinancial.length > 0) {
    const w = Math.min(35, 16 + matchedFinancial.length * 9);
    scoreBreakdown.push({
      id: 'message_financial',
      label: 'Financial / Payment Lure',
      category: 'lure',
      weight: w,
      evidence: `Financial or payment lure pattern detected (${matchedFinancial.slice(0, 3).join(', ')}).`,
    });
  }

  const credentialTerms = [
    'otp',
    'one-time passcode',
    'verification code',
    'pin',
    'ssn',
    'social security',
    'seed phrase',
    'recovery phrase',
    'password',
    'cvv',
  ];
  const matchedCreds = credentialTerms.filter((t) => lower.includes(t));
  if (matchedCreds.length > 0) {
    scoreBreakdown.push({
      id: 'message_credential_solicitation',
      label: 'Credential / Secret Solicitation',
      category: 'lure',
      weight: 28,
      evidence: `Sensitive credential / OTP / secret solicitation detected (${matchedCreds.slice(0, 3).join(', ')}).`,
    });
  }

  if (
    sender &&
    /@(gmail|yahoo|outlook|hotmail|proton)\./i.test(sender) &&
    /(bank|paypal|support|security|admin|irs|hr|ceo|billing)/i.test(`${sender} ${subject}`)
  ) {
    scoreBreakdown.push({
      id: 'sender_role_mismatch',
      label: 'Institutional Role via Free Webmail',
      category: 'impersonation',
      weight: 26,
      evidence:
        'Sender claims an institutional/corporate role while originating from a free webmail provider.',
    });
  }

  if (channel === 'sms' && extractedUrls.length > 0) {
    scoreBreakdown.push({
      id: 'sms_embedded_link',
      label: 'SMS Embedded Link Vector',
      category: 'structure',
      weight: 18,
      evidence: 'SMS message contains an embedded link (high-frequency smishing vector).',
    });
  }

  const liveRepRaw =
    extractedUrls.length > 0
      ? await checkUrlsReputationWithSafeBrowsing(extractedUrls)
      : buildNoUrlReputationResult(isSafeBrowsingConfigured());

  const embeddedReputation: ReputationResult = {
    ...liveRepRaw,
    source: liveRepRaw.provider,
  };

  let topUrlRes: HeuristicAnalysis | null = null;
  if (extractedUrls.length > 0) {
    let maxUrlScore = 0;
    for (const url of extractedUrls.slice(0, 4)) {
      const urlRes = analyzeUrlRisk(url, 'standard');
      if (urlRes.riskScore >= maxUrlScore) {
        maxUrlScore = urlRes.riskScore;
        topUrlRes = urlRes;
      }
    }
    if (topUrlRes && maxUrlScore >= 22) {
      const linkWeight = Math.round(maxUrlScore * 0.55);
      scoreBreakdown.push({
        id: 'embedded_url_risk',
        label: 'Embedded URL Risk Contribution',
        category: 'typosquatting',
        weight: linkWeight,
        evidence: `Embedded URL "${(topUrlRes.extractedUrls[0] || '').slice(0, 80)}" scored ${topUrlRes.riskScore}/100 (${topUrlRes.riskLevel}).`,
      });
    }
  }

  const rawScore = Math.min(100, scoreBreakdown.reduce((sum, item) => sum + item.weight, 0));
  const adjustedScore = applySensitivityMultiplier(rawScore, sensitivity);
  const delta = adjustedScore - rawScore;
  if (delta > 0) {
    scoreBreakdown.push({
      id: 'sensitivity_multiplier',
      label: `Sensitivity Profile (${sensitivity})`,
      category: 'sensitivity',
      weight: delta,
      evidence: `Applied '${sensitivity}' heuristic sensitivity scaling (+${delta} pts).`,
    });
  }

  const riskLevel = classifyFromScores({
    heuristicScore: adjustedScore,
    reputation: embeddedReputation,
  });
  const riskScore = embeddedReputation.isConfirmedMalicious
    ? Math.max(95, adjustedScore)
    : adjustedScore;

  const indicators = scoreBreakdown.map((item) => `[+${item.weight} pts] ${item.label}: ${item.evidence}`);

  const recommendations =
    riskLevel === 'Unknown/Unverified'
      ? [
          'Verify the sender out-of-band using an official phone number or known directory before acting.',
          'Do not click embedded links directly; inspect sender headers and domain alignment independently.',
          'Never share one-time passcodes (OTP), passwords, or recovery phrases over email or SMS.',
        ]
      : [
          'Do not reply to the sender, download attachments, or tap any embedded links.',
          'Contact the purported organization directly via their official app or verified phone number.',
          'Report the message as phishing/smishing to your email provider, mobile carrier (7726), or security team.',
        ];

  const verdictSummary =
    riskLevel === 'Unknown/Unverified'
      ? `Static ${channel.toUpperCase()} analysis found low overt phishing signal density, but the message remains Unknown/Unverified until sender authenticity is confirmed out-of-band.`
      : `Demo ${channel.toUpperCase()} analysis detected ${scoreBreakdown.length} social-engineering or link indicator(s), classifying this message as ${riskLevel}.`;

  const mlProb = Math.max(
    3,
    Math.min(
      98,
      Math.round(
        100 /
          (1 +
            Math.exp(
              -(-2.4 +
                matchedUrgency.length * 0.65 +
                matchedFinancial.length * 0.7 +
                matchedCreds.length * 0.9 +
                (extractedUrls.length > 0 ? 0.6 : 0) +
                (topUrlRes ? topUrlRes.mlPrediction.phishingProbability / 35 : 0))
            ))
      )
    )
  );
  const mlPrediction: MlPredictionResult = {
    modelName: 'PhishShield-TS-TextFeature-v1 (TypeScript Feature Scorer)',
    phishingProbability: mlProb,
    predictedLabel:
      mlProb >= 65
        ? 'Likely Phishing'
        : mlProb >= 30
          ? 'Suspicious Lexical Profile'
          : 'Low-Risk Lexical Profile',
    confidence: mlProb >= 75 || mlProb <= 15 ? 'High' : 'Medium',
    topFeatures: [
      {
        name: 'Urgency & Financial Coercion Density',
        value: `${matchedUrgency.length + matchedFinancial.length} phrase(s)`,
        impact: matchedUrgency.length + matchedFinancial.length > 0 ? 'increases_risk' : 'neutral',
      },
      {
        name: 'Embedded URL Feature Score',
        value: topUrlRes ? `${topUrlRes.mlPrediction.phishingProbability}%` : 'No embedded URL',
        impact: topUrlRes && topUrlRes.mlPrediction.phishingProbability >= 40 ? 'increases_risk' : 'neutral',
      },
    ],
    summary: `Server-side TypeScript text/link feature scorer estimates ${mlProb}% phishing likelihood independently of rule weights and static reputation.`,
  };

  return {
    riskScore,
    heuristicScore: adjustedScore,
    riskLevel,
    verdictSummary,
    indicators:
      indicators.length > 0
        ? indicators.slice(0, 12)
        : ['[0 pts] No explicit scam keywords matched static heuristics (sender authenticity remains unverified).'],
    scoreBreakdown,
    reputation: embeddedReputation,
    mlPrediction,
    recommendations,
    extractedUrls,
  };
}

async function analyzeQrPayloadWithReputation(
  decodedPayload: string,
  sensitivity: Sensitivity
): Promise<HeuristicAnalysis> {
  const trimmed = decodedPayload.trim();
  const lower = trimmed.toLowerCase();

  if (/^https?:\/\//i.test(trimmed) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(trimmed)) {
    const baseUrlAnalysis = analyzeUrlRisk(trimmed, sensitivity);
    const liveRepRaw = await checkUrlReputationWithSafeBrowsing(
      baseUrlAnalysis.normalizedUrl || trimmed
    );
    const base = applyReputationToAnalysis(baseUrlAnalysis, {
      ...liveRepRaw,
      source: liveRepRaw.provider,
    });

    const quishingWeight = 10;
    const scoreBreakdown: ScoreContribution[] = [
      {
        id: 'qr_hidden_url_vector',
        label: 'QR Hidden Destination ("Quishing")',
        category: 'structure',
        weight: quishingWeight,
        evidence: 'QR payload encodes an external URL hidden from naked-eye inspection prior to scanning.',
      },
      ...base.scoreBreakdown,
    ];
    const updatedHeuristicScore = Math.min(100, base.heuristicScore + quishingWeight);
    const riskLevel = classifyFromScores({
      heuristicScore: updatedHeuristicScore,
      reputation: base.reputation,
    });
    const riskScore = base.reputation.isConfirmedMalicious
      ? Math.max(95, updatedHeuristicScore)
      : updatedHeuristicScore;

    return {
      ...base,
      heuristicScore: updatedHeuristicScore,
      riskScore,
      riskLevel,
      scoreBreakdown,
      indicators: scoreBreakdown.map((item) => `[+${item.weight} pts] ${item.label}: ${item.evidence}`),
      verdictSummary: `Decoded QR URL payload (${base.normalizedHost || trimmed.slice(0, 64)}) classified as ${riskLevel} (heuristic ${updatedHeuristicScore}/100, reputation: ${base.reputation.resultLabel}; destination never visited).`,
    };
  }

  const scoreBreakdown: ScoreContribution[] = [
    {
      id: 'qr_non_url_payload',
      label: 'Non-URL QR Action Payload',
      category: 'structure',
      weight: 15,
      evidence: 'Structured non-web QR payload decoded locally.',
    },
  ];

  if (lower.startsWith('upi://') || lower.startsWith('bitcoin:') || lower.startsWith('ethereum:')) {
    scoreBreakdown.push({
      id: 'qr_payment_uri',
      label: 'Payment / Crypto URI Scheme',
      category: 'lure',
      weight: 40,
      evidence: 'Payment or cryptocurrency transfer URI encoded in QR payload. Verify payee identity before approving any transaction.',
    });
  } else if (lower.startsWith('wifi:')) {
    scoreBreakdown.push({
      id: 'qr_wifi_autoconfig',
      label: 'Wi-Fi Auto-Configuration QR',
      category: 'structure',
      weight: 28,
      evidence: 'Wi-Fi auto-configuration payload detected; rogue QR Wi-Fi codes can route traffic through an attacker-controlled access point.',
    });
    if (lower.includes('t:nopass') || !lower.includes('p:')) {
      scoreBreakdown.push({
        id: 'qr_wifi_open',
        label: 'Open / Unencrypted Wi-Fi Config',
        category: 'transport',
        weight: 18,
        evidence: 'Unencrypted or open Wi-Fi network configuration inside QR code.',
      });
    }
  } else if (lower.startsWith('tel:') || lower.startsWith('smsto:') || lower.startsWith('mailto:')) {
    scoreBreakdown.push({
      id: 'qr_communication_uri',
      label: 'Actionable Communication URI',
      category: 'structure',
      weight: 24,
      evidence: 'Actionable call, SMS, or email trigger URI encoded in QR payload.',
    });
  }

  const rawScore = Math.min(100, scoreBreakdown.reduce((sum, item) => sum + item.weight, 0));
  const adjustedScore = applySensitivityMultiplier(rawScore, sensitivity);
  const delta = adjustedScore - rawScore;
  if (delta > 0) {
    scoreBreakdown.push({
      id: 'sensitivity_multiplier',
      label: `Sensitivity Profile (${sensitivity})`,
      category: 'sensitivity',
      weight: delta,
      evidence: `Applied '${sensitivity}' heuristic sensitivity scaling (+${delta} pts).`,
    });
  }

  const noUrlRep = buildNoUrlReputationResult(isSafeBrowsingConfigured());
  const reputation: ReputationResult = {
    ...noUrlRep,
    source: noUrlRep.provider,
  };
  const riskLevel = classifyFromScores({ heuristicScore: adjustedScore, reputation });

  const qrMlProb = Math.max(5, Math.min(95, Math.round(adjustedScore * 0.9)));
  const mlPrediction: MlPredictionResult = {
    modelName: 'PhishShield-TS-QrFeature-v1 (TypeScript Feature Scorer)',
    phishingProbability: qrMlProb,
    predictedLabel:
      qrMlProb >= 65
        ? 'Likely Phishing'
        : qrMlProb >= 30
          ? 'Suspicious Lexical Profile'
          : 'Low-Risk Lexical Profile',
    confidence: qrMlProb >= 70 || qrMlProb <= 20 ? 'High' : 'Medium',
    topFeatures: [
      {
        name: 'QR URI Scheme Profile',
        value: trimmed.split(':')[0] || 'plain_text',
        impact: adjustedScore >= 35 ? 'increases_risk' : 'neutral',
      },
    ],
    summary: `Server-side TypeScript QR feature scorer estimates ${qrMlProb}% scam likelihood based on URI scheme and token structure.`,
  };

  const safePreview = trimmed
    .replace(/(WIFI:[^;\n]*;[^;\n]*P:)([^;\n]+)/gi, '$1[REDACTED]')
    .replace(/(;P:)([^;\n]+)(;|$)/gi, '$1[REDACTED]$3')
    .slice(0, 64);

  return {
    riskScore: adjustedScore,
    heuristicScore: adjustedScore,
    riskLevel,
    verdictSummary: `Decoded QR payload (${safePreview}${trimmed.length > 64 ? '...' : ''}) classified as ${riskLevel} via static payload inspection.`,
    indicators: scoreBreakdown.map((item) => `[+${item.weight} pts] ${item.label}: ${item.evidence}`),
    scoreBreakdown,
    reputation,
    mlPrediction,
    recommendations: [
      'Never scan or approve payment/login QR codes from unsolicited posters, stickers, or emails.',
      'Inspect the decoded destination domain or payment recipient carefully before taking action.',
      'PhishShield AI does not automatically follow or execute decoded QR targets.',
    ],
    extractedUrls: extractUrlsFromText(trimmed),
  };
}

async function generateGeminiExplanation(
  mode: 'url' | 'email' | 'sms' | 'qr',
  rawInput: string,
  heuristics: HeuristicAnalysis,
  extraContext?: string
) {
  return generateGeminiExplanationWithClient(
    createGeminiClientFromEnv(),
    mode,
    rawInput,
    heuristics,
    extraContext
  );
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  app.get('/api/health', async (req: Request, res: Response) => {
    const ai = createGeminiClientFromEnv();
    const base = {
      ok: true,
      geminiConfigured: Boolean(ai),
      geminiModel: GEMINI_FLASH_MODEL,
      reputationConfigured: isSafeBrowsingConfigured(),
      reputationProvider: GOOGLE_SAFE_BROWSING_PROVIDER,
    };

    if (req.query.probe !== '1') {
      res.json(base);
      return;
    }

    if (!ai) {
      res.status(503).json({
        ...base,
        probe: {
          status: 'unavailable',
          code: 'NOT_CONFIGURED',
          message: 'GEMINI_API_KEY is not configured in server runtime.',
        },
      });
      return;
    }

    const requestId = createRequestId();
    const availableModels: string[] = [];
    try {
      const pager = await ai.models.list();
      for await (const m of pager) {
        if (m.name && /(flash|hydrogen|gemini-3|gemini-4)/i.test(m.name)) {
          availableModels.push(m.name);
        }
        if (availableModels.length >= 25) break;
      }
    } catch {
      // ListModels may be restricted by key scope; proceed with direct prompt probe
    }

    const ALLOWED_PROBE_MODELS = new Set([
      GEMINI_FLASH_MODEL,
      'gemini-3.8-flash',
      'gemini-3.1-flash-lite',
      'gemini-4-hydrogen',
    ]);
    const requestedModel =
      typeof req.query.model === 'string' && ALLOWED_PROBE_MODELS.has(req.query.model)
        ? req.query.model
        : GEMINI_FLASH_MODEL;

    const probeOutcome = await executeGeminiWithRetry(
      async (signal) => {
        const reply = await ai.models.generateContent({
          model: requestedModel,
          contents: 'Reply with OK.',
          config: {
            abortSignal: signal,
            thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          },
        });
        return (reply.text ?? '').trim();
      },
      {
        requestId,
        operationName: 'health_probe',
        model: requestedModel,
        promptChars: 14,
        maxAttempts: 1,
      }
    );

    if (!probeOutcome.ok) {
      res.status(probeOutcome.error.httpStatus).json({
        ...base,
        probe: {
          status: 'unavailable',
          model: requestedModel,
          requestId: probeOutcome.requestId,
          code: probeOutcome.error.code,
          latencyMs: probeOutcome.totalDurationMs,
          message: probeOutcome.error.userMessage,
          availableModels,
        },
      });
      return;
    }

    res.json({
      ...base,
      probe: {
        status: 'ok',
        model: requestedModel,
        requestId: probeOutcome.requestId,
        latencyMs: probeOutcome.totalDurationMs,
        replyPreview: probeOutcome.value.slice(0, 40),
        availableModels,
      },
    });
  });

  app.post('/api/analyze/url', async (req: Request, res: Response) => {
    const { url, sensitivity = 'standard', useAi = true } = (req.body ?? {}) as {
      url?: string;
      sensitivity?: Sensitivity;
      useAi?: boolean;
    };

    if (!url || typeof url !== 'string' || !url.trim()) {
      res.status(400).json({ error: 'Please provide a URL string to inspect.' });
      return;
    }

    const cleanUrl = url.trim().slice(0, 4000);
    const heuristics = await analyzeUrlWithReputation(cleanUrl, sensitivity);

    if (!useAi) {
      res.json({
        ...heuristics,
        aiExplanation:
          'AI explanation skipped per user preference. Deterministic demo heuristics applied without visiting the submitted URL.',
        aiStatus: 'skipped',
        modelUsed: GEMINI_FLASH_MODEL,
        isDemoMode: true,
        analyzedAt: new Date().toISOString(),
      });
      return;
    }

    const aiRes = await generateGeminiExplanation('url', cleanUrl, heuristics);
    res.json({
      ...heuristics,
      aiExplanation: aiRes.explanation,
      aiStatus: aiRes.aiStatus,
      aiError: aiRes.aiError,
      aiErrorCode: aiRes.aiErrorCode,
      modelUsed: aiRes.modelUsed,
      requestId: aiRes.requestId,
      latencyMs: aiRes.latencyMs,
      isDemoMode: true,
      analyzedAt: new Date().toISOString(),
    });
  });

  app.post('/api/analyze/message', async (req: Request, res: Response) => {
    const {
      channel = 'email',
      sender = '',
      subject = '',
      content,
      sensitivity = 'standard',
      useAi = true,
    } = (req.body ?? {}) as {
      channel?: 'email' | 'sms';
      sender?: string;
      subject?: string;
      content?: string;
      sensitivity?: Sensitivity;
      useAi?: boolean;
    };

    if (!content || typeof content !== 'string' || !content.trim()) {
      res.status(400).json({ error: 'Please paste an email or SMS message body to analyze.' });
      return;
    }

    const safeChannel = channel === 'sms' ? 'sms' : 'email';
    const cleanContent = content.trim().slice(0, 6000);
    const cleanSender = String(sender || '').trim().slice(0, 200);
    const cleanSubject = String(subject || '').trim().slice(0, 300);

    const heuristics = await analyzeMessageWithReputation(
      safeChannel,
      cleanSender,
      cleanSubject,
      cleanContent,
      sensitivity
    );

    if (!useAi) {
      res.json({
        ...heuristics,
        aiExplanation:
          'AI explanation skipped per user preference. Deterministic demo heuristics applied.',
        aiStatus: 'skipped',
        modelUsed: GEMINI_FLASH_MODEL,
        isDemoMode: true,
        analyzedAt: new Date().toISOString(),
      });
      return;
    }

    const context = `Channel: ${safeChannel.toUpperCase()} | Sender: ${cleanSender || '(not provided)'} | Subject: ${cleanSubject || '(not provided)'}`;
    const aiRes = await generateGeminiExplanation(safeChannel, cleanContent, heuristics, context);
    res.json({
      ...heuristics,
      aiExplanation: aiRes.explanation,
      aiStatus: aiRes.aiStatus,
      aiError: aiRes.aiError,
      aiErrorCode: aiRes.aiErrorCode,
      modelUsed: aiRes.modelUsed,
      requestId: aiRes.requestId,
      latencyMs: aiRes.latencyMs,
      isDemoMode: true,
      analyzedAt: new Date().toISOString(),
    });
  });

  app.post('/api/analyze/qr', async (req: Request, res: Response) => {
    const {
      decodedPayload,
      sourceFileName = '',
      sensitivity = 'standard',
      useAi = true,
    } = (req.body ?? {}) as {
      decodedPayload?: string;
      sourceFileName?: string;
      sensitivity?: Sensitivity;
      useAi?: boolean;
    };

    if (!decodedPayload || typeof decodedPayload !== 'string' || !decodedPayload.trim()) {
      res.status(400).json({ error: 'No decoded QR payload provided.' });
      return;
    }

    const cleanPayload = decodedPayload.trim().slice(0, 4000);
    const heuristics = await analyzeQrPayloadWithReputation(cleanPayload, sensitivity);

    if (!useAi) {
      res.json({
        ...heuristics,
        aiExplanation:
          'AI explanation skipped per user preference. Deterministic QR payload heuristics applied without visiting external links.',
        aiStatus: 'skipped',
        modelUsed: GEMINI_FLASH_MODEL,
        isDemoMode: true,
        analyzedAt: new Date().toISOString(),
      });
      return;
    }

    const context = sourceFileName ? `Source QR image filename: ${sourceFileName.slice(0, 120)}` : undefined;
    const aiRes = await generateGeminiExplanation('qr', cleanPayload, heuristics, context);
    res.json({
      ...heuristics,
      aiExplanation: aiRes.explanation,
      aiStatus: aiRes.aiStatus,
      aiError: aiRes.aiError,
      aiErrorCode: aiRes.aiErrorCode,
      modelUsed: aiRes.modelUsed,
      requestId: aiRes.requestId,
      latencyMs: aiRes.latencyMs,
      isDemoMode: true,
      analyzedAt: new Date().toISOString(),
    });
  });

  app.post('/api/analyze/explain', async (req: Request, res: Response) => {
    const { mode, rawInput, heuristics, extraContext } = (req.body ?? {}) as {
      mode?: 'url' | 'email' | 'sms' | 'qr';
      rawInput?: string;
      heuristics?: Partial<HeuristicAnalysis>;
      extraContext?: string;
    };

    if (
      !mode ||
      !['url', 'email', 'sms', 'qr'].includes(mode) ||
      !rawInput ||
      typeof rawInput !== 'string' ||
      !rawInput.trim() ||
      !heuristics ||
      typeof heuristics.riskScore !== 'number' ||
      typeof heuristics.riskLevel !== 'string' ||
      !Array.isArray(heuristics.indicators)
    ) {
      res.status(400).json({ error: 'Invalid explanation retry payload.' });
      return;
    }

    const safeHeuristics: HeuristicAnalysis = {
      riskScore: heuristics.riskScore,
      heuristicScore:
        typeof heuristics.heuristicScore === 'number'
          ? heuristics.heuristicScore
          : heuristics.riskScore,
      riskLevel: heuristics.riskLevel as RiskLevel,
      verdictSummary: String(heuristics.verdictSummary || ''),
      indicators: heuristics.indicators.map((item) => String(item)).slice(0, 20),
      scoreBreakdown: Array.isArray(heuristics.scoreBreakdown)
        ? heuristics.scoreBreakdown.slice(0, 20)
        : [],
      reputation: heuristics.reputation ?? {
        status: 'unverified',
        resultLabel: 'Unknown / Unverified',
        statusLabel: 'Unknown / Unverified (Reputation Not Checked)',
        provider: GOOGLE_SAFE_BROWSING_PROVIDER,
        source: GOOGLE_SAFE_BROWSING_PROVIDER,
        configured: isSafeBrowsingConfigured(),
        checkedAt: new Date().toISOString(),
        threatCategories: [],
        summary: 'No external reputation record provided.',
        isConfirmedMalicious: false,
      },
      mlPrediction: heuristics.mlPrediction ?? {
        modelName: 'PhishShield-TS-FeatureModel-v2 (TypeScript Feature Scorer)',
        phishingProbability: Math.min(99, Math.max(1, heuristics.riskScore)),
        predictedLabel:
          heuristics.riskScore >= 65
            ? 'Likely Phishing'
            : heuristics.riskScore >= 30
              ? 'Suspicious Lexical Profile'
              : 'Low-Risk Lexical Profile',
        confidence: 'Medium',
        topFeatures: [],
        summary: 'Derived TypeScript lexical feature estimate.',
      },
      recommendations: [],
      extractedUrls: [],
    };

    const aiRes = await generateGeminiExplanation(
      mode,
      rawInput.trim().slice(0, 6000),
      safeHeuristics,
      typeof extraContext === 'string' ? extraContext.slice(0, 400) : undefined
    );

    res.json({
      aiExplanation: aiRes.explanation,
      aiStatus: aiRes.aiStatus,
      aiError: aiRes.aiError,
      aiErrorCode: aiRes.aiErrorCode,
      modelUsed: aiRes.modelUsed,
      requestId: aiRes.requestId,
      latencyMs: aiRes.latencyMs,
      analyzedAt: new Date().toISOString(),
    });
  });

  app.post('/api/scans/rescore', async (req: Request, res: Response) => {
    const { scans, sensitivity = 'standard' } = (req.body ?? {}) as {
      scans?: Array<{
        id?: string;
        scanType?: 'url' | 'email' | 'sms' | 'qr';
        rawInput?: string;
        targetPreview?: string;
        submittedUrl?: string;
        riskScore?: number;
        heuristicScore?: number;
        verdictSummary?: string;
        indicators?: string[];
        recommendations?: string[];
        mlProbability?: number;
        mlSummary?: string;
      }>;
      sensitivity?: Sensitivity;
    };

    if (!Array.isArray(scans)) {
      res.status(400).json({ error: 'scans array is required.' });
      return;
    }

    const updated = await Promise.all(
      scans.slice(0, 50).map(async (item) => {
        const id = String(item.id || '');
        const scanType = item.scanType || 'url';
        const target = String(item.targetPreview || item.rawInput || '').trim();
        const raw = String(item.rawInput || target).trim();

        // Redacted email/SMS records intentionally omit original message contents in Firestore;
        // refresh threat reputation for submittedUrl without overwriting original message heuristics.
        if (
          (scanType === 'email' || scanType === 'sms') &&
          raw.startsWith('[REDACTED_')
        ) {
          const urlCandidate = String(item.submittedUrl || '').trim();
          const liveRep = urlCandidate
            ? await checkUrlReputationWithSafeBrowsing(urlCandidate)
            : buildNoUrlReputationResult(isSafeBrowsingConfigured());
          const savedHeuristicScore =
            typeof item.heuristicScore === 'number'
              ? item.heuristicScore
              : typeof item.riskScore === 'number'
                ? item.riskScore
                : 0;
          const riskLevel = classifyFromScores({
            heuristicScore: savedHeuristicScore,
            reputation: liveRep,
          });
          const riskScore = liveRep.isConfirmedMalicious
            ? Math.max(95, savedHeuristicScore)
            : savedHeuristicScore;

          return {
            id,
            riskScore,
            heuristicScore: savedHeuristicScore,
            riskLevel,
            submittedUrl: liveRep.submittedUrl || urlCandidate || '',
            reputationStatus: liveRep.status,
            reputationResult: liveRep.resultLabel,
            reputationProvider: liveRep.provider,
            reputationCheckedAt: liveRep.checkedAt,
            threatCategories: liveRep.threatCategories,
            reputationSummary: liveRep.summary,
            scoreBreakdownSummary: '',
            mlProbability: typeof item.mlProbability === 'number' ? item.mlProbability : 10,
            mlSummary: item.mlSummary || 'Redacted message metadata preserved.',
            verdictSummary:
              item.verdictSummary ||
              `Preserved ${scanType.toUpperCase()} heuristic result with refreshed threat reputation (${liveRep.resultLabel}).`,
            indicators: Array.isArray(item.indicators) ? item.indicators : [],
            recommendations: Array.isArray(item.recommendations) ? item.recommendations : [],
          };
        }

        let analysis: HeuristicAnalysis;
        if (scanType === 'url') {
          analysis = await analyzeUrlWithReputation(target || raw, sensitivity);
        } else if (scanType === 'qr') {
          const decodedMatch = raw.match(/Decoded Payload:\s*([\s\S]+)$/i);
          const payload = (decodedMatch?.[1] || target || raw).trim();
          analysis = await analyzeQrPayloadWithReputation(payload, sensitivity);
        } else {
          const senderMatch = raw.match(/^Sender:\s*(.*)$/m);
          const subjectMatch = raw.match(/^Subject:\s*(.*)$/m);
          const sender = senderMatch && senderMatch[1] !== '(none)' ? senderMatch[1] : '';
          const subject = subjectMatch && subjectMatch[1] !== '(none)' ? subjectMatch[1] : '';
          const body = raw.replace(/^Sender:.*\nSubject:.*\n\n?/i, '').trim() || raw;
          analysis = await analyzeMessageWithReputation(
            scanType === 'sms' ? 'sms' : 'email',
            sender,
            subject,
            body,
            sensitivity
          );
        }

        return {
          id,
          riskScore: analysis.riskScore,
          heuristicScore: analysis.heuristicScore,
          riskLevel: analysis.riskLevel,
          submittedUrl:
            analysis.reputation.submittedUrl ||
            analysis.normalizedUrl ||
            analysis.extractedUrls[0] ||
            '',
          reputationStatus: analysis.reputation.status,
          reputationResult: analysis.reputation.resultLabel,
          reputationProvider: analysis.reputation.provider,
          reputationCheckedAt: analysis.reputation.checkedAt,
          threatCategories: analysis.reputation.threatCategories,
          reputationSummary: analysis.reputation.summary,
          scoreBreakdownSummary: analysis.scoreBreakdown
            .map((b) => `+${b.weight} ${b.label}: ${b.evidence}`)
            .join(' | '),
          mlProbability: analysis.mlPrediction.phishingProbability,
          mlSummary: analysis.mlPrediction.summary,
          verdictSummary: analysis.verdictSummary,
          indicators: analysis.indicators,
          recommendations: analysis.recommendations,
        };
      })
    );

    res.json({ updated });
  });

  app.post('/api/assistant/chat', async (req: Request, res: Response) => {
    const { messages, scanContext } = (req.body ?? {}) as {
      messages?: Array<{ role: 'user' | 'model'; text: string }>;
      scanContext?: {
        scanType?: string;
        targetPreview?: string;
        riskLevel?: string;
        riskScore?: number;
        indicators?: string[];
      };
    };

    if (!Array.isArray(messages) || messages.length === 0) {
      res.status(400).json({ error: 'Conversation messages are required.' });
      return;
    }

    const ai = createGeminiClientFromEnv();
    if (!ai) {
      res.status(503).json({
        error: 'AI explanation temporarily unavailable (Gemini API key is not configured on the server).',
        code: 'NOT_CONFIGURED',
      });
      return;
    }

    const contextBlock = scanContext
      ? `\n\nActive Scan Context Attached by User:\n- Type: ${scanContext.scanType}\n- Target: ${scanContext.targetPreview}\n- Risk Classification: ${scanContext.riskLevel} (${scanContext.riskScore}/100)\n- Indicators: ${(scanContext.indicators || []).join('; ')}`
      : '';

    const latestText = String(messages[messages.length - 1].text).slice(0, 4000);
    const requestId = createRequestId();
    const outcome = await executeGeminiWithRetry(
      async (signal) => {
        const chat = ai.chats.create({
          model: GEMINI_FLASH_MODEL,
          history: messages.slice(0, -1).map((m) => ({
            role: m.role === 'model' ? 'model' : 'user',
            parts: [{ text: String(m.text).slice(0, 4000) }],
          })),
          config: {
            abortSignal: signal,
            thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
            systemInstruction: `You are PhishShield AI Security Assistant, an expert phishing, smishing, quishing, and social-engineering defensive analyst.${contextBlock}\n\nSafety Rules:\n1. Never visit, fetch, or verify live external websites.\n2. Never tell a user an unknown URL or unverified sender is safe.\n3. Give clear, structured, actionable remediation advice (e.g., MFA checks, password rotation, session revocation, out-of-band verification).`,
          },
        });

        const response = await chat.sendMessage({
          message: latestText,
        });

        const reply = (response.text ?? '').trim();
        if (!reply) {
          const emptyErr = new Error('Gemini returned an empty chat response.');
          (emptyErr as Error & { status?: number }).status = 503;
          throw emptyErr;
        }
        return reply;
      },
      {
        requestId,
        operationName: 'assistant_chat',
        model: GEMINI_FLASH_MODEL,
        promptChars: latestText.length,
      }
    );

    if (!outcome.ok) {
      res.status(outcome.error.httpStatus).json({
        error: outcome.error.userMessage,
        code: outcome.error.code,
        requestId: outcome.requestId,
      });
      return;
    }

    res.json({
      reply: outcome.value,
      modelUsed: GEMINI_FLASH_MODEL,
      requestId: outcome.requestId,
      latencyMs: outcome.totalDurationMs,
    });
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`PhishShield AI server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start PhishShield AI server:', err);
  process.exit(1);
});
