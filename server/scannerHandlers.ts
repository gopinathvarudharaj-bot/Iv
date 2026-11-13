import { ThinkingLevel } from '@google/genai';
import {
  createGeminiClientFromEnv,
  createRequestId,
  executeGeminiWithRetry,
  GEMINI_FLASH_MODEL,
  generateGeminiExplanationWithClient,
  type HeuristicSummaryInput,
} from './geminiResilience.ts';
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
  type UpiPaymentDetails,
} from './urlRiskEngine.ts';
import {
  buildNoUrlReputationResult,
  checkUrlReputationWithSafeBrowsing,
  checkUrlsReputationWithSafeBrowsing,
  GOOGLE_SAFE_BROWSING_PROVIDER,
  isSafeBrowsingConfigured,
} from './threatReputation.ts';
import { analyzeQrPayloadWithReputation } from './qrRiskEngine.ts';

export type RiskLevel = RiskClassification;
export type Sensitivity = SensitivityLevel;

export interface HeuristicAnalysis {
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
  upiDetails?: UpiPaymentDetails;
}

export function extractUrlsFromText(text: string): string[] {
  const matches = text.match(/https?:\/\/[^\s"'<>()]+/gi) || [];
  const bareMatches =
    text.match(
      /\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|xyz|top|tk|ml|ga|cf|zip|mov|info|click|link|ru|cn|invalid)(?:\/[^\s"'<>()]*)?/gi
    ) || [];
  const combined = [...matches, ...bareMatches].map((u) => u.trim());
  return Array.from(new Set(combined)).slice(0, 12);
}

export async function analyzeUrlWithReputation(
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

export async function analyzeMessageWithReputation(
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

  const indicators = scoreBreakdown.map(
    (item) => `[+${item.weight} pts] ${item.label}: ${item.evidence}`
  );

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
      : `Static ${channel.toUpperCase()} analysis detected ${scoreBreakdown.length} social-engineering or link indicator(s), classifying this message as ${riskLevel}.`;

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
        impact:
          topUrlRes && topUrlRes.mlPrediction.phishingProbability >= 40
            ? 'increases_risk'
            : 'neutral',
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
        : [
            '[0 pts] No explicit scam keywords matched static heuristics (sender authenticity remains unverified).',
          ],
    scoreBreakdown,
    reputation: embeddedReputation,
    mlPrediction,
    recommendations,
    extractedUrls,
  };
}

export async function generateGeminiExplanation(
  mode: 'url' | 'email' | 'sms' | 'qr',
  rawInput: string,
  heuristics: HeuristicSummaryInput,
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

export async function handleHealthRequest(probeParam?: string, modelParam?: string) {
  const ai = createGeminiClientFromEnv();
  const base = {
    ok: true,
    geminiConfigured: Boolean(ai),
    geminiModel: GEMINI_FLASH_MODEL,
    reputationConfigured: isSafeBrowsingConfigured(),
    reputationProvider: GOOGLE_SAFE_BROWSING_PROVIDER,
  };

  if (probeParam !== '1') {
    return { status: 200, body: base };
  }

  if (!ai) {
    return {
      status: 503,
      body: {
        ...base,
        probe: {
          status: 'unavailable',
          code: 'NOT_CONFIGURED',
          message: 'GEMINI_API_KEY is not configured in server runtime.',
        },
      },
    };
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
    modelParam && ALLOWED_PROBE_MODELS.has(modelParam) ? modelParam : GEMINI_FLASH_MODEL;

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
    return {
      status: probeOutcome.error.httpStatus,
      body: {
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
      },
    };
  }

  return {
    status: 200,
    body: {
      ...base,
      probe: {
        status: 'ok',
        model: requestedModel,
        requestId: probeOutcome.requestId,
        latencyMs: probeOutcome.totalDurationMs,
        replyPreview: probeOutcome.value.slice(0, 40),
        availableModels,
      },
    },
  };
}

export async function handleRescoreScansRequest(body: unknown) {
  const { scans, sensitivity = 'standard' } = (body ?? {}) as {
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
    return { status: 400, body: { error: 'scans array is required.' } };
  }

  const updated = await Promise.all(
    scans.slice(0, 50).map(async (item) => {
      const id = String(item.id || '');
      const scanType = item.scanType || 'url';
      const target = String(item.targetPreview || item.rawInput || '').trim();
      const raw = String(item.rawInput || target).trim();

      if ((scanType === 'email' || scanType === 'sms') && raw.startsWith('[REDACTED_')) {
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
        const bodyText = raw.replace(/^Sender:.*\nSubject:.*\n\n?/i, '').trim() || raw;
        analysis = await analyzeMessageWithReputation(
          scanType === 'sms' ? 'sms' : 'email',
          sender,
          subject,
          bodyText,
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

  return { status: 200, body: { updated } };
}

export async function handleAssistantChatRequest(body: unknown) {
  const { messages, scanContext } = (body ?? {}) as {
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
    return { status: 400, body: { error: 'Conversation messages are required.' } };
  }

  const ai = createGeminiClientFromEnv();
  if (!ai) {
    return {
      status: 503,
      body: {
        error:
          'AI explanation temporarily unavailable (Gemini API key is not configured on the server).',
        code: 'NOT_CONFIGURED',
      },
    };
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
    return {
      status: outcome.error.httpStatus,
      body: {
        error: outcome.error.userMessage,
        code: outcome.error.code,
        requestId: outcome.requestId,
      },
    };
  }

  return {
    status: 200,
    body: {
      reply: outcome.value,
      modelUsed: GEMINI_FLASH_MODEL,
      requestId: outcome.requestId,
      latencyMs: outcome.totalDurationMs,
    },
  };
}

export async function handleAnalyzeUrlRequest(body: unknown) {
  const { url, sensitivity = 'standard', useAi = true } = (body ?? {}) as {
    url?: string;
    sensitivity?: Sensitivity;
    useAi?: boolean;
  };

  if (!url || typeof url !== 'string' || !url.trim()) {
    return { status: 400, body: { error: 'Please provide a URL string to inspect.' } };
  }

  const cleanUrl = url.trim().slice(0, 4000);
  const heuristics = await analyzeUrlWithReputation(cleanUrl, sensitivity);

  if (!useAi) {
    return {
      status: 200,
      body: {
        ...heuristics,
        aiExplanation:
          'AI explanation skipped per user preference. Deterministic heuristics applied without visiting the submitted URL.',
        aiStatus: 'skipped',
        modelUsed: GEMINI_FLASH_MODEL,
        isDemoMode: true,
        analyzedAt: new Date().toISOString(),
      },
    };
  }

  const aiRes = await generateGeminiExplanation('url', cleanUrl, heuristics);
  return {
    status: 200,
    body: {
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
    },
  };
}

export async function handleAnalyzeMessageRequest(body: unknown) {
  const {
    channel = 'email',
    sender = '',
    subject = '',
    content,
    sensitivity = 'standard',
    useAi = true,
  } = (body ?? {}) as {
    channel?: 'email' | 'sms';
    sender?: string;
    subject?: string;
    content?: string;
    sensitivity?: Sensitivity;
    useAi?: boolean;
  };

  if (!content || typeof content !== 'string' || !content.trim()) {
    return {
      status: 400,
      body: { error: 'Please paste an email or SMS message body to analyze.' },
    };
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
    return {
      status: 200,
      body: {
        ...heuristics,
        aiExplanation: 'AI explanation skipped per user preference. Deterministic heuristics applied.',
        aiStatus: 'skipped',
        modelUsed: GEMINI_FLASH_MODEL,
        isDemoMode: true,
        analyzedAt: new Date().toISOString(),
      },
    };
  }

  const context = `Channel: ${safeChannel.toUpperCase()} | Sender: ${cleanSender || '(not provided)'} | Subject: ${cleanSubject || '(not provided)'}`;
  const aiRes = await generateGeminiExplanation(safeChannel, cleanContent, heuristics, context);
  return {
    status: 200,
    body: {
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
    },
  };
}

export async function handleAnalyzeQrRequest(body: unknown) {
  const {
    decodedPayload,
    sourceFileName = '',
    sensitivity = 'standard',
    useAi = true,
  } = (body ?? {}) as {
    decodedPayload?: string;
    sourceFileName?: string;
    sensitivity?: Sensitivity;
    useAi?: boolean;
  };

  if (!decodedPayload || typeof decodedPayload !== 'string' || !decodedPayload.trim()) {
    return { status: 400, body: { error: 'No decoded QR payload provided.' } };
  }

  const cleanPayload = decodedPayload.trim().slice(0, 4000);
  const heuristics = await analyzeQrPayloadWithReputation(cleanPayload, sensitivity);

  if (!useAi) {
    return {
      status: 200,
      body: {
        ...heuristics,
        aiExplanation:
          'AI explanation skipped per user preference. Deterministic QR payload heuristics applied without visiting external links or initiating payments.',
        aiStatus: 'skipped',
        modelUsed: GEMINI_FLASH_MODEL,
        isDemoMode: true,
        analyzedAt: new Date().toISOString(),
      },
    };
  }

  const upiExtra = heuristics.upiDetails
    ? ` | UPI Payee: ${heuristics.upiDetails.payeeName} (${heuristics.upiDetails.payeeAddressMasked}) | Amount: ${heuristics.upiDetails.amountDisplay}`
    : '';
  const context = `${
    sourceFileName ? `Source QR image filename: ${sourceFileName.slice(0, 120)}` : 'Local QR Scan'
  }${upiExtra}`;
  const aiRes = await generateGeminiExplanation('qr', cleanPayload, heuristics, context);
  return {
    status: 200,
    body: {
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
    },
  };
}

export async function handleExplainRetryRequest(body: unknown) {
  const { mode, rawInput, heuristics, extraContext } = (body ?? {}) as {
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
    return { status: 400, body: { error: 'Invalid explanation retry payload.' } };
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

  return {
    status: 200,
    body: {
      aiExplanation: aiRes.explanation,
      aiStatus: aiRes.aiStatus,
      aiError: aiRes.aiError,
      aiErrorCode: aiRes.aiErrorCode,
      modelUsed: aiRes.modelUsed,
      requestId: aiRes.requestId,
      latencyMs: aiRes.latencyMs,
      analyzedAt: new Date().toISOString(),
    },
  };
}
