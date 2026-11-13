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
  isSafeBrowsingConfigured,
  type ThreatReputationResult,
} from './threatReputation.ts';

export interface QrRiskAnalysis {
  riskScore: number;
  heuristicScore: number;
  riskLevel: RiskClassification;
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

export type QrReputationChecker = (url: string) => Promise<ThreatReputationResult>;

const UPI_VPA_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}@[a-zA-Z0-9][a-zA-Z0-9.-]{1,63}$/;
const UPI_AMOUNT_REGEX = /^\d+(?:\.\d{1,2})?$/;
const UPI_LURE_TERMS = [
  'refund',
  'kyc',
  'prize',
  'lottery',
  'cashback claim',
  'claim reward',
  'verify account',
  'account blocked',
  'suspended',
  'customs',
  'penalty',
  'otp',
  'pin',
  'urgent',
  'helpdesk',
  'customer care',
  'unlock',
];

export function maskUpiAddress(rawPa: string): string {
  const trimmed = (rawPa || '').trim();
  if (!trimmed) return 'Missing';
  const atIndex = trimmed.indexOf('@');
  if (atIndex <= 0 || atIndex === trimmed.length - 1) {
    if (trimmed.length <= 3) return '***';
    return `${trimmed.slice(0, 2)}***${trimmed.slice(-1)}`;
  }

  const local = trimmed.slice(0, atIndex);
  const psp = trimmed.slice(atIndex + 1);
  if (/^\d{7,}$/.test(local)) {
    const maskLen = Math.max(4, local.length - 4);
    return `${local.slice(0, 2)}${'*'.repeat(maskLen)}${local.slice(-2)}@${psp}`;
  }
  if (local.length <= 2) {
    return `${local[0]}*@${psp}`;
  }
  if (local.length <= 4) {
    return `${local[0]}***@${psp}`;
  }
  return `${local.slice(0, 2)}***${local.slice(-2)}@${psp}`;
}

export function maskUpiReferenceId(rawRef: string): string {
  const trimmed = (rawRef || '').trim();
  if (!trimmed) return '';
  if (trimmed.length <= 6) return '***';
  return `${trimmed.slice(0, 2)}****${trimmed.slice(-4)}`;
}

function safeDecodeParam(value: string | null | undefined): string {
  if (!value) return '';
  try {
    return decodeURIComponent(value.replace(/\+/g, ' ')).trim();
  } catch {
    return value.trim();
  }
}

function parseUpiUri(trimmed: string): {
  action: string;
  params: Map<string, string>;
  hasQuerySyntaxError: boolean;
} {
  const withoutScheme = trimmed.replace(/^upi:\/\//i, '');
  const qIndex = withoutScheme.indexOf('?');
  const actionRaw = (qIndex === -1 ? withoutScheme : withoutScheme.slice(0, qIndex)).trim().toLowerCase();
  const action = actionRaw.replace(/\/+$/, '');
  const queryStr = qIndex === -1 ? '' : withoutScheme.slice(qIndex + 1);
  const params = new Map<string, string>();
  let hasQuerySyntaxError = false;

  if (queryStr) {
    for (const pair of queryStr.split('&')) {
      if (!pair) continue;
      const eqIdx = pair.indexOf('=');
      if (eqIdx === -1) {
        hasQuerySyntaxError = true;
        continue;
      }
      const key = safeDecodeParam(pair.slice(0, eqIdx)).toLowerCase();
      const val = safeDecodeParam(pair.slice(eqIdx + 1));
      if (!key) {
        hasQuerySyntaxError = true;
        continue;
      }
      params.set(key, val);
    }
  }

  return { action, params, hasQuerySyntaxError };
}

function extractUrlsFromQrText(text: string): string[] {
  const matches = text.match(/https?:\/\/[^\s"'<>()]+/gi) || [];
  return Array.from(new Set(matches.map((u) => u.trim()))).slice(0, 8);
}

function isLikelyHttpUrlOrDomain(trimmed: string): boolean {
  if (/^https?:\/\//i.test(trimmed)) return true;
  if (/^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[:/][^\s]*)?$/i.test(trimmed)) {
    const firstSegment = trimmed.split('/')[0].split(':')[0];
    // Reject obvious non-web tokens without valid TLD chars
    return /\.[a-z]{2,24}$/i.test(firstSegment);
  }
  return false;
}

function hasControlOrBinaryGarbage(input: string): boolean {
  return /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(input);
}

async function analyzeUpiQrPayload(
  trimmed: string,
  sensitivity: SensitivityLevel,
  reputationChecker: QrReputationChecker
): Promise<QrRiskAnalysis> {
  const { action, params, hasQuerySyntaxError } = parseUpiUri(trimmed);
  const rawPa = params.get('pa') || '';
  const rawPn = params.get('pn') || '';
  const rawAm = params.get('am') || '';
  const rawCu = (params.get('cu') || 'INR').toUpperCase();
  const rawTn = params.get('tn') || '';
  const rawMc = params.get('mc') || '';
  const rawTr = params.get('tr') || params.get('tid') || '';
  const rawEmbeddedUrl = params.get('url') || '';

  const scoreBreakdown: ScoreContribution[] = [];
  const warnings: string[] = [];

  const isStandardPayAction = action === 'pay';
  const hasValidPa = Boolean(rawPa && UPI_VPA_REGEX.test(rawPa) && !rawPa.includes('..'));

  if (!isStandardPayAction) {
    if (action === 'collect' || action === 'mandate') {
      scoreBreakdown.push({
        id: 'upi_collect_or_mandate',
        label: `UPI ${action.toUpperCase()} Request URI`,
        category: 'lure',
        weight: 38,
        evidence: `Payload uses upi://${action} instead of upi://pay; collect/mandate requests trigger pull or recurring debits and carry elevated abuse risk.`,
      });
      warnings.push(`Caution: upi://${action} request detected instead of standard upi://pay.`);
    } else {
      scoreBreakdown.push({
        id: 'upi_unknown_action',
        label: 'Malformed / Unrecognized UPI Action',
        category: 'structure',
        weight: 36,
        evidence: `Unrecognized UPI action path 'upi://${action || '(empty)'}' (expected 'upi://pay').`,
      });
      warnings.push('Unrecognized UPI URI action path.');
    }
  }

  if (!rawPa) {
    scoreBreakdown.push({
      id: 'upi_missing_pa',
      label: 'Missing Payee Address (pa)',
      category: 'structure',
      weight: 42,
      evidence: 'UPI payload omits the mandatory payee VPA (pa) parameter.',
    });
    warnings.push('Missing payee UPI address (pa).');
  } else if (!hasValidPa) {
    scoreBreakdown.push({
      id: 'upi_invalid_pa',
      label: 'Malformed Payee VPA Format (pa)',
      category: 'structure',
      weight: 40,
      evidence: `Payee address '${maskUpiAddress(rawPa)}' does not match valid NPCI UPI VPA syntax (handle@psp).`,
    });
    warnings.push('Malformed payee VPA address.');
  }

  let hasValidAmount = true;
  let numericAmount = 0;
  if (rawAm !== '') {
    if (!UPI_AMOUNT_REGEX.test(rawAm)) {
      hasValidAmount = false;
    } else {
      numericAmount = Number(rawAm);
      if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
        hasValidAmount = false;
      }
    }
    if (!hasValidAmount) {
      scoreBreakdown.push({
        id: 'upi_invalid_amount',
        label: 'Invalid Pre-Filled Payment Amount (am)',
        category: 'structure',
        weight: 34,
        evidence: `Amount parameter '${rawAm.slice(0, 32)}' is negative, zero, or malformed.`,
      });
      warnings.push('Malformed or invalid payment amount.');
    } else if (numericAmount >= 50000) {
      scoreBreakdown.push({
        id: 'upi_high_amount',
        label: 'High Pre-Filled Transaction Amount',
        category: 'lure',
        weight: 16,
        evidence: `Pre-filled amount (${rawCu} ${rawAm}) is high; verify recipient and invoice details carefully before authorizing.`,
      });
      warnings.push(`High pre-filled amount (${rawCu} ${rawAm}).`);
    }
  }

  if (rawCu && !/^[A-Z]{3}$/.test(rawCu)) {
    scoreBreakdown.push({
      id: 'upi_malformed_currency',
      label: 'Malformed Currency Code (cu)',
      category: 'structure',
      weight: 22,
      evidence: `Currency parameter '${rawCu.slice(0, 16)}' is not a valid 3-letter ISO currency code.`,
    });
    warnings.push('Malformed currency code.');
  } else if (rawCu && rawCu !== 'INR') {
    scoreBreakdown.push({
      id: 'upi_non_inr_currency',
      label: 'Non-INR Currency Parameter',
      category: 'structure',
      weight: 20,
      evidence: `UPI payload specifies unexpected currency '${rawCu}' instead of 'INR'.`,
    });
    warnings.push(`Unexpected currency code: ${rawCu}.`);
  }

  if (hasQuerySyntaxError) {
    scoreBreakdown.push({
      id: 'upi_malformed_query',
      label: 'Malformed UPI Query Parameter Syntax',
      category: 'structure',
      weight: 26,
      evidence: 'One or more query parameters inside the UPI URI are syntactically malformed.',
    });
    warnings.push('Malformed query syntax in UPI URI.');
  }

  if (!rawPn) {
    scoreBreakdown.push({
      id: 'upi_missing_pn',
      label: 'Payee Display Name (pn) Omitted',
      category: 'structure',
      weight: 8,
      evidence:
        'Payee name (pn) is omitted from the QR URI; confirm the registered banking name displayed inside your UPI app before paying.',
    });
    warnings.push('Payee name (pn) not embedded in QR.');
  }

  const lureCheckText = `${rawPn} ${rawTn}`.toLowerCase();
  const matchedLures = UPI_LURE_TERMS.filter((term) => lureCheckText.includes(term));
  if (matchedLures.length > 0) {
    scoreBreakdown.push({
      id: 'upi_social_lure',
      label: 'Suspicious Payment Lure Wording',
      category: 'lure',
      weight: 38,
      evidence: `Payee name or note contains scam-associated wording (${matchedLures.slice(0, 3).join(', ')}); UPI QR codes only send funds and never deposit refunds.`,
    });
    warnings.push(`Suspicious lure phrasing detected: ${matchedLures.slice(0, 2).join(', ')}.`);
  }

  if (rawMc && !/^\d{4}$/.test(rawMc)) {
    scoreBreakdown.push({
      id: 'upi_invalid_mc',
      label: 'Invalid Merchant Category Code (mc)',
      category: 'structure',
      weight: 14,
      evidence: `Merchant category code '${rawMc.slice(0, 16)}' is not a standard 4-digit MCC.`,
    });
    warnings.push('Non-standard merchant category code.');
  }

  // Evaluate any embedded external HTTP/HTTPS URL (parameter `url=` or URLs inside text notes)
  const candidateUrls = [
    ...(rawEmbeddedUrl ? [rawEmbeddedUrl] : []),
    ...extractUrlsFromQrText(trimmed),
  ].filter(Boolean);
  const uniqueUrls = Array.from(new Set(candidateUrls)).slice(0, 4);

  let embeddedReputation: ReputationResult = {
    ...buildNoUrlReputationResult(isSafeBrowsingConfigured()),
    source: buildNoUrlReputationResult(isSafeBrowsingConfigured()).provider,
  };
  let embeddedUrlThreat = false;

  if (uniqueUrls.length > 0) {
    const primaryEmbeddedUrl = uniqueUrls[0];
    const baseUrlAnalysis = analyzeUrlRisk(primaryEmbeddedUrl, sensitivity);
    const liveRepRaw = await reputationChecker(baseUrlAnalysis.normalizedUrl || primaryEmbeddedUrl);
    const mergedUrlAnalysis = applyReputationToAnalysis(baseUrlAnalysis, {
      ...liveRepRaw,
      source: liveRepRaw.provider,
    });
    embeddedReputation = mergedUrlAnalysis.reputation;

    if (mergedUrlAnalysis.reputation.isConfirmedMalicious || mergedUrlAnalysis.heuristicScore >= 22) {
      embeddedUrlThreat = true;
      scoreBreakdown.push(...mergedUrlAnalysis.scoreBreakdown);
      warnings.push(
        `Embedded URL (${mergedUrlAnalysis.normalizedHost || primaryEmbeddedUrl}) flagged as ${mergedUrlAnalysis.riskLevel}.`
      );
    }
  }

  const isCleanLegitUpi =
    isStandardPayAction &&
    hasValidPa &&
    hasValidAmount &&
    !hasQuerySyntaxError &&
    matchedLures.length === 0 &&
    !embeddedUrlThreat &&
    rawCu === 'INR' &&
    numericAmount < 50000;

  if (isCleanLegitUpi) {
    // Baseline verification weight: payment QRs require recipient/amount check even when well-formed
    scoreBreakdown.unshift({
      id: 'upi_verify_recipient_baseline',
      label: 'Valid UPI Payment URI – Verify Recipient',
      category: 'structure',
      weight: 10,
      evidence:
        'Recognized valid NPCI upi://pay format. No phishing or structural anomalies triggered, but payment QRs initiate real money transfers and require manual recipient/amount verification.',
    });
  }

  const rawScore = Math.min(100, scoreBreakdown.reduce((sum, item) => sum + item.weight, 0));
  const adjustedScore = isCleanLegitUpi
    ? rawScore
    : applySensitivityMultiplier(rawScore, sensitivity);
  const sensitivityDelta = adjustedScore - rawScore;
  if (sensitivityDelta > 0) {
    scoreBreakdown.push({
      id: 'sensitivity_multiplier',
      label: `Sensitivity Profile (${sensitivity})`,
      category: 'sensitivity',
      weight: sensitivityDelta,
      evidence: `Applied '${sensitivity}' heuristic sensitivity scaling (+${sensitivityDelta} pts).`,
    });
  }

  let riskLevel: RiskClassification;
  let riskScore: number;

  if (embeddedReputation.isConfirmedMalicious) {
    riskLevel = 'Known Malicious';
    riskScore = Math.max(95, adjustedScore);
  } else if (isCleanLegitUpi) {
    riskLevel = 'UPI Payment QR – Verify Recipient';
    riskScore = adjustedScore;
  } else {
    riskLevel = classifyFromScores({
      heuristicScore: adjustedScore,
      reputation: embeddedReputation,
    });
    riskScore = adjustedScore;
  }

  const maskedAddress = maskUpiAddress(rawPa);
  const payeeNameDisplay = rawPn || 'Not specified in QR';
  const amountDisplay = rawAm
    ? `${rawCu || 'INR'} ${rawAm}`
    : 'User-entered amount (not pre-filled)';

  const upiDetails: UpiPaymentDetails = {
    scheme: `upi://${action || 'unknown'}`,
    payeeName: payeeNameDisplay,
    payeeAddressMasked: maskedAddress,
    amountDisplay,
    rawAmount: rawAm || undefined,
    currency: rawCu || 'INR',
    transactionNote: rawTn ? rawTn.slice(0, 120) : undefined,
    merchantCode: rawMc || undefined,
    transactionRefMasked: rawTr ? maskUpiReferenceId(rawTr) : undefined,
    embeddedUrl: uniqueUrls[0],
    isValidUpiFormat: isStandardPayAction && hasValidPa && hasValidAmount && !hasQuerySyntaxError,
    warnings,
  };

  const indicators = scoreBreakdown.map(
    (item) => `[+${item.weight} pts] ${item.label}: ${item.evidence}`
  );

  const mlProb = isCleanLegitUpi
    ? Math.max(5, Math.min(18, rawPn ? 8 : 15))
    : Math.max(15, Math.min(96, adjustedScore));

  const mlPrediction: MlPredictionResult = {
    modelName: 'PhishShield-TS-QrFeature-v2 (TypeScript UPI & URI Scorer)',
    phishingProbability: mlProb,
    predictedLabel:
      mlProb >= 65
        ? 'Likely Phishing'
        : mlProb >= 25
          ? 'Suspicious Lexical Profile'
          : 'Low-Risk Lexical Profile',
    confidence: mlProb >= 75 || mlProb <= 15 ? 'High' : 'Medium',
    topFeatures: [
      {
        name: 'QR Payload Type',
        value: `upi://${action || 'unknown'}`,
        impact: isCleanLegitUpi ? 'neutral' : 'increases_risk',
      },
      {
        name: 'VPA Syntax Validation',
        value: hasValidPa ? 'Valid NPCI VPA format' : 'Invalid / Missing VPA',
        impact: hasValidPa ? 'neutral' : 'increases_risk',
      },
      {
        name: 'Pre-Filled Amount',
        value: amountDisplay,
        impact: !hasValidAmount || numericAmount >= 50000 ? 'increases_risk' : 'neutral',
      },
    ],
    summary: isCleanLegitUpi
      ? `Valid NPCI UPI payment URI (${mlProb}% phishing likelihood). Always verify the recipient and amount inside your UPI app before authorizing payment.`
      : `Detected ${warnings.length || 1} structural or social-engineering payment risk signal(s) (${mlProb}% suspicious likelihood).`,
  };

  const verdictSummary = isCleanLegitUpi
    ? `Valid UPI payment QR for '${payeeNameDisplay}' (${maskedAddress}, Amount: ${amountDisplay}). PhishShield AI cannot verify physical merchant authenticity offline—verify the recipient and amount in your UPI app before paying.`
    : `Suspicious or malformed UPI payment QR detected (${warnings.join(' ') || 'rule triggers fired'}), classified as ${riskLevel} (${riskScore}/100).`;

  const recommendations = isCleanLegitUpi
    ? [
        `Verify the payee name (${payeeNameDisplay}) and banking beneficiary displayed by your UPI app before entering your UPI PIN.`,
        `Confirm the masked payment address (${maskedAddress}) and exact amount (${amountDisplay}) match the merchant or biller.`,
        'Remember: scanning a UPI QR code only sends money—never scan a payment QR or enter your PIN to claim refunds, prizes, or KYC updates.',
        'PhishShield AI never opens links or initiates payments automatically, and cannot guarantee a physical QR sticker has not been swapped.',
      ]
    : [
        'Do NOT approve or authorize this UPI payment until you verify the recipient out-of-band.',
        'Be especially cautious of collect/mandate prompts or QR notes claiming refunds, prizes, or KYC verification.',
        'PhishShield AI does not initiate payments or visit embedded links.',
      ];

  return {
    riskScore,
    heuristicScore: adjustedScore,
    riskLevel,
    verdictSummary,
    indicators,
    scoreBreakdown,
    reputation: embeddedReputation,
    mlPrediction,
    recommendations,
    extractedUrls: uniqueUrls,
    upiDetails,
  };
}

export async function analyzeQrPayloadWithReputation(
  decodedPayload: string,
  sensitivity: SensitivityLevel = 'standard',
  reputationChecker: QrReputationChecker = checkUrlReputationWithSafeBrowsing
): Promise<QrRiskAnalysis> {
  const trimmed = (decodedPayload || '').trim();

  if (!trimmed || hasControlOrBinaryGarbage(trimmed)) {
    const breakdown: ScoreContribution[] = [
      {
        id: 'malformed_qr_payload',
        label: 'Invalid or Malformed QR Payload',
        category: 'structure',
        weight: 40,
        evidence: !trimmed
          ? 'Decoded QR payload is empty.'
          : 'Decoded QR payload contains invalid non-printable control characters or corrupted data.',
      },
    ];
    const adjusted = applySensitivityMultiplier(40, sensitivity);
    const noUrlRep = buildNoUrlReputationResult(isSafeBrowsingConfigured());
    const reputation: ReputationResult = { ...noUrlRep, source: noUrlRep.provider };
    const riskLevel = classifyFromScores({ heuristicScore: adjusted, reputation });
    return {
      riskScore: adjusted,
      heuristicScore: adjusted,
      riskLevel,
      verdictSummary: `Invalid or malformed QR payload detected (${adjusted}/100, ${riskLevel}).`,
      indicators: breakdown.map((b) => `[+${b.weight} pts] ${b.label}: ${b.evidence}`),
      scoreBreakdown: breakdown,
      reputation,
      mlPrediction: {
        modelName: 'PhishShield-TS-QrFeature-v2 (TypeScript UPI & URI Scorer)',
        phishingProbability: adjusted,
        predictedLabel: 'Suspicious Lexical Profile',
        confidence: 'Medium',
        topFeatures: [
          {
            name: 'Payload Integrity',
            value: 'Malformed / Unparseable',
            impact: 'increases_risk',
          },
        ],
        summary: `Malformed QR payload scored ${adjusted}% suspicious likelihood.`,
      },
      recommendations: [
        'Do not execute, open, or retry scanning corrupted or unexpected binary QR payloads.',
        'Re-scan only from a trusted physical source if a camera read error occurred.',
      ],
      extractedUrls: [],
    };
  }

  const lower = trimmed.toLowerCase();

  // 1. UPI Payment URIs
  if (lower.startsWith('upi://')) {
    return analyzeUpiQrPayload(trimmed, sensitivity, reputationChecker);
  }

  // 2. HTTP/HTTPS URLs or bare domains
  if (isLikelyHttpUrlOrDomain(trimmed)) {
    const baseUrlAnalysis = analyzeUrlRisk(trimmed, sensitivity);
    const liveRepRaw = await reputationChecker(baseUrlAnalysis.normalizedUrl || trimmed);
    const merged = applyReputationToAnalysis(baseUrlAnalysis, {
      ...liveRepRaw,
      source: liveRepRaw.provider,
    });

    const qrNote =
      'QR code URL decoded locally without visiting or opening the destination automatically.';
    return {
      ...merged,
      recommendations: [
        ...merged.recommendations,
        'Because QR codes hide the destination URL until scanned, always verify the full domain before opening it in a browser.',
      ],
      verdictSummary: `${merged.verdictSummary} (${qrNote})`,
    };
  }

  // 3. Other structured non-URL QR payloads (Crypto URIs, Wi-Fi auto-config, tel/sms/mailto, plain text)
  const scoreBreakdown: ScoreContribution[] = [];

  if (lower.startsWith('bitcoin:') || lower.startsWith('ethereum:')) {
    scoreBreakdown.push({
      id: 'qr_crypto_uri',
      label: 'Cryptocurrency Payment URI',
      category: 'lure',
      weight: 30,
      evidence:
        'Cryptocurrency transfer URI detected; crypto transfers are irreversible—verify the wallet address and amount out-of-band.',
    });
  } else if (lower.startsWith('wifi:')) {
    scoreBreakdown.push({
      id: 'qr_wifi_autoconfig',
      label: 'Wi-Fi Auto-Configuration QR',
      category: 'structure',
      weight: 26,
      evidence:
        'Wi-Fi auto-configuration payload detected; rogue QR Wi-Fi codes can route traffic through an attacker-controlled access point.',
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
  } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    // Unknown custom URI scheme or broken URL like http://[::bad
    const baseUrlAnalysis = analyzeUrlRisk(trimmed, sensitivity);
    const noUrlRep = buildNoUrlReputationResult(isSafeBrowsingConfigured());
    const reputation: ReputationResult = { ...noUrlRep, source: noUrlRep.provider };
    return {
      ...baseUrlAnalysis,
      reputation,
    };
  } else {
    scoreBreakdown.push({
      id: 'qr_plain_text',
      label: 'Plain-Text / Non-URL QR Payload',
      category: 'structure',
      weight: 0,
      evidence: 'Decoded QR contains plain text rather than an actionable web link or payment URI.',
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

  const embeddedUrls = extractUrlsFromQrText(trimmed);
  let reputation: ReputationResult = {
    ...buildNoUrlReputationResult(isSafeBrowsingConfigured()),
    source: buildNoUrlReputationResult(isSafeBrowsingConfigured()).provider,
  };
  if (embeddedUrls.length > 0) {
    const repRaw = await reputationChecker(embeddedUrls[0]);
    reputation = { ...repRaw, source: repRaw.provider };
  }

  const riskLevel = classifyFromScores({ heuristicScore: adjustedScore, reputation });
  const riskScore = reputation.isConfirmedMalicious ? Math.max(95, adjustedScore) : adjustedScore;
  const qrMlProb = Math.max(5, Math.min(95, Math.round(riskScore * 0.9)));

  const mlPrediction: MlPredictionResult = {
    modelName: 'PhishShield-TS-QrFeature-v2 (TypeScript UPI & URI Scorer)',
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
        value: trimmed.includes(':') ? trimmed.split(':')[0] : 'plain_text',
        impact: riskScore >= 25 ? 'increases_risk' : 'neutral',
      },
    ],
    summary: `Server-side TypeScript QR feature scorer estimates ${qrMlProb}% scam likelihood based on URI scheme and token structure.`,
  };

  const safePreview = trimmed
    .replace(/(WIFI:[^;\n]*;[^;\n]*P:)([^;\n]+)/gi, '$1[REDACTED]')
    .replace(/(;P:)([^;\n]+)(;|$)/gi, '$1[REDACTED]$3')
    .slice(0, 64);

  return {
    riskScore,
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
    extractedUrls: embeddedUrls,
  };
}
