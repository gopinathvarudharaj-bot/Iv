import { BLUEPRINT_LIMITS, type RiskLevel, type ScanRecord } from '../types/phishshield';

export function clampString(val: string, max: number, fallback = ''): string {
  const trimmed = (val || '').trim();
  if (!trimmed) return fallback;
  return trimmed.slice(0, max);
}

export function clampStringArray(items: string[], maxItems: number, maxLen: number): string[] {
  return items
    .map((item) => clampString(String(item), maxLen))
    .filter(Boolean)
    .slice(0, maxItems);
}

export function redactSecretsInText(input: string): string {
  if (!input) return '';
  return (
    input
      // Never persist base64 or inline image payloads in Firestore
      .replace(/data:image\/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]+/gi, '[LOCAL_IMAGE_OMITTED]')
      // Redact Wi-Fi QR password fields: WIFI:T:WPA;S:Net;P:secret;;
      .replace(/(WIFI:[^;\n]*;[^;\n]*P:)([^;\n]+)/gi, '$1[REDACTED]')
      .replace(/(;P:)([^;\n]+)(;|$)/gi, '$1[REDACTED]$3')
      // Redact password in URL authority: https://user:secret@host
      .replace(/([a-z][a-z0-9+.-]*:\/\/[^/\s:@]+):([^@\s/]+)@/gi, '$1:[REDACTED]@')
      // Redact sensitive query parameters (tokens, passwords, OTPs, keys)
      .replace(
        /([?&](?:password|passwd|pwd|pass|token|access_token|id_token|refresh_token|auth|secret|api_key|apikey|key|otp|pin|cvv|ssn)=)([^&#\s]+)/gi,
        '$1[REDACTED]'
      )
  );
}

export function buildMinimizedMessageInputForStorage(params: {
  channel: 'email' | 'sms';
  bodyLength: number;
  extractedUrls: string[];
}): {
  targetPreview: string;
  rawInput: string;
  submittedUrl?: string;
} {
  const safeUrls = params.extractedUrls
    .map((u) => redactSecretsInText(u.trim()))
    .filter(Boolean)
    .slice(0, 5);
  const primaryUrl = safeUrls[0];
  let hostLabel = '';
  if (primaryUrl) {
    try {
      const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(primaryUrl)
        ? primaryUrl
        : `https://${primaryUrl}`;
      hostLabel = new URL(candidate).hostname || primaryUrl;
    } catch {
      hostLabel = primaryUrl.slice(0, 120);
    }
  }

  const tag = params.channel === 'sms' ? 'SMS' : 'EMAIL';
  const targetPreview = hostLabel
    ? `[${tag} Link] ${hostLabel}`.slice(0, BLUEPRINT_LIMITS.TARGET_PREVIEW_MAX)
    : `[${tag} Scan · Redacted Body]`;

  const rawInput = `[REDACTED_${tag}_META] len=${Math.max(0, Math.round(params.bodyLength))}; urls=${safeUrls.length}; primary=${primaryUrl || 'none'}`.slice(
    0,
    BLUEPRINT_LIMITS.RAW_INPUT_MAX
  );

  return {
    targetPreview,
    rawInput,
    submittedUrl: primaryUrl ? primaryUrl.slice(0, BLUEPRINT_LIMITS.SUBMITTED_URL_MAX) : undefined,
  };
}

export function sanitizeQrPayloadForStorage(decodedPayload: string): string {
  return redactSecretsInText(decodedPayload.trim()).slice(0, BLUEPRINT_LIMITS.RAW_INPUT_MAX);
}

export function normalizeRiskLevel(raw: unknown): RiskLevel {
  const val = String(raw || '').trim();
  if (val === 'Critical Risk') return 'High Risk';
  if (val === 'Unknown / Unverified') return 'Unknown/Unverified';
  if (
    val === 'Known Malicious' ||
    val === 'High Risk' ||
    val === 'Suspicious' ||
    val === 'No Known Threat Found' ||
    val === 'Unknown/Unverified'
  ) {
    return val;
  }
  return 'Unknown/Unverified';
}

export function buildScanRecordFirestorePayload(
  uid: string,
  id: string,
  input: Omit<ScanRecord, 'id' | 'userId' | 'createdAtMs' | 'updatedAtMs'>,
  timestamps: { createdAt: unknown; updatedAt: unknown }
): Record<string, unknown> {
  const safeTargetPreview = redactSecretsInText(input.targetPreview);
  let safeRawInput = redactSecretsInText(input.rawInput);

  // Enforce strict data minimization for Email/SMS: never persist raw message contents
  if (
    (input.scanType === 'email' || input.scanType === 'sms') &&
    !/^\[REDACTED_(EMAIL|SMS)_META\]/.test(safeRawInput.trim())
  ) {
    const minimized = buildMinimizedMessageInputForStorage({
      channel: input.scanType,
      bodyLength: safeRawInput.length,
      extractedUrls: input.submittedUrl ? [input.submittedUrl] : [],
    });
    safeRawInput = minimized.rawInput;
  }

  const payload: Record<string, unknown> = {
    id,
    userId: uid,
    scanType: input.scanType,
    targetPreview: clampString(
      safeTargetPreview,
      BLUEPRINT_LIMITS.TARGET_PREVIEW_MAX,
      'Scanned Target'
    ),
    rawInput: clampString(safeRawInput, BLUEPRINT_LIMITS.RAW_INPUT_MAX, 'Redacted Scan Input'),
    riskLevel: normalizeRiskLevel(input.riskLevel),
    riskScore: Math.max(0, Math.min(100, Math.round(input.riskScore))),
    verdictSummary: clampString(
      redactSecretsInText(input.verdictSummary),
      BLUEPRINT_LIMITS.VERDICT_SUMMARY_MAX,
      'Completed static analysis.'
    ),
    aiExplanation: clampString(
      redactSecretsInText(input.aiExplanation),
      BLUEPRINT_LIMITS.AI_EXPLANATION_MAX,
      ''
    ),
    indicators: clampStringArray(
      input.indicators.map((item) => redactSecretsInText(String(item))),
      BLUEPRINT_LIMITS.INDICATORS_MAX,
      BLUEPRINT_LIMITS.INDICATOR_ITEM_MAX
    ),
    recommendations: clampStringArray(
      input.recommendations,
      BLUEPRINT_LIMITS.RECOMMENDATIONS_MAX,
      BLUEPRINT_LIMITS.RECOMMENDATION_ITEM_MAX
    ),
    isDemoMode: Boolean(input.isDemoMode),
    archived: Boolean(input.archived),
    analystNote: clampString(
      redactSecretsInText(input.analystNote || ''),
      BLUEPRINT_LIMITS.ANALYST_NOTE_MAX,
      ''
    ),
    createdAt: timestamps.createdAt,
    updatedAt: timestamps.updatedAt,
  };

  if (typeof input.heuristicScore === 'number') {
    payload.heuristicScore = Math.max(0, Math.min(100, Math.round(input.heuristicScore)));
  }
  if (input.submittedUrl) {
    payload.submittedUrl = clampString(
      redactSecretsInText(input.submittedUrl),
      BLUEPRINT_LIMITS.SUBMITTED_URL_MAX
    );
  }
  if (input.reputationStatus) {
    payload.reputationStatus = clampString(
      input.reputationStatus,
      BLUEPRINT_LIMITS.REPUTATION_STATUS_MAX
    );
  }
  if (input.reputationResult) {
    const rawRep = input.reputationResult.trim();
    payload.reputationResult =
      rawRep === 'Known Malicious' ||
      rawRep === 'No Known Threat Found' ||
      rawRep === 'Unknown / Unverified'
        ? rawRep
        : 'Unknown / Unverified';
  }
  if (input.reputationProvider) {
    payload.reputationProvider = clampString(
      input.reputationProvider,
      BLUEPRINT_LIMITS.REPUTATION_PROVIDER_MAX
    );
  }
  if (input.reputationCheckedAt) {
    payload.reputationCheckedAt = clampString(
      input.reputationCheckedAt,
      BLUEPRINT_LIMITS.REPUTATION_CHECKED_AT_MAX
    );
  }
  if (Array.isArray(input.threatCategories)) {
    payload.threatCategories = clampStringArray(
      input.threatCategories,
      BLUEPRINT_LIMITS.THREAT_CATEGORIES_MAX,
      BLUEPRINT_LIMITS.THREAT_CATEGORY_ITEM_MAX
    );
  }
  if (input.reputationSummary) {
    payload.reputationSummary = clampString(
      redactSecretsInText(input.reputationSummary),
      BLUEPRINT_LIMITS.REPUTATION_SUMMARY_MAX
    );
  }
  if (input.scoreBreakdownSummary) {
    payload.scoreBreakdownSummary = clampString(
      redactSecretsInText(input.scoreBreakdownSummary),
      BLUEPRINT_LIMITS.SCORE_BREAKDOWN_SUMMARY_MAX
    );
  }
  if (typeof input.mlProbability === 'number') {
    payload.mlProbability = Math.max(0, Math.min(100, Math.round(input.mlProbability)));
  }
  if (input.mlSummary) {
    payload.mlSummary = clampString(input.mlSummary, BLUEPRINT_LIMITS.ML_SUMMARY_MAX);
  }

  return payload;
}
