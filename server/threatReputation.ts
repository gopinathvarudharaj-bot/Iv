import { sanitizeSecretText } from './geminiResilience.ts';

export type ReputationLabel =
  | 'Known Malicious'
  | 'No Known Threat Found'
  | 'Unknown / Unverified';

export type ReputationStatus =
  | 'confirmed_malicious'
  | 'no_known_threat'
  | 'unverified';

export type ReputationErrorCode =
  | 'NOT_CONFIGURED'
  | 'TIMEOUT'
  | 'RATE_LIMITED'
  | 'QUOTA_EXHAUSTED'
  | 'SERVICE_UNAVAILABLE'
  | 'INVALID_RESPONSE'
  | 'AUTH_ERROR'
  | 'NO_URL'
  | 'REQUEST_FAILED';

export interface ThreatReputationResult {
  status: ReputationStatus;
  resultLabel: ReputationLabel;
  statusLabel: string;
  provider: string;
  configured: boolean;
  checkedAt: string;
  submittedUrl?: string;
  matchedUrl?: string;
  threatCategories: string[];
  summary: string;
  isConfirmedMalicious: boolean;
  errorCode?: ReputationErrorCode;
  latencyMs?: number;
}

export interface SafeBrowsingMatch {
  threatType?: string;
  platformType?: string;
  threatEntryType?: string;
  threat?: { url?: string };
  cacheDuration?: string;
}

export interface SafeBrowsingApiResponse {
  matches?: SafeBrowsingMatch[];
}

export interface SafeBrowsingClientOptions {
  apiKey?: string;
  endpointUrl?: string;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
  nowFn?: () => Date;
}

export const GOOGLE_SAFE_BROWSING_PROVIDER = 'Google Safe Browsing API v4';
export const GOOGLE_SAFE_BROWSING_ENDPOINT =
  'https://safebrowsing.googleapis.com/v4/threatMatches:find';
export const DEFAULT_SAFE_BROWSING_TIMEOUT_MS = 8_000;

export function isSafeBrowsingConfigured(apiKey?: string): boolean {
  const key = (apiKey ?? process.env.GOOGLE_SAFE_BROWSING_API_KEY ?? '').trim();
  if (!key) return false;
  if (key === 'MY_GOOGLE_SAFE_BROWSING_API_KEY' || key === 'YOUR_API_KEY') {
    return false;
  }
  return true;
}

export function resolveSafeBrowsingTimeoutMs(overrideMs?: number): number {
  if (typeof overrideMs === 'number' && Number.isFinite(overrideMs) && overrideMs > 0) {
    return Math.round(overrideMs);
  }
  const raw = Number(process.env.GOOGLE_SAFE_BROWSING_TIMEOUT_MS);
  if (Number.isFinite(raw) && raw >= 500 && raw <= 30_000) {
    return Math.round(raw);
  }
  return DEFAULT_SAFE_BROWSING_TIMEOUT_MS;
}

export function buildUnconfiguredReputationResult(
  submittedUrl?: string,
  checkedAt: string = new Date().toISOString()
): ThreatReputationResult {
  return {
    status: 'unverified',
    resultLabel: 'Unknown / Unverified',
    statusLabel: 'Unknown / Unverified (Reputation Checking Not Configured)',
    provider: `${GOOGLE_SAFE_BROWSING_PROVIDER} (Not Configured)`,
    configured: false,
    checkedAt,
    submittedUrl,
    threatCategories: [],
    summary:
      'Threat reputation checking is not configured (GOOGLE_SAFE_BROWSING_API_KEY is missing on the server). Returning Unknown / Unverified without simulated results.',
    isConfirmedMalicious: false,
    errorCode: 'NOT_CONFIGURED',
  };
}

export function buildNoUrlReputationResult(
  configured: boolean,
  checkedAt: string = new Date().toISOString()
): ThreatReputationResult {
  return {
    status: 'unverified',
    resultLabel: 'Unknown / Unverified',
    statusLabel: 'Unknown / Unverified (No Inspectable URL)',
    provider: configured
      ? GOOGLE_SAFE_BROWSING_PROVIDER
      : `${GOOGLE_SAFE_BROWSING_PROVIDER} (Not Configured)`,
    configured,
    checkedAt,
    threatCategories: [],
    summary:
      'No external HTTP/HTTPS URL was present in the payload to query against Google Safe Browsing.',
    isConfirmedMalicious: false,
    errorCode: 'NO_URL',
  };
}

function normalizeThreatEntryUrl(rawUrl: string): string | null {
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed.href;
  } catch {
    return null;
  }
}

function buildErrorReputationResult(params: {
  submittedUrl: string;
  checkedAt: string;
  errorCode: ReputationErrorCode;
  statusLabel: string;
  summary: string;
  latencyMs: number;
}): ThreatReputationResult {
  return {
    status: 'unverified',
    resultLabel: 'Unknown / Unverified',
    statusLabel: params.statusLabel,
    provider: GOOGLE_SAFE_BROWSING_PROVIDER,
    configured: true,
    checkedAt: params.checkedAt,
    submittedUrl: params.submittedUrl,
    threatCategories: [],
    summary: sanitizeSecretText(params.summary),
    isConfirmedMalicious: false,
    errorCode: params.errorCode,
    latencyMs: params.latencyMs,
  };
}

export async function checkUrlsReputationWithSafeBrowsing(
  rawUrls: string[],
  options: SafeBrowsingClientOptions = {}
): Promise<ThreatReputationResult> {
  const nowFn = options.nowFn ?? (() => new Date());
  const checkedAt = nowFn().toISOString();
  const apiKey = (options.apiKey ?? process.env.GOOGLE_SAFE_BROWSING_API_KEY ?? '').trim();
  const configured = isSafeBrowsingConfigured(apiKey);

  const normalizedEntries = Array.from(
    new Set(rawUrls.map((u) => normalizeThreatEntryUrl(u)).filter((u): u is string => Boolean(u)))
  ).slice(0, 10);

  const primarySubmittedUrl = normalizedEntries[0] || rawUrls[0]?.trim() || undefined;

  if (!configured) {
    return buildUnconfiguredReputationResult(primarySubmittedUrl, checkedAt);
  }

  if (normalizedEntries.length === 0) {
    return buildNoUrlReputationResult(true, checkedAt);
  }

  const endpointUrl = options.endpointUrl ?? GOOGLE_SAFE_BROWSING_ENDPOINT;
  const timeoutMs = resolveSafeBrowsingTimeoutMs(options.timeoutMs);
  const fetchFn = options.fetchFn ?? fetch;
  const startedAt = Date.now();

  const requestBody = {
    client: {
      clientId: 'phishshield-ai',
      clientVersion: '1.0.0',
    },
    threatInfo: {
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION',
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: normalizedEntries.map((url) => ({ url })),
    },
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchFn(endpointUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': apiKey,
      },
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    });

    const latencyMs = Date.now() - startedAt;

    if (!response.ok) {
      const errorText = sanitizeSecretText(await response.text().catch(() => ''));
      const lower = errorText.toLowerCase();

      if (response.status === 429) {
        const isQuota = lower.includes('quota') || lower.includes('resource_exhausted');
        return buildErrorReputationResult({
          submittedUrl: primarySubmittedUrl || normalizedEntries[0],
          checkedAt,
          errorCode: isQuota ? 'QUOTA_EXHAUSTED' : 'RATE_LIMITED',
          statusLabel: isQuota
            ? 'Unknown / Unverified (API Quota Reached)'
            : 'Unknown / Unverified (API Rate Limited)',
          summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} ${isQuota ? 'quota limit' : 'rate limit'} reached (HTTP 429); URL reputation could not be verified.`,
          latencyMs,
        });
      }

      if (response.status === 401 || response.status === 403) {
        return buildErrorReputationResult({
          submittedUrl: primarySubmittedUrl || normalizedEntries[0],
          checkedAt,
          errorCode: 'AUTH_ERROR',
          statusLabel: 'Unknown / Unverified (Provider Authentication Error)',
          summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} rejected server credentials (HTTP ${response.status}); verify GOOGLE_SAFE_BROWSING_API_KEY configuration.`,
          latencyMs,
        });
      }

      if (response.status >= 500) {
        return buildErrorReputationResult({
          submittedUrl: primarySubmittedUrl || normalizedEntries[0],
          checkedAt,
          errorCode: 'SERVICE_UNAVAILABLE',
          statusLabel: 'Unknown / Unverified (Provider Temporarily Unavailable)',
          summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} returned HTTP ${response.status}; threat reputation remains Unknown / Unverified.`,
          latencyMs,
        });
      }

      return buildErrorReputationResult({
        submittedUrl: primarySubmittedUrl || normalizedEntries[0],
        checkedAt,
        errorCode: 'REQUEST_FAILED',
        statusLabel: `Unknown / Unverified (HTTP ${response.status})`,
        summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} lookup failed with HTTP ${response.status}; URL reputation remains Unknown / Unverified.`,
        latencyMs,
      });
    }

    let parsed: unknown;
    try {
      parsed = await response.json();
    } catch {
      return buildErrorReputationResult({
        submittedUrl: primarySubmittedUrl || normalizedEntries[0],
        checkedAt,
        errorCode: 'INVALID_RESPONSE',
        statusLabel: 'Unknown / Unverified (Invalid Provider Response)',
        summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} returned malformed JSON; URL reputation remains Unknown / Unverified.`,
        latencyMs,
      });
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return buildErrorReputationResult({
        submittedUrl: primarySubmittedUrl || normalizedEntries[0],
        checkedAt,
        errorCode: 'INVALID_RESPONSE',
        statusLabel: 'Unknown / Unverified (Invalid Provider Schema)',
        summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} returned an unexpected payload structure; URL reputation remains Unknown / Unverified.`,
        latencyMs,
      });
    }

    const body = parsed as SafeBrowsingApiResponse;
    if (body.matches !== undefined && !Array.isArray(body.matches)) {
      return buildErrorReputationResult({
        submittedUrl: primarySubmittedUrl || normalizedEntries[0],
        checkedAt,
        errorCode: 'INVALID_RESPONSE',
        statusLabel: 'Unknown / Unverified (Malformed Match List)',
        summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} returned an invalid matches field; URL reputation remains Unknown / Unverified.`,
        latencyMs,
      });
    }

    const matches = Array.isArray(body.matches) ? body.matches : [];
    if (matches.length > 0) {
      const threatCategories = Array.from(
        new Set(
          matches
            .map((m) => String(m?.threatType || '').trim())
            .filter(Boolean)
        )
      ).slice(0, 10);

      const matchedUrl =
        matches.find((m) => typeof m?.threat?.url === 'string')?.threat?.url ||
        primarySubmittedUrl ||
        normalizedEntries[0];

      return {
        status: 'confirmed_malicious',
        resultLabel: 'Known Malicious',
        statusLabel: 'Known Malicious (Google Safe Browsing Match)',
        provider: GOOGLE_SAFE_BROWSING_PROVIDER,
        configured: true,
        checkedAt,
        submittedUrl: primarySubmittedUrl || normalizedEntries[0],
        matchedUrl,
        threatCategories: threatCategories.length > 0 ? threatCategories : ['UNSPECIFIED_THREAT'],
        summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} reported active threat match(es) [${(threatCategories.length > 0 ? threatCategories : ['UNSPECIFIED_THREAT']).join(', ')}] for '${matchedUrl}'.`,
        isConfirmedMalicious: true,
        latencyMs,
      };
    }

    // Empty JSON {} means Google Safe Browsing found no threat match.
    // Never label the URL "Safe" — return "No Known Threat Found" with an explicit caveat.
    return {
      status: 'no_known_threat',
      resultLabel: 'No Known Threat Found',
      statusLabel: 'No Known Threat Found (Google Safe Browsing)',
      provider: GOOGLE_SAFE_BROWSING_PROVIDER,
      configured: true,
      checkedAt,
      submittedUrl: primarySubmittedUrl || normalizedEntries[0],
      threatCategories: [],
      summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} found no active threat match for '${primarySubmittedUrl || normalizedEntries[0]}'. No match does not guarantee the URL is safe; heuristic indicators and unverified domain risk remain separate.`,
      isConfirmedMalicious: false,
      latencyMs,
    };
  } catch (err) {
    const latencyMs = Date.now() - startedAt;
    const isAbort =
      err instanceof Error && (err.name === 'AbortError' || /timeout|timed out/i.test(err.message));

    if (isAbort) {
      return buildErrorReputationResult({
        submittedUrl: primarySubmittedUrl || normalizedEntries[0],
        checkedAt,
        errorCode: 'TIMEOUT',
        statusLabel: 'Unknown / Unverified (Lookup Timed Out)',
        summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} request timed out after ${timeoutMs}ms; URL reputation remains Unknown / Unverified.`,
        latencyMs,
      });
    }

    return buildErrorReputationResult({
      submittedUrl: primarySubmittedUrl || normalizedEntries[0],
      checkedAt,
      errorCode: 'SERVICE_UNAVAILABLE',
      statusLabel: 'Unknown / Unverified (Provider Unavailable)',
      summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} could not be reached (${sanitizeSecretText(
        err instanceof Error ? err.message : 'Network error'
      ).slice(0, 140)}); URL reputation remains Unknown / Unverified.`,
      latencyMs,
    });
  } finally {
    clearTimeout(timer);
  }
}

export async function checkUrlReputationWithSafeBrowsing(
  rawUrl: string,
  options: SafeBrowsingClientOptions = {}
): Promise<ThreatReputationResult> {
  return checkUrlsReputationWithSafeBrowsing([rawUrl], options);
}
