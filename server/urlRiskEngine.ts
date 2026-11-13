import { domainToUnicode } from 'node:url';

export type RiskClassification =
  | 'Known Malicious'
  | 'High Risk'
  | 'Suspicious'
  | 'No Known Threat Found'
  | 'Unknown/Unverified';

export type SensitivityLevel = 'standard' | 'strict' | 'paranoid';

export type ReputationStatus = 'confirmed_malicious' | 'no_known_threat' | 'unverified';
export type ReputationLabel = 'Known Malicious' | 'No Known Threat Found' | 'Unknown / Unverified';

export interface ScoreContribution {
  id: string;
  label: string;
  category:
    | 'typosquatting'
    | 'homoglyph'
    | 'impersonation'
    | 'transport'
    | 'structure'
    | 'lure'
    | 'sensitivity';
  weight: number;
  evidence: string;
}

export interface ReputationResult {
  status: ReputationStatus;
  resultLabel: ReputationLabel;
  statusLabel: string;
  provider: string;
  source: string;
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

export interface HeuristicWeights {
  unencryptedHttp: number;
  ipAddressHost: number;
  obfuscatedIpHost: number;
  punycodeIdn: number;
  unicodeHomoglyph: number;
  atCredentialMask: number;
  deepSubdomain: number;
  riskyTld: number;
  urlShortener: number;
  typosquattingStrong: number;
  typosquattingModerate: number;
  homoglyphBrand: number;
  subdomainImpersonation: number;
  brandWithLureOrHyphen: number;
  multiLureTokens: number;
  hyphenatedAuthHost: number;
  nonStandardPort: number;
  longUrl: number;
  openRedirectParam: number;
  malformedUrl: number;
}

export interface UrlEngineConfig {
  protectedDomains: string[];
  knownMaliciousDomains: string[];
  weights: HeuristicWeights;
  thresholds: {
    suspiciousMin: number;
    highRiskMin: number;
  };
}

export interface NormalizedUrlParts {
  normalizedUrl: string;
  scheme: string;
  username: string;
  rawHost: string;
  parsedHost: string;
  normalizedHost: string;
  registrableDomain: string;
  subdomain: string;
  primaryLabel: string;
  labels: string[];
  port: string;
  pathAndQuery: string;
  hadObfuscatedHost: boolean;
  validSyntax: boolean;
}

export interface UrlRiskAnalysis {
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
  normalizedUrl: string;
  parsedHost: string;
  normalizedHost: string;
  registrableDomain: string;
}

export const DEFAULT_PROTECTED_DOMAINS: string[] = [
  'google.com',
  'youtube.com',
  'gmail.com',
  'microsoft.com',
  'live.com',
  'outlook.com',
  'office.com',
  'apple.com',
  'icloud.com',
  'amazon.com',
  'paypal.com',
  'netflix.com',
  'facebook.com',
  'instagram.com',
  'whatsapp.com',
  'linkedin.com',
  'github.com',
  'twitter.com',
  'chase.com',
  'bankofamerica.com',
  'wellsfargo.com',
  'citibank.com',
  'coinbase.com',
  'binance.com',
  'stripe.com',
  'dropbox.com',
  'adobe.com',
  'fedex.com',
  'usps.com',
  'dhl.com',
];

export const DEFAULT_HEURISTIC_WEIGHTS: HeuristicWeights = {
  unencryptedHttp: 20,
  ipAddressHost: 42,
  obfuscatedIpHost: 24,
  punycodeIdn: 36,
  unicodeHomoglyph: 44,
  atCredentialMask: 40,
  deepSubdomain: 16,
  riskyTld: 22,
  urlShortener: 24,
  typosquattingStrong: 58,
  typosquattingModerate: 46,
  homoglyphBrand: 60,
  subdomainImpersonation: 48,
  brandWithLureOrHyphen: 44,
  multiLureTokens: 24,
  hyphenatedAuthHost: 14,
  nonStandardPort: 22,
  longUrl: 12,
  openRedirectParam: 14,
  malformedUrl: 32,
};

export function resolveConfiguredProtectedDomains(): string[] {
  const envList = process.env.PHISHSHIELD_PROTECTED_DOMAINS;
  if (!envList || !envList.trim()) {
    return DEFAULT_PROTECTED_DOMAINS;
  }
  const parsed = envList
    .split(',')
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
  return parsed.length > 0 ? Array.from(new Set(parsed)) : DEFAULT_PROTECTED_DOMAINS;
}

export const DEFAULT_URL_ENGINE_CONFIG: UrlEngineConfig = {
  protectedDomains: DEFAULT_PROTECTED_DOMAINS,
  knownMaliciousDomains: [],
  weights: DEFAULT_HEURISTIC_WEIGHTS,
  thresholds: {
    suspiciousMin: 22,
    highRiskMin: 55,
  },
};

const MULTI_PART_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.jp',
  'co.nz',
  'com.br',
  'co.in',
  'com.sg',
  'co.za',
]);

const RISKY_TLDS = [
  '.zip',
  '.mov',
  '.tk',
  '.ml',
  '.ga',
  '.cf',
  '.gq',
  '.xyz',
  '.top',
  '.click',
  '.work',
  '.cfd',
  '.rest',
];

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'rb.gy',
  'is.gd',
  'cutt.ly',
  'ow.ly',
  'shorturl.at',
]);

const LURE_KEYWORDS = [
  'login',
  'verify',
  'secure',
  'update',
  'signin',
  'wallet',
  'suspend',
  'unlock',
  'confirm',
  'sso',
  'mfa',
  'reset',
  'account',
  'auth',
];

const RESERVED_NON_BRAND_DOMAINS = new Set([
  'example.com',
  'example.org',
  'example.net',
  'localhost',
]);

const UNICODE_CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a',
  е: 'e',
  ё: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  у: 'y',
  х: 'x',
  і: 'i',
  ј: 'j',
  к: 'k',
  м: 'm',
  н: 'h',
  т: 't',
  в: 'b',
  ѕ: 's',
  п: 'n',
  // Greek
  α: 'a',
  β: 'b',
  ε: 'e',
  ι: 'i',
  κ: 'k',
  ν: 'v',
  ο: 'o',
  ρ: 'p',
  τ: 't',
  υ: 'u',
  χ: 'x',
  // Latin lookalikes
  ı: 'i',
  ſ: 's',
};

export function normalizeHostname(rawHost: string): string {
  const cleaned = rawHost
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[\u3002\uFF0E\uFF61]/g, '.')
    .trim()
    .toLowerCase()
    .replace(/\.+$/, '')
    .normalize('NFKC');
  const unicodeHost = cleaned.includes('xn--') ? domainToUnicode(cleaned) || cleaned : cleaned;
  return unicodeHost.replace(/^(www|m)\./, '');
}

export function extractRegistrableDomain(normalizedHost: string): {
  registrableDomain: string;
  subdomain: string;
  primaryLabel: string;
  labels: string[];
} {
  const clean = normalizedHost.replace(/\.+$/, '');
  const labels = clean.split('.').filter(Boolean);

  if (labels.length <= 1) {
    return {
      registrableDomain: clean,
      subdomain: '',
      primaryLabel: labels[0] || '',
      labels,
    };
  }

  const lastTwo = `${labels[labels.length - 2]}.${labels[labels.length - 1]}`;
  const suffixParts = MULTI_PART_SUFFIXES.has(lastTwo) && labels.length >= 3 ? 3 : 2;
  const regLabels = labels.slice(labels.length - suffixParts);
  const subLabels = labels.slice(0, labels.length - suffixParts);

  return {
    registrableDomain: regLabels.join('.'),
    subdomain: subLabels.join('.'),
    primaryLabel: regLabels[0] || '',
    labels,
  };
}

export function normalizeUrlInput(rawUrl: string): NormalizedUrlParts {
  const sanitized = rawUrl
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[\u3002\uFF0E\uFF61]/g, '.')
    .trim()
    .replace(/^(https?):\\+/i, '$1://');

  const withScheme = sanitized.startsWith('//')
    ? `https:${sanitized}`
    : /^[a-z][a-z0-9+.-]*:\/\//i.test(sanitized)
      ? sanitized
      : `https://${sanitized}`;

  const rawAuthorityMatch = withScheme.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^/?#@]*@)?([^/?#:]+)/i);
  const rawHostToken = (rawAuthorityMatch?.[1] || '').toLowerCase();

  try {
    const parsed = new URL(withScheme);
    const parsedHost = parsed.hostname.toLowerCase().replace(/\.+$/, '');
    const normalizedHost = normalizeHostname(parsedHost);
    const domainParts = extractRegistrableDomain(normalizedHost);
    const hadObfuscatedHost =
      Boolean(rawHostToken) &&
      (rawHostToken.includes('%') ||
        (/^(\d{1,3}(\.\d{1,3}){3}|\[.+\])$/.test(parsedHost) &&
          rawHostToken.replace(/\.+$/, '') !== parsedHost));

    return {
      normalizedUrl: `${parsed.protocol}//${normalizedHost}${parsed.port ? `:${parsed.port}` : ''}${parsed.pathname}${parsed.search}`,
      scheme: parsed.protocol,
      username: decodeURIComponent(parsed.username || '').toLowerCase(),
      rawHost: rawHostToken,
      parsedHost,
      normalizedHost,
      registrableDomain: domainParts.registrableDomain,
      subdomain: domainParts.subdomain,
      primaryLabel: domainParts.primaryLabel,
      labels: domainParts.labels,
      port: parsed.port,
      pathAndQuery: `${parsed.pathname}${parsed.search}`,
      hadObfuscatedHost,
      validSyntax: true,
    };
  } catch {
    return {
      normalizedUrl: sanitized,
      scheme: /^http:\/\//i.test(sanitized) ? 'http:' : 'https:',
      username: '',
      rawHost: rawHostToken,
      parsedHost: '',
      normalizedHost: '',
      registrableDomain: '',
      subdomain: '',
      primaryLabel: '',
      labels: [],
      port: '',
      pathAndQuery: '',
      hadObfuscatedHost: false,
      validSyntax: false,
    };
  }
}

export function collapseRepeatedChars(input: string): string {
  return input.replace(/(.)\1+/g, '$1');
}

export function normalizeHomoglyphs(input: string): {
  asciiSkeleton: string;
  hadUnicodeConfusables: boolean;
  hadAsciiLeet: boolean;
} {
  const nfd = input.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  let hadUnicodeConfusables = false;
  let mapped = '';

  for (const ch of nfd) {
    if (UNICODE_CONFUSABLES[ch]) {
      mapped += UNICODE_CONFUSABLES[ch];
      hadUnicodeConfusables = true;
    } else {
      if (ch.charCodeAt(0) > 127) {
        hadUnicodeConfusables = true;
      }
      mapped += ch;
    }
  }

  const beforeLeet = mapped;
  const leetReplaced = mapped
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/8/g, 'b')
    .replace(/\$/g, 's')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');

  return {
    asciiSkeleton: leetReplaced,
    hadUnicodeConfusables,
    hadAsciiLeet: leetReplaced !== beforeLeet,
  };
}

export function damerauLevenshtein(a: string, b: string): number {
  const lenA = a.length;
  const lenB = b.length;
  if (lenA === 0) return lenB;
  if (lenB === 0) return lenA;

  const dp: number[][] = Array.from({ length: lenA + 1 }, () => new Array(lenB + 1).fill(0));
  for (let i = 0; i <= lenA; i += 1) dp[i][0] = i;
  for (let j = 0; j <= lenB; j += 1) dp[0][j] = j;

  for (let i = 1; i <= lenA; i += 1) {
    for (let j = 1; j <= lenB; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let val = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        val = Math.min(val, dp[i - 2][j - 2] + cost);
      }
      dp[i][j] = val;
    }
  }

  return dp[lenA][lenB];
}

function classifyEditOperation(candidate: string, brand: string, dist: number): string {
  if (dist === 0) return 'exact';
  if (candidate.length > brand.length) return 'character insertion';
  if (candidate.length < brand.length) return 'character deletion';
  if (dist === 1) {
    for (let i = 0; i < candidate.length - 1; i += 1) {
      if (
        candidate[i] !== brand[i] &&
        candidate[i] === brand[i + 1] &&
        candidate[i + 1] === brand[i]
      ) {
        return 'character transposition';
      }
    }
  }
  return 'character substitution';
}

export function applySensitivityMultiplier(score: number, sensitivity: SensitivityLevel): number {
  if (sensitivity === 'strict') return Math.min(100, Math.round(score * 1.15));
  if (sensitivity === 'paranoid') return Math.min(100, Math.round(score * 1.3));
  return Math.min(100, Math.round(score));
}

export function evaluateDomainReputation(
  _registrableDomain: string,
  _normalizedHost: string,
  _config: UrlEngineConfig = DEFAULT_URL_ENGINE_CONFIG,
  submittedUrl?: string
): ReputationResult {
  // Heuristic engine never synthesizes fake or hardcoded threat reputation results.
  // Live reputation is populated exclusively by the server-side threat reputation provider.
  return {
    status: 'unverified',
    resultLabel: 'Unknown / Unverified',
    statusLabel: 'Unknown / Unverified (Reputation Not Checked)',
    provider: 'Google Safe Browsing API v4 (Pending / Not Configured)',
    source: 'Google Safe Browsing API v4',
    configured: false,
    checkedAt: new Date().toISOString(),
    submittedUrl,
    threatCategories: [],
    summary:
      'Live threat reputation has not been verified by an external threat intelligence provider.',
    isConfirmedMalicious: false,
  };
}

export function classifyFromScores(params: {
  heuristicScore: number;
  reputation: Pick<ReputationResult, 'status' | 'resultLabel' | 'isConfirmedMalicious'>;
  thresholds?: UrlEngineConfig['thresholds'];
}): RiskClassification {
  const thresholds = params.thresholds ?? DEFAULT_URL_ENGINE_CONFIG.thresholds;
  if (
    params.reputation.isConfirmedMalicious ||
    params.reputation.resultLabel === 'Known Malicious' ||
    params.reputation.status === 'confirmed_malicious'
  ) {
    return 'Known Malicious';
  }
  if (params.heuristicScore >= thresholds.highRiskMin) {
    return 'High Risk';
  }
  if (params.heuristicScore >= thresholds.suspiciousMin) {
    return 'Suspicious';
  }
  if (
    params.reputation.resultLabel === 'No Known Threat Found' ||
    params.reputation.status === 'no_known_threat'
  ) {
    return 'No Known Threat Found';
  }
  return 'Unknown/Unverified';
}

interface TyposquatMatch {
  brandDomain: string;
  brandLabel: string;
  kind: 'homoglyph' | 'repetition' | 'edit_distance' | 'subdomain_spoof' | 'brand_lure';
  editType?: string;
  distance: number;
  detail: string;
}

function detectBrandTyposquatting(
  registrableDomain: string,
  primaryLabel: string,
  subdomain: string,
  username: string,
  config: UrlEngineConfig
): TyposquatMatch[] {
  const matches: TyposquatMatch[] = [];
  const protectedSet = new Set(config.protectedDomains.map((d) => normalizeHostname(d)));

  // Exact official registrable domain is NOT a lookalike
  if (protectedSet.has(registrableDomain)) {
    return matches;
  }

  const isReservedDocDomain = RESERVED_NON_BRAND_DOMAINS.has(registrableDomain);
  const { asciiSkeleton, hadUnicodeConfusables, hadAsciiLeet } = normalizeHomoglyphs(primaryLabel);
  const candidateCollapsed = collapseRepeatedChars(primaryLabel);
  const skeletonCollapsed = collapseRepeatedChars(asciiSkeleton);

  const seenBrands = new Set<string>();

  for (const protectedDomainRaw of config.protectedDomains) {
    const protectedDomain = normalizeHostname(protectedDomainRaw);
    const { primaryLabel: brandLabel } = extractRegistrableDomain(protectedDomain);
    if (!brandLabel || seenBrands.has(brandLabel)) continue;

    // 1. Subdomain or userinfo impersonation (e.g., google.com.evil.xyz or google.com@evil.xyz)
    if (subdomain || username) {
      const subTokens = `${subdomain}.${username}`.split(/[.-]+/).filter(Boolean);
      if (
        subdomain === protectedDomain ||
        subdomain.endsWith(`.${protectedDomain}`) ||
        username.includes(protectedDomain) ||
        (brandLabel.length >= 4 && subTokens.includes(brandLabel))
      ) {
        seenBrands.add(brandLabel);
        matches.push({
          brandDomain: protectedDomain,
          brandLabel,
          kind: 'subdomain_spoof',
          distance: 0,
          detail: `Protected brand '${protectedDomain}' appears inside subdomain/userinfo ('${subdomain || username}') while the true registrable domain is '${registrableDomain}'.`,
        });
        continue;
      }
    }

    if (isReservedDocDomain) continue;

    // 2. Homoglyph / leetspeak / Unicode confusable match
    const leetAlt = asciiSkeleton.replace(/1/g, 'i');
    if (
      (hadUnicodeConfusables || hadAsciiLeet) &&
      (asciiSkeleton === brandLabel || leetAlt === brandLabel)
    ) {
      seenBrands.add(brandLabel);
      matches.push({
        brandDomain: protectedDomain,
        brandLabel,
        kind: 'homoglyph',
        editType: 'homoglyph substitution',
        distance: damerauLevenshtein(primaryLabel, brandLabel),
        detail: `Hostname label '${primaryLabel}' uses visual character/homoglyph substitution mimicking protected domain '${protectedDomain}'.`,
      });
      continue;
    }

    // 3. Repeated-character insertion/elongation (e.g., googggle -> google)
    const brandCollapsed = collapseRepeatedChars(brandLabel);
    if (
      brandLabel.length >= 4 &&
      primaryLabel !== brandLabel &&
      (candidateCollapsed === brandCollapsed ||
        ((hadUnicodeConfusables || hadAsciiLeet) && skeletonCollapsed === brandCollapsed))
    ) {
      const dist = damerauLevenshtein(primaryLabel, brandLabel);
      const editType = classifyEditOperation(primaryLabel, brandLabel, dist);
      seenBrands.add(brandLabel);
      matches.push({
        brandDomain: protectedDomain,
        brandLabel,
        kind: 'repetition',
        editType,
        distance: dist,
        detail: `Hostname '${registrableDomain}' uses ${editType} (repeated characters) to mimic protected domain '${protectedDomain}' (edit distance ${dist}).`,
      });
      continue;
    }

    // 4. Damerau-Levenshtein edit distance (insertion, deletion, substitution, transposition)
    if (brandLabel.length >= 4 && primaryLabel !== brandLabel) {
      const dist = damerauLevenshtein(primaryLabel, brandLabel);
      const distSkeleton = damerauLevenshtein(asciiSkeleton, brandLabel);
      const bestDist = Math.min(dist, distSkeleton);

      const isStrongEditMatch =
        (brandLabel.length >= 5 && bestDist === 1) ||
        (brandLabel.length >= 6 &&
          bestDist === 2 &&
          (primaryLabel[0] === brandLabel[0] || primaryLabel.at(-1) === brandLabel.at(-1)) &&
          Math.abs(primaryLabel.length - brandLabel.length) <= 2);

      if (isStrongEditMatch) {
        const editType = classifyEditOperation(primaryLabel, brandLabel, bestDist);
        seenBrands.add(brandLabel);
        matches.push({
          brandDomain: protectedDomain,
          brandLabel,
          kind: 'edit_distance',
          editType,
          distance: bestDist,
          detail: `Hostname label '${primaryLabel}' matches '${protectedDomain}' via ${editType} (Damerau-Levenshtein distance ${bestDist}).`,
        });
        continue;
      }
    }

    // 5. Brand token embedded with hyphens/lures in registrable label
    if (
      brandLabel.length >= 4 &&
      primaryLabel !== brandLabel &&
      (primaryLabel.includes(brandLabel) || asciiSkeleton.includes(brandLabel))
    ) {
      const hasSeparatorOrLure =
        primaryLabel.includes('-') ||
        LURE_KEYWORDS.some((kw) => primaryLabel.includes(kw));
      if (hasSeparatorOrLure) {
        seenBrands.add(brandLabel);
        matches.push({
          brandDomain: protectedDomain,
          brandLabel,
          kind: 'brand_lure',
          distance: damerauLevenshtein(primaryLabel, brandLabel),
          detail: `Registrable label '${primaryLabel}' embeds protected brand '${brandLabel}' alongside hyphenation or authentication lure tokens.`,
        });
      }
    }
  }

  return matches;
}

function shannonEntropy(input: string): number {
  if (!input) return 0;
  const counts = new Map<string, number>();
  for (const ch of input) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function maxConsecutiveRepeat(input: string): number {
  let maxRun = 1;
  let currentRun = 1;
  for (let i = 1; i < input.length; i += 1) {
    if (input[i] === input[i - 1]) {
      currentRun += 1;
      if (currentRun > maxRun) maxRun = currentRun;
    } else {
      currentRun = 1;
    }
  }
  return input ? maxRun : 0;
}

export function predictUrlLexicalMl(params: {
  rawUrl?: string;
  parts: NormalizedUrlParts;
  typoMatches: TyposquatMatch[];
  hostLuresCount: number;
  fullLuresCount: number;
  isRiskyTld: boolean;
  isUrlShortener?: boolean;
  isIpHost: boolean;
  isHttp: boolean;
  hasAtMask: boolean;
}): MlPredictionResult {
  const {
    rawUrl,
    parts,
    typoMatches,
    hostLuresCount,
    fullLuresCount,
    isRiskyTld,
    isUrlShortener = false,
    isIpHost,
    isHttp,
    hasAtMask,
  } = params;
  const inspectedUrl = (rawUrl || parts.normalizedUrl || '').trim();
  const label = parts.primaryLabel || parts.normalizedHost;
  const entropy = Number(shannonEntropy(parts.normalizedHost || label).toFixed(2));
  const hyphenCount = (parts.normalizedHost.match(/-/g) || []).length;
  const urlDigitCount = (inspectedUrl.match(/\d/g) || []).length;
  const hostDigitCount = (parts.normalizedHost.match(/\d/g) || []).length;
  const hostDigitRatio = parts.normalizedHost
    ? Number((hostDigitCount / parts.normalizedHost.length).toFixed(3))
    : 0;
  const maxRepeat = maxConsecutiveRepeat(label);
  const dotCount = (parts.parsedHost.match(/\./g) || []).length;
  const subdomainCount = parts.subdomain
    ? parts.subdomain.split('.').filter(Boolean).length
    : 0;

  const queryIdx = parts.pathAndQuery.indexOf('?');
  const pathPart = queryIdx >= 0 ? parts.pathAndQuery.slice(0, queryIdx) : parts.pathAndQuery;
  const queryPart = queryIdx >= 0 ? parts.pathAndQuery.slice(queryIdx + 1) : '';

  const isHttps = parts.scheme === 'https:' && !isHttp ? 1 : 0;
  const hasNonStandardPort = parts.port && !['80', '443'].includes(parts.port) ? 1 : 0;
  const isPunycodeOrIdn =
    parts.parsedHost.includes('xn--') || /[^\x00-\x7f]/.test(parts.parsedHost) ? 1 : 0;
  const suspiciousChars = inspectedUrl.match(/[@%;=\\~!$*?&]/g) || [];
  const hasDoubleSlashRedirect =
    parts.pathAndQuery.includes('//') || /redirect=|next=|url=/i.test(parts.pathAndQuery) ? 1 : 0;

  const hasBrandProximity = typoMatches.length > 0 ? 1 : 0;
  const hasHomoglyphFeature =
    typoMatches.some((m) => m.kind === 'homoglyph') || isPunycodeOrIdn === 1 ? 1 : 0;

  const extractedFeatures: UrlExtractedFeatures = {
    urlLength: inspectedUrl.length,
    hostnameLength: parts.normalizedHost.length,
    pathLength: pathPart.length,
    queryLength: queryPart.length,
    subdomainCount,
    dotCount,
    hostHyphenCount: hyphenCount,
    urlDigitCount,
    hostDigitRatio,
    hasIpAddress: isIpHost ? 1 : 0,
    hasNonStandardPort,
    isHttps,
    isPunycodeOrIdn,
    suspiciousCharCount: suspiciousChars.length,
    hasAtSymbol: hasAtMask ? 1 : 0,
    hasDoubleSlashRedirect,
    hostLureKeywordCount: hostLuresCount,
    totalLureKeywordCount: fullLuresCount,
    isUrlShortener: isUrlShortener ? 1 : 0,
    hasRiskyTld: isRiskyTld ? 1 : 0,
    hostnameEntropy: entropy,
    maxConsecutiveRepeat: maxRepeat,
    brandTyposquatMatch: hasBrandProximity,
  };

  // Transparent deterministic TypeScript feature-scoring model (no external Python server or fabricated ML)
  let logit = -3.15;
  logit += hasBrandProximity * 3.1;
  logit += hasHomoglyphFeature * 1.4;
  logit += maxRepeat >= 3 ? 1.5 : 0;
  logit += Math.min(3, hostLuresCount) * 0.95;
  logit += Math.min(3, Math.max(0, fullLuresCount - hostLuresCount)) * 0.35;
  logit += Math.min(4, hyphenCount) * 0.45;
  logit += hostDigitRatio * 2.2;
  logit += entropy > 3.6 ? (entropy - 3.6) * 0.9 : 0;
  logit += isRiskyTld ? 1.25 : 0;
  logit += isUrlShortener ? 1.15 : 0;
  logit += isIpHost ? 2.4 : 0;
  logit += hasNonStandardPort ? 0.95 : 0;
  logit += isHttp ? 0.9 : 0;
  logit += hasAtMask ? 1.8 : 0;
  logit += hasDoubleSlashRedirect ? 0.65 : 0;
  logit += subdomainCount >= 2 ? 0.65 : 0;
  logit += inspectedUrl.length > 110 ? 0.5 : 0;
  logit += suspiciousChars.length >= 4 ? 0.45 : 0;
  if (!parts.validSyntax) logit += 1.6;

  const prob = Math.max(1, Math.min(99, Math.round((1 / (1 + Math.exp(-logit))) * 100)));

  const predictedLabel: MlPredictionResult['predictedLabel'] =
    prob >= 65
      ? 'Likely Phishing'
      : prob >= 30
        ? 'Suspicious Lexical Profile'
        : 'Low-Risk Lexical Profile';

  const confidence: MlPredictionResult['confidence'] =
    prob >= 75 || prob <= 15 ? 'High' : prob >= 55 || prob <= 25 ? 'Medium' : 'Low';

  const topFeatures: MlFeatureSignal[] = [
    {
      name: 'Brand Lexical Proximity',
      value: hasBrandProximity ? `${typoMatches[0].kind} (${typoMatches[0].brandDomain})` : 'None detected',
      impact: hasBrandProximity ? 'increases_risk' : 'neutral',
    },
    {
      name: 'Auth Lure Keywords',
      value: `${hostLuresCount} in host / ${fullLuresCount} total`,
      impact: hostLuresCount > 0 || fullLuresCount >= 2 ? 'increases_risk' : 'neutral',
    },
    {
      name: 'Character Repetition Run',
      value: `${maxRepeat} consecutive char(s)`,
      impact: maxRepeat >= 3 ? 'increases_risk' : 'neutral',
    },
    {
      name: 'Hostname Entropy',
      value: `${entropy.toFixed(2)} bits`,
      impact: entropy > 3.6 ? 'increases_risk' : 'reduces_risk',
    },
    {
      name: 'Host Hyphens / Digits',
      value: `${hyphenCount} hyphen(s), ${urlDigitCount} URL digit(s)`,
      impact: hyphenCount >= 2 || hostDigitRatio > 0.15 ? 'increases_risk' : 'neutral',
    },
  ];

  return {
    modelName: 'PhishShield-TS-FeatureModel-v2 (TypeScript Feature Scorer)',
    phishingProbability: prob,
    predictedLabel,
    confidence,
    topFeatures,
    extractedFeatures,
    summary: `Server-side TypeScript feature model scores ${prob}% phishing likelihood (${predictedLabel}, ${confidence} confidence) across 23 lexical & structural URL features.`,
  };
}

export function analyzeUrlRisk(
  rawUrl: string,
  sensitivity: SensitivityLevel = 'standard',
  customConfig?: Partial<UrlEngineConfig>
): UrlRiskAnalysis {
  const config: UrlEngineConfig = {
    protectedDomains: customConfig?.protectedDomains ?? resolveConfiguredProtectedDomains(),
    knownMaliciousDomains:
      customConfig?.knownMaliciousDomains ?? DEFAULT_URL_ENGINE_CONFIG.knownMaliciousDomains,
    weights: {
      ...DEFAULT_URL_ENGINE_CONFIG.weights,
      ...(customConfig?.weights ?? {}),
    },
    thresholds: {
      ...DEFAULT_URL_ENGINE_CONFIG.thresholds,
      ...(customConfig?.thresholds ?? {}),
    },
  };

  const w = config.weights;
  const trimmed = rawUrl.trim();
  const parts = normalizeUrlInput(trimmed);
  const breakdown: ScoreContribution[] = [];

  let typoMatches: TyposquatMatch[] = [];
  let isIpHost = false;
  let isRiskyTld = false;
  let isUrlShortener = false;
  let hostLures: string[] = [];
  let fullLures: string[] = [];
  const isHttp = /^http:\/\//i.test(trimmed);
  const hasAtMask = trimmed.includes('@');

  if (parts.validSyntax) {
    if (isHttp) {
      breakdown.push({
        id: 'unencrypted_http',
        label: 'Unencrypted HTTP Transport',
        category: 'transport',
        weight: w.unencryptedHttp,
        evidence: 'Uses cleartext http:// scheme instead of TLS-encrypted https://.',
      });
    }

    isIpHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(parts.parsedHost) || parts.parsedHost.startsWith('[');
    if (isIpHost) {
      breakdown.push({
        id: 'ip_address_host',
        label: 'Direct IP Address Host',
        category: 'structure',
        weight: w.ipAddressHost,
        evidence: `Direct IP address host (${parts.parsedHost}) used instead of a registered domain name.`,
      });
      if (parts.hadObfuscatedHost) {
        breakdown.push({
          id: 'obfuscated_ip_host',
          label: 'Obfuscated Numeric/Hex IP Host',
          category: 'structure',
          weight: w.obfuscatedIpHost,
          evidence: `Raw authority '${parts.rawHost}' normalized to IP host '${parts.parsedHost}'.`,
        });
      }
    }

    if (parts.parsedHost.includes('xn--')) {
      breakdown.push({
        id: 'punycode_idn',
        label: 'Punycode / IDN Hostname',
        category: 'homoglyph',
        weight: w.punycodeIdn,
        evidence: `Punycode domain '${parts.parsedHost}' (decoded: '${parts.normalizedHost}') can disguise non-ASCII lookalike characters.`,
      });
    } else if (/[^\x00-\x7f]/.test(parts.parsedHost)) {
      breakdown.push({
        id: 'unicode_homoglyph_host',
        label: 'Non-ASCII Unicode Hostname',
        category: 'homoglyph',
        weight: w.unicodeHomoglyph,
        evidence: `Hostname '${parts.parsedHost}' contains non-ASCII Unicode characters commonly abused in homograph attacks.`,
      });
    }

    if (hasAtMask) {
      breakdown.push({
        id: 'at_credential_mask',
        label: 'URL "@" Authority Masking',
        category: 'structure',
        weight: w.atCredentialMask,
        evidence: 'Embedded "@" symbol in URL authority can conceal the actual destination host.',
      });
    }

    if (!isIpHost && parts.labels.length >= 4) {
      breakdown.push({
        id: 'deep_subdomain',
        label: 'Deep Subdomain Nesting',
        category: 'structure',
        weight: w.deepSubdomain,
        evidence: `Hostname contains ${parts.labels.length} domain labels (${parts.normalizedHost}).`,
      });
    }

    const matchedTld = RISKY_TLDS.find((tld) => parts.parsedHost.endsWith(tld));
    if (matchedTld) {
      isRiskyTld = true;
      breakdown.push({
        id: 'risky_tld',
        label: 'High-Abuse Top-Level Domain',
        category: 'structure',
        weight: w.riskyTld,
        evidence: `Top-level domain '${matchedTld}' exhibits elevated phishing and spam abuse frequency.`,
      });
    }

    if (URL_SHORTENERS.has(parts.normalizedHost) || URL_SHORTENERS.has(parts.registrableDomain)) {
      isUrlShortener = true;
      breakdown.push({
        id: 'url_shortener',
        label: 'URL Shortener Obfuscation',
        category: 'structure',
        weight: w.urlShortener,
        evidence: `URL shortener (${parts.normalizedHost}) conceals the final landing destination.`,
      });
    }

    if (!isIpHost && parts.primaryLabel) {
      typoMatches = detectBrandTyposquatting(
        parts.registrableDomain,
        parts.primaryLabel,
        parts.subdomain,
        parts.username,
        config
      );

      for (const match of typoMatches.slice(0, 2)) {
        if (match.kind === 'homoglyph') {
          breakdown.push({
            id: `homoglyph_${match.brandLabel}`,
            label: `Homoglyph Lookalike (${match.brandDomain})`,
            category: 'homoglyph',
            weight: w.homoglyphBrand,
            evidence: match.detail,
          });
        } else if (match.kind === 'repetition') {
          breakdown.push({
            id: `typosquat_repeat_${match.brandLabel}`,
            label: `Typosquatting Lookalike (${match.brandDomain})`,
            category: 'typosquatting',
            weight: w.typosquattingStrong,
            evidence: match.detail,
          });
        } else if (match.kind === 'edit_distance') {
          breakdown.push({
            id: `typosquat_edit_${match.brandLabel}`,
            label: `Typosquatting Edit Distance (${match.brandDomain})`,
            category: 'typosquatting',
            weight: match.distance <= 1 ? w.typosquattingStrong : w.typosquattingModerate,
            evidence: match.detail,
          });
        } else if (match.kind === 'subdomain_spoof') {
          breakdown.push({
            id: `subdomain_spoof_${match.brandLabel}`,
            label: `Subdomain Brand Spoofing (${match.brandDomain})`,
            category: 'impersonation',
            weight: w.subdomainImpersonation,
            evidence: match.detail,
          });
        } else {
          breakdown.push({
            id: `brand_lure_${match.brandLabel}`,
            label: `Brand-Impersonating Domain (${match.brandDomain})`,
            category: 'impersonation',
            weight: w.brandWithLureOrHyphen,
            evidence: match.detail,
          });
        }
      }
    }

    const isProtectedOfficial = new Set(
      config.protectedDomains.map((d) => normalizeHostname(d))
    ).has(parts.registrableDomain);

    const hostTokens = parts.normalizedHost.split(/[.-]+/).filter(Boolean);
    hostLures = Array.from(
      new Set(
        LURE_KEYWORDS.filter((kw) => hostTokens.some((tok) => tok === kw || tok.includes(kw)))
      )
    );
    const fullLower = `${parts.parsedHost}${parts.pathAndQuery}`.toLowerCase();
    fullLures = Array.from(new Set(LURE_KEYWORDS.filter((kw) => fullLower.includes(kw))));

    if (!isProtectedOfficial) {
      if (hostLures.length >= 2) {
        breakdown.push({
          id: 'multi_lure_host',
          label: 'Credential-Lure Keywords in Hostname',
          category: 'lure',
          weight: w.multiLureTokens,
          evidence: `Hostname contains multiple authentication lure terms (${hostLures.slice(0, 4).join(', ')}).`,
        });
      } else if (fullLures.length >= 2) {
        breakdown.push({
          id: 'multi_lure_url',
          label: 'Multiple Authentication Lure Tokens',
          category: 'lure',
          weight: Math.round(w.multiLureTokens * 0.8),
          evidence: `URL contains multiple authentication lure tokens (${fullLures.slice(0, 4).join(', ')}).`,
        });
      }

      if (parts.primaryLabel.includes('-') && hostLures.length >= 1) {
        breakdown.push({
          id: 'hyphenated_auth_host',
          label: 'Hyphenated Authentication Hostname',
          category: 'structure',
          weight: w.hyphenatedAuthHost,
          evidence: `Registrable label '${parts.primaryLabel}' combines hyphens with credential-lure terminology (${hostLures.slice(0, 3).join(', ')}).`,
        });
      }
    }

    if (parts.port && !['80', '443'].includes(parts.port)) {
      breakdown.push({
        id: 'non_standard_port',
        label: 'Non-Standard TCP Port',
        category: 'structure',
        weight: w.nonStandardPort,
        evidence: `URL specifies non-standard port :${parts.port}.`,
      });
    }

    if (trimmed.length > 110) {
      breakdown.push({
        id: 'long_url',
        label: 'Excessive URL Length',
        category: 'structure',
        weight: w.longUrl,
        evidence: `Unusually long URL (${trimmed.length} characters) that may obscure redirect parameters.`,
      });
    }

    const redirectKeys = ['redirect=', 'next=', 'url='];
    if (redirectKeys.some((k) => parts.pathAndQuery.toLowerCase().includes(k))) {
      breakdown.push({
        id: 'open_redirect_param',
        label: 'Redirect Query Parameter',
        category: 'lure',
        weight: w.openRedirectParam,
        evidence: 'Contains redirect/next/url query parameter commonly abused for open-redirect chaining.',
      });
    }
  } else {
    breakdown.push({
      id: 'malformed_url',
      label: 'Malformed URL Syntax',
      category: 'structure',
      weight: w.malformedUrl,
      evidence: 'Malformed URL syntax prevented standard RFC URL parsing.',
    });
  }

  let rawHeuristicScore = Math.min(
    100,
    breakdown.reduce((sum, item) => sum + item.weight, 0)
  );

  // Explicit invariant: strong typosquatting/homoglyph evidence must never produce a zero score
  const hasStrongTyposquatEvidence = breakdown.some(
    (b) => b.category === 'typosquatting' || b.category === 'homoglyph'
  );
  if (hasStrongTyposquatEvidence && rawHeuristicScore < 45) {
    rawHeuristicScore = 45;
  }

  const adjustedHeuristicScore = applySensitivityMultiplier(rawHeuristicScore, sensitivity);
  const sensitivityDelta = adjustedHeuristicScore - rawHeuristicScore;
  if (sensitivityDelta > 0) {
    breakdown.push({
      id: 'sensitivity_multiplier',
      label: `Sensitivity Profile (${sensitivity})`,
      category: 'sensitivity',
      weight: sensitivityDelta,
      evidence: `Applied '${sensitivity}' heuristic sensitivity scaling (+${sensitivityDelta} pts).`,
    });
  }

  const reputation = evaluateDomainReputation(
    parts.registrableDomain,
    parts.normalizedHost,
    config,
    trimmed
  );
  const mlPrediction = predictUrlLexicalMl({
    rawUrl: trimmed,
    parts,
    typoMatches,
    hostLuresCount: hostLures.length,
    fullLuresCount: fullLures.length,
    isRiskyTld,
    isUrlShortener,
    isIpHost,
    isHttp,
    hasAtMask,
  });

  const riskLevel = classifyFromScores({
    heuristicScore: adjustedHeuristicScore,
    reputation,
    thresholds: config.thresholds,
  });

  const overallRiskScore = reputation.isConfirmedMalicious
    ? Math.max(95, adjustedHeuristicScore)
    : adjustedHeuristicScore;

  const indicators = breakdown.map((item) => `[+${item.weight} pts] ${item.label}: ${item.evidence}`);
  if (indicators.length === 0) {
    indicators.push(
      `[0 pts] No overt lexical phishing or typosquatting patterns detected on '${parts.normalizedHost || trimmed}'.`
    );
  }

  const recommendations = buildRecommendationsForRiskLevel(riskLevel);
  const verdictSummary = buildVerdictSummaryForAnalysis({
    targetLabel: parts.normalizedHost || parts.parsedHost || trimmed.slice(0, 64),
    riskLevel,
    overallRiskScore,
    breakdownCount: breakdown.length,
    mlProbability: mlPrediction.phishingProbability,
    reputation,
  });

  return {
    riskScore: overallRiskScore,
    heuristicScore: adjustedHeuristicScore,
    riskLevel,
    verdictSummary,
    indicators,
    scoreBreakdown: breakdown,
    reputation,
    mlPrediction,
    recommendations,
    extractedUrls: [trimmed],
    normalizedUrl: parts.normalizedUrl,
    parsedHost: parts.parsedHost,
    normalizedHost: parts.normalizedHost,
    registrableDomain: parts.registrableDomain,
  };
}

function buildRecommendationsForRiskLevel(riskLevel: RiskClassification): string[] {
  if (riskLevel === 'Known Malicious' || riskLevel === 'High Risk' || riskLevel === 'Suspicious') {
    return [
      'Do not open or forward this link from an untrusted source.',
      'Navigate independently to the official service via a known bookmark or manually typed domain.',
      'If you already entered credentials or approved an MFA prompt, rotate your password and revoke active sessions immediately.',
    ];
  }
  if (riskLevel === 'No Known Threat Found') {
    return [
      'No known threat match was returned by the reputation provider, and zero lexical triggers fired—but this does NOT mean the URL is safe.',
      'PhishShield AI never opens or visits submitted URLs; verify the sender, domain spelling, and context before entering credentials.',
    ];
  }
  return [
    'Do not treat this URL as safe solely because it uses HTTPS or triggered zero lexical indicators.',
    'PhishShield AI never visits or renders external links; verify domain ownership and sender identity independently before interacting.',
  ];
}

function buildVerdictSummaryForAnalysis(params: {
  targetLabel: string;
  riskLevel: RiskClassification;
  overallRiskScore: number;
  breakdownCount: number;
  mlProbability: number;
  reputation: ReputationResult;
}): string {
  const { targetLabel, riskLevel, overallRiskScore, breakdownCount, mlProbability, reputation } =
    params;
  if (riskLevel === 'Known Malicious') {
    const cats =
      reputation.threatCategories.length > 0
        ? ` (${reputation.threatCategories.join(', ')})`
        : '';
    return `Threat reputation provider (${reputation.provider}) flagged ${targetLabel} as Known Malicious${cats}; heuristic score ${overallRiskScore}/100, TypeScript feature model ${mlProbability}%.`;
  }
  if (riskLevel === 'High Risk' || riskLevel === 'Suspicious') {
    return `Deterministic heuristic analysis flagged ${breakdownCount} weighted risk signal(s) on ${targetLabel} (heuristic score ${overallRiskScore}/100, TypeScript feature model ${mlProbability}%, reputation: ${reputation.resultLabel}), classifying it as ${riskLevel}.`;
  }
  if (riskLevel === 'No Known Threat Found') {
    return `${reputation.provider} returned No Known Threat Found for ${targetLabel} with 0/100 heuristic risk (TypeScript feature model ${mlProbability}%). Absence of a threat listing does not guarantee the URL is safe.`;
  }
  return `Zero lexical phishing markers triggered on ${targetLabel} (TypeScript feature model ${mlProbability}%), and threat reputation status is ${reputation.resultLabel}; classified as Unknown/Unverified.`;
}

export function applyReputationToAnalysis(
  analysis: UrlRiskAnalysis,
  reputation: Omit<ReputationResult, 'source'> & { source?: string },
  thresholds: UrlEngineConfig['thresholds'] = DEFAULT_URL_ENGINE_CONFIG.thresholds
): UrlRiskAnalysis {
  const mergedReputation: ReputationResult = {
    ...reputation,
    source: reputation.source ?? reputation.provider,
  };
  const riskLevel = classifyFromScores({
    heuristicScore: analysis.heuristicScore,
    reputation: mergedReputation,
    thresholds,
  });
  const riskScore = mergedReputation.isConfirmedMalicious
    ? Math.max(95, analysis.heuristicScore)
    : analysis.heuristicScore;

  return {
    ...analysis,
    riskScore,
    riskLevel,
    reputation: mergedReputation,
    recommendations: buildRecommendationsForRiskLevel(riskLevel),
    verdictSummary: buildVerdictSummaryForAnalysis({
      targetLabel:
        analysis.normalizedHost ||
        analysis.parsedHost ||
        analysis.extractedUrls[0] ||
        'the submitted URL',
      riskLevel,
      overallRiskScore: riskScore,
      breakdownCount: analysis.scoreBreakdown.length,
      mlProbability: analysis.mlPrediction.phishingProbability,
      reputation: mergedReputation,
    }),
  };
}
