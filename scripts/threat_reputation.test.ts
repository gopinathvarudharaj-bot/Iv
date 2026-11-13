import assert from 'node:assert/strict';
import test from 'node:test';
import {
  checkUrlReputationWithSafeBrowsing,
  checkUrlsReputationWithSafeBrowsing,
  GOOGLE_SAFE_BROWSING_ENDPOINT,
  GOOGLE_SAFE_BROWSING_PROVIDER,
} from '../server/threatReputation.ts';
import { analyzeUrlRisk, applyReputationToAnalysis } from '../server/urlRiskEngine.ts';
import { buildScanRecordFirestorePayload } from '../src/lib/scanPayload.ts';

const FAKE_KEY = 'AIzaSyFakeTestCredentialDoNotLeak1234567890';
const FIXED_NOW = () => new Date('2026-11-13T10:15:30.000Z');

test('reputation 1/3: returns Known Malicious with threat categories when Safe Browsing matches URL and never visits the submitted URL itself', async () => {
  const calledUrls: string[] = [];
  let sentHeaders: Record<string, string> = {};
  let sentBody = '';

  const mockFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const endpoint = typeof input === 'string' ? input : input.toString();
    calledUrls.push(endpoint);
    sentHeaders = (init?.headers as Record<string, string>) || {};
    sentBody = String(init?.body || '');
    return new Response(
      JSON.stringify({
        matches: [
          {
            threatType: 'SOCIAL_ENGINEERING',
            platformType: 'ANY_PLATFORM',
            threatEntryType: 'URL',
            threat: { url: 'http://phish-target.example/login' },
            cacheDuration: '300s',
          },
          {
            threatType: 'MALWARE',
            platformType: 'ANY_PLATFORM',
            threatEntryType: 'URL',
            threat: { url: 'http://phish-target.example/login' },
          },
        ],
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  }) as typeof fetch;

  const rep = await checkUrlReputationWithSafeBrowsing('http://phish-target.example/login', {
    apiKey: FAKE_KEY,
    fetchFn: mockFetch,
    nowFn: FIXED_NOW,
  });

  // Never open/visit submitted URLs directly; only query the official Safe Browsing endpoint
  assert.deepEqual(calledUrls, [GOOGLE_SAFE_BROWSING_ENDPOINT]);
  assert.ok(!calledUrls.some((u) => u.includes('phish-target.example')));
  assert.equal(sentHeaders['x-goog-api-key'], FAKE_KEY);
  assert.ok(!GOOGLE_SAFE_BROWSING_ENDPOINT.includes(FAKE_KEY));
  assert.match(sentBody, /http:\/\/phish-target\.example\/login/);

  assert.equal(rep.resultLabel, 'Known Malicious');
  assert.equal(rep.status, 'confirmed_malicious');
  assert.equal(rep.isConfirmedMalicious, true);
  assert.equal(rep.configured, true);
  assert.equal(rep.provider, GOOGLE_SAFE_BROWSING_PROVIDER);
  assert.equal(rep.checkedAt, '2026-11-13T10:15:30.000Z');
  assert.equal(rep.submittedUrl, 'http://phish-target.example/login');
  assert.deepEqual(rep.threatCategories, ['SOCIAL_ENGINEERING', 'MALWARE']);
});

test('reputation 2/3: returns No Known Threat Found (never Safe) when Safe Browsing returns empty matches {}', async () => {
  const mockFetch = (async () =>
    new Response(JSON.stringify({}), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })) as typeof fetch;

  const rep = await checkUrlReputationWithSafeBrowsing('https://example.com', {
    apiKey: FAKE_KEY,
    fetchFn: mockFetch,
    nowFn: FIXED_NOW,
  });

  assert.equal(rep.resultLabel, 'No Known Threat Found');
  assert.notEqual(rep.resultLabel as string, 'Safe');
  assert.equal(rep.status, 'no_known_threat');
  assert.equal(rep.isConfirmedMalicious, false);
  assert.equal(rep.configured, true);
  assert.equal(rep.provider, GOOGLE_SAFE_BROWSING_PROVIDER);
  assert.equal(rep.checkedAt, '2026-11-13T10:15:30.000Z');
  assert.equal(rep.submittedUrl, 'https://example.com/');
  assert.deepEqual(rep.threatCategories, []);
  assert.match(rep.summary, /does not guarantee the URL is safe/i);

  // Verify heuristic engine + reputation combination does NOT label as Safe
  const combined = applyReputationToAnalysis(analyzeUrlRisk('https://example.com', 'standard'), rep);
  assert.equal(combined.riskLevel, 'No Known Threat Found');
  assert.notEqual(combined.riskLevel as string, 'Safe');
});

test('reputation 3/3: returns Unknown / Unverified and configured=false when API credentials are missing', async () => {
  const originalKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  try {
    let fetchCalled = false;
    const mockFetch = (async () => {
      fetchCalled = true;
      return new Response('{}', { status: 200 });
    }) as typeof fetch;

    const rep = await checkUrlReputationWithSafeBrowsing('https://example.com', {
      fetchFn: mockFetch,
      nowFn: FIXED_NOW,
    });

    assert.equal(fetchCalled, false);
    assert.equal(rep.resultLabel, 'Unknown / Unverified');
    assert.equal(rep.status, 'unverified');
    assert.equal(rep.configured, false);
    assert.equal(rep.errorCode, 'NOT_CONFIGURED');
    assert.match(rep.summary, /not configured/i);
    assert.equal(rep.isConfirmedMalicious, false);
  } finally {
    if (originalKey !== undefined) {
      process.env.GOOGLE_SAFE_BROWSING_API_KEY = originalKey;
    }
  }
});

test('keeps heuristic risk scoring separate from reputation results (googggle.com stays High Risk even if Safe Browsing finds no match)', async () => {
  const mockFetch = (async () =>
    new Response(JSON.stringify({}), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })) as typeof fetch;

  const base = analyzeUrlRisk('https://www.googggle.com', 'standard');
  const rep = await checkUrlReputationWithSafeBrowsing(base.normalizedUrl, {
    apiKey: FAKE_KEY,
    fetchFn: mockFetch,
    nowFn: FIXED_NOW,
  });
  const combined = applyReputationToAnalysis(base, rep);

  assert.equal(rep.resultLabel, 'No Known Threat Found');
  assert.equal(combined.reputation.resultLabel, 'No Known Threat Found');
  assert.equal(combined.heuristicScore, 58);
  assert.equal(combined.riskScore, 58);
  assert.equal(combined.riskLevel, 'High Risk');
});

test('failure handling: API timeout returns Unknown / Unverified with TIMEOUT code', async () => {
  const slowFetch = ((_input: string | URL | Request, init?: RequestInit) =>
    new Promise((_resolve, reject) => {
      const err = new Error('The operation was aborted due to timeout');
      err.name = 'AbortError';
      if (init?.signal?.aborted) {
        reject(err);
        return;
      }
      init?.signal?.addEventListener('abort', () => reject(err));
    })) as typeof fetch;

  const rep = await checkUrlReputationWithSafeBrowsing('https://example.com', {
    apiKey: FAKE_KEY,
    timeoutMs: 25,
    fetchFn: slowFetch,
    nowFn: FIXED_NOW,
  });

  assert.equal(rep.resultLabel, 'Unknown / Unverified');
  assert.equal(rep.status, 'unverified');
  assert.equal(rep.errorCode, 'TIMEOUT');
  assert.equal(rep.configured, true);
  assert.equal(rep.isConfirmedMalicious, false);
});

test('failure handling: HTTP 503 unavailable service and network errors return Unknown / Unverified', async () => {
  const fetch503 = (async () =>
    new Response('Service Unavailable', { status: 503 })) as typeof fetch;

  const rep503 = await checkUrlReputationWithSafeBrowsing('https://example.com', {
    apiKey: FAKE_KEY,
    fetchFn: fetch503,
  });
  assert.equal(rep503.resultLabel, 'Unknown / Unverified');
  assert.equal(rep503.errorCode, 'SERVICE_UNAVAILABLE');
  assert.equal(rep503.isConfirmedMalicious, false);

  const fetchNetworkErr = (async () => {
    throw new Error(`ENOTFOUND safebrowsing.googleapis.com key=${FAKE_KEY}`);
  }) as typeof fetch;

  const repNet = await checkUrlReputationWithSafeBrowsing('https://example.com', {
    apiKey: FAKE_KEY,
    fetchFn: fetchNetworkErr,
  });
  assert.equal(repNet.resultLabel, 'Unknown / Unverified');
  assert.equal(repNet.errorCode, 'SERVICE_UNAVAILABLE');
  assert.ok(!repNet.summary.includes(FAKE_KEY), 'API key must be redacted from error summaries');
});

test('failure handling: invalid JSON and malformed schema return Unknown / Unverified with INVALID_RESPONSE', async () => {
  const badJsonFetch = (async () =>
    new Response('<html>not json</html>', { status: 200 })) as typeof fetch;

  const repJson = await checkUrlReputationWithSafeBrowsing('https://example.com', {
    apiKey: FAKE_KEY,
    fetchFn: badJsonFetch,
  });
  assert.equal(repJson.resultLabel, 'Unknown / Unverified');
  assert.equal(repJson.errorCode, 'INVALID_RESPONSE');

  const badSchemaFetch = (async () =>
    new Response(JSON.stringify({ matches: 'not-an-array' }), { status: 200 })) as typeof fetch;

  const repSchema = await checkUrlReputationWithSafeBrowsing('https://example.com', {
    apiKey: FAKE_KEY,
    fetchFn: badSchemaFetch,
  });
  assert.equal(repSchema.resultLabel, 'Unknown / Unverified');
  assert.equal(repSchema.errorCode, 'INVALID_RESPONSE');
});

test('failure handling: HTTP 429 quota limit, rate limit, and HTTP 403 auth error are handled safely without leaking secrets', async () => {
  const quotaFetch = (async () =>
    new Response(JSON.stringify({ error: { status: 'RESOURCE_EXHAUSTED', message: 'Quota exceeded' } }), {
      status: 429,
    })) as typeof fetch;
  const repQuota = await checkUrlReputationWithSafeBrowsing('https://example.com', {
    apiKey: FAKE_KEY,
    fetchFn: quotaFetch,
  });
  assert.equal(repQuota.resultLabel, 'Unknown / Unverified');
  assert.equal(repQuota.errorCode, 'QUOTA_EXHAUSTED');

  const rateFetch = (async () =>
    new Response('Too Many Requests', { status: 429 })) as typeof fetch;
  const repRate = await checkUrlReputationWithSafeBrowsing('https://example.com', {
    apiKey: FAKE_KEY,
    fetchFn: rateFetch,
  });
  assert.equal(repRate.resultLabel, 'Unknown / Unverified');
  assert.equal(repRate.errorCode, 'RATE_LIMITED');

  const authFetch = (async () =>
    new Response(`Forbidden for ${FAKE_KEY}`, { status: 403 })) as typeof fetch;
  const repAuth = await checkUrlReputationWithSafeBrowsing('https://example.com', {
    apiKey: FAKE_KEY,
    fetchFn: authFetch,
  });
  assert.equal(repAuth.resultLabel, 'Unknown / Unverified');
  assert.equal(repAuth.errorCode, 'AUTH_ERROR');
  assert.ok(!JSON.stringify(repAuth).includes(FAKE_KEY), 'API key must never appear in result object');
});

test('Firestore payload saves submittedUrl, reputationResult, reputationProvider, reputationCheckedAt, and threatCategories', async () => {
  const mockFetch = (async () =>
    new Response(
      JSON.stringify({
        matches: [
          {
            threatType: 'SOCIAL_ENGINEERING',
            threat: { url: 'http://evil-example.test/signin' },
          },
        ],
      }),
      { status: 200 }
    )) as typeof fetch;

  const rep = await checkUrlsReputationWithSafeBrowsing(['http://evil-example.test/signin'], {
    apiKey: FAKE_KEY,
    fetchFn: mockFetch,
    nowFn: FIXED_NOW,
  });
  const combined = applyReputationToAnalysis(
    analyzeUrlRisk('http://evil-example.test/signin', 'standard'),
    rep
  );

  const firestoreDoc = buildScanRecordFirestorePayload(
    'user_123',
    'scan_rep_1',
    {
      scanType: 'url',
      targetPreview: 'http://evil-example.test/signin',
      rawInput: 'http://evil-example.test/signin',
      riskLevel: combined.riskLevel,
      riskScore: combined.riskScore,
      heuristicScore: combined.heuristicScore,
      submittedUrl: combined.reputation.submittedUrl,
      reputationStatus: combined.reputation.status,
      reputationResult: combined.reputation.resultLabel,
      reputationProvider: combined.reputation.provider,
      reputationCheckedAt: combined.reputation.checkedAt,
      threatCategories: combined.reputation.threatCategories,
      reputationSummary: combined.reputation.summary,
      scoreBreakdownSummary: combined.scoreBreakdown
        .map((b) => `+${b.weight} ${b.label}: ${b.evidence}`)
        .join(' | '),
      mlProbability: combined.mlPrediction.phishingProbability,
      mlSummary: combined.mlPrediction.summary,
      verdictSummary: combined.verdictSummary,
      aiExplanation: '',
      indicators: combined.indicators,
      recommendations: combined.recommendations,
      isDemoMode: true,
      archived: false,
      analystNote: '',
    },
    { createdAt: 'SERVER_TS', updatedAt: 'SERVER_TS' }
  );

  assert.equal(firestoreDoc.submittedUrl, 'http://evil-example.test/signin');
  assert.equal(firestoreDoc.reputationResult, 'Known Malicious');
  assert.equal(firestoreDoc.reputationProvider, GOOGLE_SAFE_BROWSING_PROVIDER);
  assert.equal(firestoreDoc.reputationCheckedAt, '2026-11-13T10:15:30.000Z');
  assert.deepEqual(firestoreDoc.threatCategories, ['SOCIAL_ENGINEERING']);
  assert.equal(firestoreDoc.riskLevel, 'Known Malicious');
  assert.ok(Number(firestoreDoc.riskScore) >= 95);
});
