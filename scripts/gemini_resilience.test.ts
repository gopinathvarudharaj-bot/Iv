import assert from 'node:assert/strict';
import test from 'node:test';
import {
  classifyGeminiError,
  computeBackoffWithJitterMs,
  executeGeminiWithRetry,
  GEMINI_FLASH_MODEL,
  generateGeminiExplanationWithClient,
  sanitizeSecretText,
  type GeminiTextClient,
} from '../server/geminiResilience.ts';

const SAMPLE_HEURISTICS = {
  riskScore: 85,
  heuristicScore: 85,
  riskLevel: 'High Risk',
  verdictSummary: 'Deterministic heuristic scan flagged credential-lure patterns.',
  indicators: ['[+20 pts] Unencrypted HTTP Transport: Uses cleartext http:// scheme instead of TLS-encrypted https://.'],
  scoreBreakdown: [
    {
      id: 'unencrypted_http',
      label: 'Unencrypted HTTP Transport',
      category: 'transport',
      weight: 20,
      evidence: 'Uses cleartext http:// scheme instead of TLS-encrypted https://.',
    },
  ],
  reputation: {
    status: 'unverified',
    statusLabel: 'Unverified / No Reputation Record',
    source: 'PhishShield Local Static Feeds',
    summary: 'Domain is not on the allowlist or confirmed blocklist.',
  },
};

test('configured model uses verified stable Flash alias gemini-4-hydrogen', () => {
  assert.equal(GEMINI_FLASH_MODEL, 'gemini-4-hydrogen');
});

test('success on first attempt returns explanation without extra retries', async () => {
  let calls = 0;
  const mockClient: GeminiTextClient = {
    models: {
      generateContent: async () => {
        calls += 1;
        return {
          text: JSON.stringify({
            keyTakeaway: 'Avoid opening unverified HTTP login pages.',
            analystExplanation: 'The URL uses plain HTTP and mimics an enterprise SSO path.',
          }),
        };
      },
    },
  };

  const logs: string[] = [];
  const res = await generateGeminiExplanationWithClient(
    mockClient,
    'url',
    'http://login-example.invalid/sso?secretToken=sensitive123',
    SAMPLE_HEURISTICS,
    undefined,
    {
      sleepFn: async () => {},
      timeoutMs: 2000,
      logger: (_level, msg) => logs.push(msg),
    }
  );

  assert.equal(calls, 1);
  assert.equal(res.aiStatus, 'success');
  assert.equal(res.attempts, 1);
  assert.equal(res.aiError, undefined);
  assert.match(res.requestId, /^req_[0-9a-f]{8}$/);
  assert.equal(typeof res.latencyMs, 'number');
  assert.equal(logs.length, 1);
  assert.match(logs[0], /requestId=req_[0-9a-f]{8}/);
  assert.doesNotMatch(logs[0], /sensitive123/);
  assert.match(res.explanation, /Avoid opening unverified HTTP login pages/);
});

test('HTTP 503 overload retries with exponential backoff + jitter and succeeds on attempt 3', async () => {
  const sleepDelays: number[] = [];
  let calls = 0;

  const mockClient: GeminiTextClient = {
    models: {
      generateContent: async () => {
        calls += 1;
        if (calls < 3) {
          const err = new Error('503 Service Unavailable: high demand') as Error & { status?: number };
          err.status = 503;
          throw err;
        }
        return {
          text: JSON.stringify({
            keyTakeaway: 'Verify independently via official bookmark.',
            analystExplanation: 'Transient overload cleared on third attempt.',
          }),
        };
      },
    },
  };

  const res = await generateGeminiExplanationWithClient(
    mockClient,
    'url',
    'http://example.invalid/auth',
    SAMPLE_HEURISTICS,
    undefined,
    {
      maxAttempts: 3,
      baseDelayMs: 200,
      maxDelayMs: 2000,
      randomFn: () => 0.5,
      sleepFn: async (ms) => {
        sleepDelays.push(ms);
      },
    }
  );

  assert.equal(calls, 3);
  assert.equal(res.aiStatus, 'success');
  assert.equal(res.attempts, 3);
  assert.deepEqual(sleepDelays, [150, 300]);
});

test('persistent HTTP 503 stops after 3 attempts and never fabricates fallback explanation', async () => {
  const sleepDelays: number[] = [];
  let calls = 0;

  const mockClient: GeminiTextClient = {
    models: {
      generateContent: async () => {
        calls += 1;
        const err = new Error('{"error":{"code":503,"status":"UNAVAILABLE"}}') as Error & {
          status?: number;
        };
        err.status = 503;
        throw err;
      },
    },
  };

  const res = await generateGeminiExplanationWithClient(
    mockClient,
    'url',
    'http://example.invalid/auth',
    SAMPLE_HEURISTICS,
    undefined,
    {
      maxAttempts: 3,
      baseDelayMs: 100,
      maxDelayMs: 1000,
      randomFn: () => 1,
      sleepFn: async (ms) => {
        sleepDelays.push(ms);
      },
    }
  );

  assert.equal(calls, 3);
  assert.equal(sleepDelays.length, 2);
  assert.equal(res.aiStatus, 'unavailable');
  assert.equal(res.aiErrorCode, 'SERVICE_UNAVAILABLE');
  assert.equal(res.explanation, '');
  assert.match(res.aiError ?? '', /^AI explanation temporarily unavailable/);
});

test('timeout aborts slow Gemini call, retries up to 3 attempts, and returns safe unavailable state', async () => {
  let calls = 0;
  let abortedSignals = 0;

  const mockClient: GeminiTextClient = {
    models: {
      generateContent: async ({ config }) => {
        calls += 1;
        const signal = config?.abortSignal as AbortSignal | undefined;
        return new Promise((_resolve, reject) => {
          signal?.addEventListener('abort', () => {
            abortedSignals += 1;
            const err = new Error('aborted');
            err.name = 'AbortError';
            reject(err);
          });
        });
      },
    },
  };

  const res = await generateGeminiExplanationWithClient(
    mockClient,
    'url',
    'http://slow-target.invalid',
    SAMPLE_HEURISTICS,
    undefined,
    {
      maxAttempts: 3,
      timeoutMs: 25,
      baseDelayMs: 1,
      maxDelayMs: 5,
    }
  );

  assert.equal(calls, 3);
  assert.equal(abortedSignals, 3);
  assert.equal(res.aiStatus, 'unavailable');
  assert.equal(res.aiErrorCode, 'TIMEOUT');
  assert.equal(res.explanation, '');
  assert.match(res.aiError ?? '', /^AI explanation temporarily unavailable/);
});

test('quota error (429 RESOURCE_EXHAUSTED) is NOT retried blindly', async () => {
  let calls = 0;

  const mockClient: GeminiTextClient = {
    models: {
      generateContent: async () => {
        calls += 1;
        const err = new Error('429 RESOURCE_EXHAUSTED: Quota exceeded for quota metric') as Error & {
          status?: number;
        };
        err.status = 429;
        throw err;
      },
    },
  };

  const res = await generateGeminiExplanationWithClient(
    mockClient,
    'url',
    'http://example.invalid',
    SAMPLE_HEURISTICS,
    undefined,
    { maxAttempts: 3, sleepFn: async () => {} }
  );

  assert.equal(calls, 1);
  assert.equal(res.attempts, 1);
  assert.equal(res.aiStatus, 'unavailable');
  assert.equal(res.aiErrorCode, 'QUOTA_EXHAUSTED');
  assert.equal(res.explanation, '');
  assert.match(res.aiError ?? '', /^AI explanation temporarily unavailable/);
});

test('invalid request (400) and authentication error (403) do not retry and never expose keys', async () => {
  let invalidCalls = 0;
  const invalidOutcome = await executeGeminiWithRetry(
    async () => {
      invalidCalls += 1;
      const err = new Error('400 INVALID_ARGUMENT: bad schema') as Error & { status?: number };
      err.status = 400;
      throw err;
    },
    { maxAttempts: 3, sleepFn: async () => {} }
  );
  assert.equal(invalidCalls, 1);
  assert.equal(invalidOutcome.ok, false);
  if (!invalidOutcome.ok) {
    assert.equal(invalidOutcome.error.code, 'INVALID_REQUEST');
    assert.equal(invalidOutcome.error.retryable, false);
  }

  let authCalls = 0;
  const authOutcome = await executeGeminiWithRetry(
    async () => {
      authCalls += 1;
      const err = new Error(
        '403 PERMISSION_DENIED for key AIzaSyDummySecretValue1234567890abcd'
      ) as Error & { status?: number };
      err.status = 403;
      throw err;
    },
    { maxAttempts: 3, sleepFn: async () => {} }
  );
  assert.equal(authCalls, 1);
  assert.equal(authOutcome.ok, false);
  if (!authOutcome.ok) {
    assert.equal(authOutcome.error.code, 'AUTH_ERROR');
    assert.equal(authOutcome.error.retryable, false);
    assert.doesNotMatch(authOutcome.error.safeDetail, /AIzaSyDummySecretValue/);
    assert.match(authOutcome.error.safeDetail, /\[REDACTED_API_KEY\]/);
  }
});

test('backoff calculation applies exponential growth with bounded jitter and secret sanitizer redacts keys', () => {
  const minDelay = computeBackoffWithJitterMs(2, 400, 4000, () => 0);
  const maxDelay = computeBackoffWithJitterMs(2, 400, 4000, () => 1);
  assert.equal(minDelay, 800);
  assert.equal(maxDelay, 1600);

  const sanitized = sanitizeSecretText('Failed calling with api_key=secret123 and AIzaSyAbcDef1234567890GhIjKlMn');
  assert.doesNotMatch(sanitized, /secret123/);
  assert.doesNotMatch(sanitized, /AIzaSyAbcDef/);

  const classified = classifyGeminiError({ status: 503, message: 'Service Unavailable' });
  assert.equal(classified.retryable, true);
  assert.equal(classified.code, 'SERVICE_UNAVAILABLE');
});
