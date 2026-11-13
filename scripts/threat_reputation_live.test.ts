import assert from 'node:assert/strict';
import test from 'node:test';
import {
  checkUrlReputationWithSafeBrowsing,
  GOOGLE_SAFE_BROWSING_PROVIDER,
  isSafeBrowsingConfigured,
} from '../server/threatReputation.ts';

const hasLiveCredentials = isSafeBrowsingConfigured();

test(
  'live Google Safe Browsing API v4 integration check (runs only when GOOGLE_SAFE_BROWSING_API_KEY is configured)',
  {
    skip: !hasLiveCredentials
      ? 'GOOGLE_SAFE_BROWSING_API_KEY is not configured; live threat reputation test skipped.'
      : false,
  },
  async () => {
    // 1. Official Google Safe Browsing test URL documented for SOCIAL_ENGINEERING verification
    const maliciousCheck = await checkUrlReputationWithSafeBrowsing(
      'https://testsafebrowsing.appspot.com/s/phishing.html'
    );
    assert.equal(maliciousCheck.configured, true);
    assert.equal(maliciousCheck.provider, GOOGLE_SAFE_BROWSING_PROVIDER);
    assert.equal(maliciousCheck.resultLabel, 'Known Malicious');
    assert.ok(maliciousCheck.threatCategories.length > 0);

    // 2. Clean domain should return No Known Threat Found (never Safe)
    const cleanCheck = await checkUrlReputationWithSafeBrowsing('https://example.com');
    assert.equal(cleanCheck.configured, true);
    assert.equal(cleanCheck.resultLabel, 'No Known Threat Found');
    assert.deepEqual(cleanCheck.threatCategories, []);
  }
);
