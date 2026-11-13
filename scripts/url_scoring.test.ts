import assert from 'node:assert/strict';
import test from 'node:test';
import {
  analyzeUrlRisk,
  applyReputationToAnalysis,
  collapseRepeatedChars,
  damerauLevenshtein,
  normalizeHostname,
  normalizeHomoglyphs,
} from '../server/urlRiskEngine.ts';
import {
  generateGeminiExplanationWithClient,
  type GeminiTextClient,
} from '../server/geminiResilience.ts';
import { GOOGLE_SAFE_BROWSING_PROVIDER } from '../server/threatReputation.ts';

function mockNoKnownThreat(submittedUrl: string) {
  return {
    status: 'no_known_threat' as const,
    resultLabel: 'No Known Threat Found' as const,
    statusLabel: 'No Known Threat Found (Google Safe Browsing)',
    provider: GOOGLE_SAFE_BROWSING_PROVIDER,
    configured: true,
    checkedAt: '2026-11-13T09:00:00.000Z',
    submittedUrl,
    threatCategories: [],
    summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} found no active threat match for '${submittedUrl}'.`,
    isConfirmedMalicious: false,
  };
}

function mockKnownMalicious(submittedUrl: string) {
  return {
    status: 'confirmed_malicious' as const,
    resultLabel: 'Known Malicious' as const,
    statusLabel: 'Known Malicious (Google Safe Browsing Match)',
    provider: GOOGLE_SAFE_BROWSING_PROVIDER,
    configured: true,
    checkedAt: '2026-11-13T09:00:00.000Z',
    submittedUrl,
    matchedUrl: submittedUrl,
    threatCategories: ['SOCIAL_ENGINEERING'],
    summary: `${GOOGLE_SAFE_BROWSING_PROVIDER} reported SOCIAL_ENGINEERING for '${submittedUrl}'.`,
    isConfirmedMalicious: true,
  };
}

test('regression: google.com and www.google.com have 0 heuristic risk and become No Known Threat Found (never Safe) when provider returns no match', () => {
  for (const url of ['https://www.google.com', 'google.com', 'https://accounts.google.com/ServiceLogin']) {
    const base = analyzeUrlRisk(url, 'standard');
    assert.equal(base.riskScore, 0, `${url} should have 0 heuristic riskScore`);
    assert.equal(base.heuristicScore, 0, `${url} should have 0 heuristicScore`);
    assert.equal(base.riskLevel, 'Unknown/Unverified');
    assert.equal(base.reputation.status, 'unverified');
    assert.equal(base.scoreBreakdown.length, 0);

    const withRep = applyReputationToAnalysis(base, mockNoKnownThreat(base.normalizedUrl || url));
    assert.equal(withRep.riskLevel, 'No Known Threat Found');
    assert.notEqual(withRep.riskLevel as string, 'Safe');
    assert.equal(withRep.reputation.resultLabel, 'No Known Threat Found');
    assert.ok(
      withRep.recommendations.some((r) => /does NOT mean the URL is safe/i.test(r)),
      'Must warn that No Known Threat Found does not mean safe'
    );
  }
});

test('regression: youtube.com and www.youtube.com have 0 heuristic risk and stay distinguishable from lookalikes', () => {
  for (const url of ['https://www.youtube.com', 'youtube.com', 'https://www.youtube.com/watch?v=dQw4w9WgXcQ']) {
    const base = analyzeUrlRisk(url, 'standard');
    assert.equal(base.riskScore, 0);
    assert.equal(base.heuristicScore, 0);
    assert.equal(base.reputation.status, 'unverified');

    const withRep = applyReputationToAnalysis(base, mockNoKnownThreat(base.normalizedUrl || url));
    assert.equal(withRep.riskLevel, 'No Known Threat Found');
  }
});

test('regression: example.com and clean unfamiliar domains classify as Unknown/Unverified without provider confirmation (never Safe and not phishing)', () => {
  for (const url of [
    'https://example.com',
    'example.com',
    'https://portal.northbridge-logistics.example/invoices/2026',
    'https://northbridge-logistics.org/about',
  ]) {
    const res = analyzeUrlRisk(url, 'standard');
    assert.equal(res.riskScore, 0, `${url} should score 0`);
    assert.equal(res.heuristicScore, 0);
    assert.equal(res.riskLevel, 'Unknown/Unverified');
    assert.equal(res.reputation.status, 'unverified');
    assert.equal(res.reputation.resultLabel, 'Unknown / Unverified');
    assert.equal(res.scoreBreakdown.length, 0);
    assert.match(res.verdictSummary, /Unknown\/Unverified/);
    assert.ok(
      res.recommendations.some((r) => /not treat this URL as safe solely because it uses HTTPS/i.test(r)),
      'Should explicitly warn against treating HTTPS + zero indicators as safe'
    );
  }
});

test('regression: googggle.com detects strong typosquatting lookalike and never scores zero', () => {
  for (const url of ['https://www.googggle.com', 'googggle.com']) {
    const res = analyzeUrlRisk(url, 'standard');
    assert.ok(res.riskScore >= 55, `${url} expected non-zero strong score >= 55, got ${res.riskScore}`);
    assert.equal(res.riskScore, res.heuristicScore);
    assert.equal(res.riskLevel, 'High Risk');
    assert.notEqual(res.riskLevel, 'Known Malicious');
    assert.equal(res.reputation.status, 'unverified');
    assert.equal(res.reputation.isConfirmedMalicious, false);
    assert.ok(
      res.scoreBreakdown.some(
        (b) => b.category === 'typosquatting' && b.weight > 0 && /google\.com/i.test(b.evidence)
      ),
      'Score breakdown must explicitly attribute typosquatting weight against google.com'
    );
    const breakdownSum = res.scoreBreakdown.reduce((acc, item) => acc + item.weight, 0);
    assert.equal(res.heuristicScore, Math.min(100, breakdownSum));
  }
});

test('regression: secure-login-example.invalid flags credential-lure & hyphenation as Suspicious (not Known Malicious or 0)', () => {
  const res = analyzeUrlRisk('https://secure-login-example.invalid', 'standard');
  assert.ok(res.riskScore >= 22 && res.riskScore < 55, `Expected Suspicious score, got ${res.riskScore}`);
  assert.equal(res.riskLevel, 'Suspicious');
  assert.equal(res.reputation.status, 'unverified');
  assert.equal(res.reputation.isConfirmedMalicious, false);
  assert.ok(res.scoreBreakdown.some((b) => b.id === 'multi_lure_host'));
  assert.ok(res.scoreBreakdown.some((b) => b.id === 'hyphenated_auth_host'));
});

test('typosquatting variants: transposition, deletion, homoglyphs (ASCII & Unicode), and subdomain spoofing', () => {
  const transposed = analyzeUrlRisk('https://goolge.com');
  assert.ok(transposed.riskScore >= 55);
  assert.equal(transposed.riskLevel, 'High Risk');

  const deleted = analyzeUrlRisk('https://youtbe.com');
  assert.ok(deleted.riskScore >= 55);
  assert.equal(deleted.riskLevel, 'High Risk');

  for (const homoUrl of ['https://paypa1.com', 'https://www.g00gle.com', 'https://rnicrosoft.com']) {
    const homo = analyzeUrlRisk(homoUrl);
    assert.ok(homo.riskScore >= 55, `${homoUrl} expected >= 55, got ${homo.riskScore}`);
    assert.equal(homo.riskLevel, 'High Risk');
    assert.ok(homo.scoreBreakdown.some((b) => b.category === 'homoglyph'));
  }

  const cyrillic = analyzeUrlRisk('https://g\u043e\u043egle.com');
  assert.ok(cyrillic.riskScore >= 60);
  assert.equal(cyrillic.riskLevel, 'High Risk');
  assert.ok(
    cyrillic.scoreBreakdown.some(
      (b) => b.id === 'punycode_idn' || b.id === 'unicode_homoglyph_host'
    )
  );
  assert.ok(cyrillic.scoreBreakdown.some((b) => b.id === 'homoglyph_google'));

  const subSpoof = analyzeUrlRisk('https://google.com.verify-login.xyz');
  assert.ok(subSpoof.riskScore >= 70);
  assert.equal(subSpoof.riskLevel, 'High Risk');
  assert.ok(subSpoof.scoreBreakdown.some((b) => b.id === 'subdomain_spoof_google'));
});

test('distinguishes confirmed Known Malicious provider match from heuristic lookalike without hardcoded threat lists', () => {
  const base = analyzeUrlRisk('https://testsafebrowsing.appspot.com/s/phishing.html');
  assert.equal(base.reputation.isConfirmedMalicious, false, 'Production heuristic engine must not hardcode malicious feeds');

  const confirmed = applyReputationToAnalysis(
    base,
    mockKnownMalicious('https://testsafebrowsing.appspot.com/s/phishing.html')
  );
  assert.equal(confirmed.reputation.status, 'confirmed_malicious');
  assert.equal(confirmed.reputation.resultLabel, 'Known Malicious');
  assert.equal(confirmed.reputation.isConfirmedMalicious, true);
  assert.equal(confirmed.riskLevel, 'Known Malicious');
  assert.ok(confirmed.riskScore >= 95);

  const lookalike = analyzeUrlRisk('https://www.googggle.com');
  assert.equal(lookalike.reputation.status, 'unverified');
  assert.equal(lookalike.reputation.isConfirmedMalicious, false);
  assert.equal(lookalike.riskLevel, 'High Risk');
});

test('supports configurable protected domains list and custom heuristic weights', () => {
  const custom = analyzeUrlRisk('https://www.acmecoorp.com', 'standard', {
    protectedDomains: ['acmecorp.com'],
    weights: {
      typosquattingStrong: 70,
    } as never,
  });
  assert.equal(custom.riskScore, 70);
  assert.equal(custom.riskLevel, 'High Risk');
  assert.ok(custom.scoreBreakdown.some((b) => b.weight === 70 && /acmecorp\.com/.test(b.evidence)));
});

test('normalization primitives handle www stripping, repeated char collapse, homoglyphs, and Damerau-Levenshtein', () => {
  assert.equal(normalizeHostname('WWW.Googggle.COM.'), 'googggle.com');
  assert.equal(collapseRepeatedChars('googggle'), collapseRepeatedChars('google'));
  assert.equal(normalizeHomoglyphs('g00gle').asciiSkeleton, 'google');
  assert.equal(damerauLevenshtein('goolge', 'google'), 1);
  assert.equal(damerauLevenshtein('googggle', 'google'), 2);
});

test('Gemini explanation receives the exact deterministic score, scoreBreakdown, reputation, and classification', async () => {
  const base = analyzeUrlRisk('https://www.googggle.com', 'standard');
  const analysis = applyReputationToAnalysis(base, mockNoKnownThreat('https://www.googggle.com/'));
  let capturedPrompt = '';
  let capturedSystem = '';

  const mockClient: GeminiTextClient = {
    models: {
      generateContent: async ({ contents, config }) => {
        capturedPrompt = contents;
        capturedSystem = String(config?.systemInstruction ?? '');
        return {
          text: JSON.stringify({
            keyTakeaway: 'googggle.com is a high-risk typosquatting lookalike of google.com.',
            analystExplanation:
              'Repeated character insertion mimics google.com even though Google Safe Browsing returned No Known Threat Found.',
          }),
        };
      },
    },
  };

  const aiOutcome = await generateGeminiExplanationWithClient(
    mockClient,
    'url',
    'https://www.googggle.com',
    analysis,
    undefined,
    { sleepFn: async () => {} }
  );

  assert.equal(aiOutcome.aiStatus, 'success');
  assert.match(capturedPrompt, /High Risk/);
  assert.match(capturedPrompt, /58\/100/);
  assert.match(capturedPrompt, /Separate Threat Reputation Check \(Google Safe Browsing API v4\): No Known Threat Found/);
  assert.match(capturedPrompt, /Separate TypeScript Feature-Model Score:/);
  assert.match(capturedPrompt, /\+58 pts \[Typosquatting Lookalike \(google\.com\)\]/);
  assert.match(capturedSystem, /Known Malicious/);
  assert.match(capturedSystem, /No Known Threat Found/);
  assert.match(capturedSystem, /Unknown\/Unverified/);
});

test('URL normalization handles backslashes, fullwidth dots, zero-width chars, credential masking, and obfuscated IPs', async () => {
  const { normalizeUrlInput } = await import('../server/urlRiskEngine.ts');

  const backslashNorm = normalizeUrlInput('https:\\\\www.googggle.com/Account');
  assert.equal(backslashNorm.normalizedHost, 'googggle.com');
  const backslashRes = analyzeUrlRisk('https:\\\\www.googggle.com/Account');
  assert.ok(backslashRes.riskScore >= 55);
  assert.equal(backslashRes.riskLevel, 'High Risk');

  const fullwidthNorm = normalizeUrlInput('https://www\uFF0Egoogggle\u3002com\u200B/login');
  assert.equal(fullwidthNorm.normalizedHost, 'googggle.com');
  const fullwidthRes = analyzeUrlRisk('https://www\uFF0Egoogggle\u3002com\u200B/login');
  assert.ok(fullwidthRes.riskScore >= 55);

  const userinfoRes = analyzeUrlRisk('https://google.com@evil-login.xyz/signin');
  assert.ok(userinfoRes.riskScore >= 55);
  assert.equal(userinfoRes.riskLevel, 'High Risk');
  assert.ok(userinfoRes.scoreBreakdown.some((b) => b.id === 'at_credential_mask'));

  const hexIpNorm = normalizeUrlInput('http://0x7f.0.0.1/login');
  assert.equal(hexIpNorm.hadObfuscatedHost, true);
  const hexIpRes = analyzeUrlRisk('http://0x7f.0.0.1/login');
  assert.ok(hexIpRes.riskScore >= 40);
  assert.ok(hexIpRes.scoreBreakdown.some((b) => b.id === 'ip_address_host' || b.id === 'obfuscated_ip_host'));
});

test('separates heuristic, reputation, and TypeScript feature model across all 5 regression domains without fake ML claims', () => {
  const google = applyReputationToAnalysis(
    analyzeUrlRisk('https://www.google.com', 'standard'),
    mockNoKnownThreat('https://www.google.com/')
  );
  const youtube = applyReputationToAnalysis(
    analyzeUrlRisk('https://www.youtube.com', 'standard'),
    mockNoKnownThreat('https://www.youtube.com/')
  );
  const example = analyzeUrlRisk('https://example.com', 'standard');
  const googggle = analyzeUrlRisk('https://www.googggle.com', 'standard');
  const lure = analyzeUrlRisk('https://secure-login-example.invalid', 'standard');

  for (const res of [google, youtube, example, googggle, lure]) {
    assert.ok(res.mlPrediction.modelName.includes('PhishShield-TS'));
    assert.doesNotMatch(res.mlPrediction.modelName, /Random\s*Forest|Scikit/i);
    assert.doesNotMatch(res.mlPrediction.summary, /Random\s*Forest|trained on|PhiUSIIL/i);
    assert.ok(res.mlPrediction.phishingProbability >= 1 && res.mlPrediction.phishingProbability <= 99);
    assert.ok(Array.isArray(res.mlPrediction.topFeatures) && res.mlPrediction.topFeatures.length > 0);
    assert.ok(res.mlPrediction.extractedFeatures, 'Should expose extractedFeatures');
  }

  assert.equal(google.reputation.status, 'no_known_threat');
  assert.equal(youtube.reputation.status, 'no_known_threat');
  assert.equal(example.reputation.status, 'unverified');
  assert.equal(googggle.reputation.status, 'unverified');
  assert.equal(lure.reputation.status, 'unverified');

  assert.ok(googggle.mlPrediction.phishingProbability > google.mlPrediction.phishingProbability);
  assert.ok(googggle.mlPrediction.phishingProbability >= 50);
  assert.equal(googggle.mlPrediction.extractedFeatures?.brandTyposquatMatch, 1);
  assert.equal(googggle.mlPrediction.extractedFeatures?.maxConsecutiveRepeat, 3);
  assert.ok(lure.mlPrediction.phishingProbability > example.mlPrediction.phishingProbability);
  assert.ok((lure.mlPrediction.extractedFeatures?.hostLureKeywordCount ?? 0) >= 2);
  assert.equal(example.mlPrediction.predictedLabel, 'Low-Risk Lexical Profile');
  assert.equal(google.mlPrediction.predictedLabel, 'Low-Risk Lexical Profile');
});

test('TypeScript URL feature extraction captures IP hosts, non-standard ports, punycode, shorteners, and suspicious characters', () => {
  const ipScan = analyzeUrlRisk('http://198.51.100.42:8443/microsoft-sso/unlock?redirect=https://evil.xyz');
  const ipFeat = ipScan.mlPrediction.extractedFeatures;
  assert.ok(ipFeat);
  assert.equal(ipFeat.hasIpAddress, 1);
  assert.equal(ipFeat.hasNonStandardPort, 1);
  assert.equal(ipFeat.isHttps, 0);
  assert.equal(ipFeat.hasDoubleSlashRedirect, 1);
  assert.ok(ipFeat.suspiciousCharCount >= 2);
  assert.ok(ipScan.mlPrediction.phishingProbability >= 70);

  const shortScan = analyzeUrlRisk('https://bit.ly/3xVerifyAccount');
  assert.equal(shortScan.mlPrediction.extractedFeatures?.isUrlShortener, 1);
  assert.ok(shortScan.riskScore >= 22);

  const punyScan = analyzeUrlRisk('https://g\u043e\u043egle.com/login');
  assert.equal(punyScan.mlPrediction.extractedFeatures?.isPunycodeOrIdn, 1);
  assert.equal(punyScan.mlPrediction.extractedFeatures?.brandTyposquatMatch, 1);
});

test('Firestore ScanRecord payload preserves corrected score, classification, reputation, ML summary, and breakdown evidence matching firestore.rules', async () => {
  const { buildScanRecordFirestorePayload } = await import('../src/lib/scanPayload.ts');
  const base = analyzeUrlRisk('https://www.googggle.com', 'standard');
  const analysis = applyReputationToAnalysis(base, mockNoKnownThreat('https://www.googggle.com/'));
  const breakdownSummary = analysis.scoreBreakdown
    .map((b) => `+${b.weight} ${b.label}: ${b.evidence}`)
    .join(' | ');

  const payload = buildScanRecordFirestorePayload(
    'user_uid_123',
    'scan_test_googggle',
    {
      scanType: 'url',
      targetPreview: 'https://www.googggle.com',
      rawInput: 'https://www.googggle.com',
      riskLevel: analysis.riskLevel,
      riskScore: analysis.riskScore,
      heuristicScore: analysis.heuristicScore,
      submittedUrl: analysis.reputation.submittedUrl,
      reputationStatus: analysis.reputation.status,
      reputationResult: analysis.reputation.resultLabel,
      reputationProvider: analysis.reputation.provider,
      reputationCheckedAt: analysis.reputation.checkedAt,
      threatCategories: analysis.reputation.threatCategories,
      reputationSummary: analysis.reputation.summary,
      scoreBreakdownSummary: breakdownSummary,
      mlProbability: analysis.mlPrediction.phishingProbability,
      mlSummary: analysis.mlPrediction.summary,
      verdictSummary: analysis.verdictSummary,
      aiExplanation: 'Sample Gemini explanation consistent with typosquatting score.',
      indicators: analysis.indicators,
      recommendations: analysis.recommendations,
      isDemoMode: true,
      archived: false,
      analystNote: '',
    },
    { createdAt: 'SERVER_TS', updatedAt: 'SERVER_TS' }
  );

  assert.equal(payload.riskScore, 58);
  assert.equal(payload.heuristicScore, 58);
  assert.equal(payload.riskLevel, 'High Risk');
  assert.equal(payload.submittedUrl, 'https://www.googggle.com/');
  assert.equal(payload.reputationStatus, 'no_known_threat');
  assert.equal(payload.reputationResult, 'No Known Threat Found');
  assert.equal(payload.reputationProvider, GOOGLE_SAFE_BROWSING_PROVIDER);
  assert.equal(payload.reputationCheckedAt, '2026-11-13T09:00:00.000Z');
  assert.deepEqual(payload.threatCategories, []);
  assert.equal(payload.mlProbability, analysis.mlPrediction.phishingProbability);
  assert.equal(payload.mlSummary, analysis.mlPrediction.summary);
  assert.match(String(payload.scoreBreakdownSummary), /\+58 Typosquatting Lookalike \(google\.com\)/);
  assert.ok(Array.isArray(payload.indicators) && payload.indicators.length > 0);
  assert.ok(
    new Set([
      'Known Malicious',
      'High Risk',
      'Suspicious',
      'No Known Threat Found',
      'Unknown/Unverified',
    ]).has(String(payload.riskLevel))
  );
});
