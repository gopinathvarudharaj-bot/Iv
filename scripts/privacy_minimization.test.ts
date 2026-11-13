import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {
  buildMinimizedMessageInputForStorage,
  buildScanRecordFirestorePayload,
  redactSecretsInText,
  sanitizeQrPayloadForStorage,
} from '../src/lib/scanPayload.ts';

function collectTsFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectTsFiles(full));
    } else if (/\.(ts|tsx|js|jsx)$/.test(entry.name)) {
      files.push(full);
    }
  }
  return files;
}

test('SMS minimization strips message body, sender phone, and OTP from Firestore payload', () => {
  const smsBody =
    'Chase Alert: Your OTP is 849201 from +15550192834. Confirm password at https://chase-verify.invalid/login?otp=849201&token=abc123';
  const minimized = buildMinimizedMessageInputForStorage({
    channel: 'sms',
    bodyLength: smsBody.length,
    extractedUrls: ['https://chase-verify.invalid/login?otp=849201&token=abc123'],
  });

  assert.equal(minimized.targetPreview, '[SMS Link] chase-verify.invalid');
  assert.ok(minimized.rawInput.startsWith('[REDACTED_SMS_META]'));
  assert.ok(!minimized.rawInput.includes('849201'));
  assert.ok(!minimized.rawInput.includes('+15550192834'));
  assert.ok(!minimized.rawInput.includes('abc123'));
  assert.ok(minimized.rawInput.includes('[REDACTED]'));

  const payload = buildScanRecordFirestorePayload(
    'user_123',
    'scan_sms_1',
    {
      scanType: 'sms',
      targetPreview: minimized.targetPreview,
      rawInput: minimized.rawInput,
      riskLevel: 'High Risk',
      riskScore: 78,
      heuristicScore: 78,
      submittedUrl: minimized.submittedUrl,
      reputationStatus: 'unverified',
      reputationResult: 'Unknown / Unverified',
      reputationProvider: 'Google Safe Browsing API v4',
      reputationCheckedAt: '2026-11-13T10:00:00.000Z',
      threatCategories: [],
      reputationSummary: 'Reputation unavailable.',
      scoreBreakdownSummary: '+40 Credential lure',
      mlProbability: 82,
      mlSummary: 'Likely phishing.',
      verdictSummary: 'SMS classified as High Risk.',
      aiExplanation: 'Avoid clicking links with ?token=abc123 or sharing OTP.',
      indicators: ['Urgent OTP request'],
      recommendations: ['Do not click link.'],
      isDemoMode: true,
      archived: false,
      analystNote: '',
    },
    { createdAt: 'SERVER_TS', updatedAt: 'SERVER_TS' }
  );

  const serialized = JSON.stringify(payload);
  assert.ok(!serialized.includes('849201'));
  assert.ok(!serialized.includes('abc123'));
  assert.ok(!serialized.includes('Chase Alert'));
});

test('Email defensive minimization prevents raw email body from entering Firestore even if passed directly', () => {
  const secretEmailBody =
    'From: ceo@company-private.com | Subject: Confidential Wire Transfer $50,000 to IBAN DE89370400440532013000';

  const payload = buildScanRecordFirestorePayload(
    'user_456',
    'scan_email_1',
    {
      scanType: 'email',
      targetPreview: '[EMAIL Scan · Redacted Body]',
      rawInput: secretEmailBody,
      riskLevel: 'Suspicious',
      riskScore: 48,
      heuristicScore: 48,
      verdictSummary: 'Detected wire coercion phrase.',
      aiExplanation: '',
      indicators: ['Financial wire language'],
      recommendations: ['Verify via phone.'],
      isDemoMode: true,
      archived: false,
      analystNote: '',
    },
    { createdAt: 'SERVER_TS', updatedAt: 'SERVER_TS' }
  );

  assert.match(String(payload.rawInput), /^\[REDACTED_EMAIL_META\]/);
  const serialized = JSON.stringify(payload);
  assert.ok(!serialized.includes('DE89370400440532013000'));
  assert.ok(!serialized.includes('Confidential Wire Transfer'));
  assert.ok(!serialized.includes('ceo@company-private.com'));
});

test('QR payload sanitizer and secret redactor remove Wi-Fi passwords, URL credentials, and base64 images', () => {
  const wifiQr = 'WIFI:T:WPA;S:CorporateGuest;P:TopSecretPass2026;;';
  const safeWifi = sanitizeQrPayloadForStorage(wifiQr);
  assert.equal(safeWifi, 'WIFI:T:WPA;S:CorporateGuest;P:[REDACTED];;');
  assert.ok(!safeWifi.includes('TopSecretPass2026'));

  const credUrl = 'https://alice:MyPassword99@auth.example.invalid/callback?password=secret&api_key=key999&safe=1';
  const redactedUrl = redactSecretsInText(credUrl);
  assert.equal(
    redactedUrl,
    'https://alice:[REDACTED]@auth.example.invalid/callback?password=[REDACTED]&api_key=[REDACTED]&safe=1'
  );

  const inlineImage = 'Preview: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ';
  const strippedImage = redactSecretsInText(inlineImage);
  assert.equal(strippedImage, 'Preview: [LOCAL_IMAGE_OMITTED]');
});

test('Spark-plan & privacy architecture invariants hold across codebase and Firestore rules', () => {
  const codeFiles = [...collectTsFiles(path.resolve('src')), path.resolve('server.ts')];
  for (const file of codeFiles) {
    const content = fs.readFileSync(file, 'utf8');
    assert.ok(
      !content.includes('firebase/storage') && !content.includes('getStorage('),
      `Unexpected Firebase Storage reference in ${file}`
    );
  }

  assert.equal(fs.existsSync(path.resolve('storage.rules')), false);

  const rules = fs.readFileSync(path.resolve('firestore.rules'), 'utf8');
  assert.ok(rules.includes('!data.rawInput.matches(\'(?s).*data:image/.*\')'));
  assert.ok(rules.includes('!data.targetPreview.matches(\'(?s).*data:image/.*\')'));
  assert.ok(rules.includes('(?s)^\\\\[REDACTED_(EMAIL|SMS)_META\\\\].*'));
  assert.ok(rules.includes('allow get: if isValidId(userId) && isOwner(userId);'));
  assert.ok(rules.includes('allow list: if false;'));
});
