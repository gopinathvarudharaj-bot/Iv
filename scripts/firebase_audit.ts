import fs from 'node:fs';
import path from 'node:path';
import { initializeApp } from 'firebase/app';
import {
  createUserWithEmailAndPassword,
  deleteUser,
  getAuth,
  signInWithEmailAndPassword,
  signOut,
} from 'firebase/auth';
import {
  collection,
  doc,
  getDoc,
  getDocs,
  getFirestore,
  query,
  setDoc,
  where,
} from 'firebase/firestore';
import firebaseConfig from '../firebase-applet-config.json';

interface TestResult {
  name: string;
  status: 'PASS' | 'FAIL' | 'NOT TESTED';
  detail: string;
}

const results: TestResult[] = [];

function record(name: string, status: TestResult['status'], detail: string) {
  results.push({ name, status, detail });
}

function scanDirectoryForStorageImports(dir: string): string[] {
  const hits: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      hits.push(...scanDirectoryForStorageImports(fullPath));
    } else if (/\.(ts|tsx|js|jsx)$/.test(entry.name)) {
      const content = fs.readFileSync(fullPath, 'utf8');
      if (content.includes('firebase/storage') || content.includes('getStorage')) {
        hits.push(fullPath);
      }
    }
  }
  return hits;
}

async function runAudit() {
  // 0. Static check: zero Firebase Storage imports in src/ or server.ts
  const srcHits = scanDirectoryForStorageImports(path.resolve('src'));
  const serverContent = fs.existsSync('server.ts') ? fs.readFileSync('server.ts', 'utf8') : '';
  const serverHasStorage =
    serverContent.includes('firebase/storage') || serverContent.includes('getStorage');

  record(
    'Zero firebase/storage SDK usage in src/ and server.ts',
    srcHits.length === 0 && !serverHasStorage ? 'PASS' : 'FAIL',
    srcHits.length === 0 && !serverHasStorage
      ? 'No firebase/storage or getStorage references detected.'
      : `Found references in: ${[...srcHits, ...(serverHasStorage ? ['server.ts'] : [])].join(', ')}`
  );

  record(
    'storage.rules removed for Spark plan',
    !fs.existsSync('storage.rules') ? 'PASS' : 'FAIL',
    !fs.existsSync('storage.rules') ? 'storage.rules absent.' : 'storage.rules still exists.'
  );

  const app = initializeApp(firebaseConfig, 'audit-runner');
  const auth = getAuth(app);
  const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);

  // 1. Unauthenticated Firestore GET probes
  for (const col of ['users', 'userPreferences', 'scans', 'reports']) {
    try {
      await getDoc(doc(db, col, 'unauth_probe_id'));
      record(`Unauthenticated GET /${col}/{id}`, 'FAIL', 'Read succeeded unexpectedly.');
    } catch (err) {
      const code = (err as { code?: string })?.code || '';
      record(
        `Unauthenticated GET /${col}/{id}`,
        code === 'permission-denied' ? 'PASS' : 'FAIL',
        code === 'permission-denied' ? 'Rejected with permission-denied.' : String(err)
      );
    }
  }

  // 2. Unauthenticated Firestore LIST probes
  try {
    await getDocs(query(collection(db, 'scans'), where('userId', '==', 'any_uid')));
    record('Unauthenticated LIST /scans', 'FAIL', 'Query succeeded unexpectedly.');
  } catch (err) {
    const code = (err as { code?: string })?.code || '';
    record(
      'Unauthenticated LIST /scans',
      code === 'permission-denied' ? 'PASS' : 'FAIL',
      code === 'permission-denied' ? 'Rejected with permission-denied.' : String(err)
    );
  }

  try {
    await getDocs(collection(db, 'users'));
    record('Unauthenticated LIST /users', 'FAIL', 'Query succeeded unexpectedly.');
  } catch (err) {
    const code = (err as { code?: string })?.code || '';
    record(
      'Unauthenticated LIST /users',
      code === 'permission-denied' ? 'PASS' : 'FAIL',
      code === 'permission-denied' ? 'Rejected with permission-denied.' : String(err)
    );
  }

  // 3. Unauthenticated Firestore WRITE probe
  try {
    await setDoc(doc(db, 'scans', 'unauth_write_probe'), {
      id: 'unauth_write_probe',
      userId: 'unauth_user',
    });
    record('Unauthenticated WRITE /scans/{id}', 'FAIL', 'Write succeeded unexpectedly.');
  } catch (err) {
    const code = (err as { code?: string })?.code || '';
    record(
      'Unauthenticated WRITE /scans/{id}',
      code === 'permission-denied' ? 'PASS' : 'FAIL',
      code === 'permission-denied' ? 'Rejected with permission-denied.' : String(err)
    );
  }

  // 4. Email/Password registration, logout, login, unverified write block, cross-user read block
  const testEmail = `audit_${Date.now()}@example.com`;
  const testPass = 'AuditPass!2026';
  try {
    const regCred = await createUserWithEmailAndPassword(auth, testEmail, testPass);
    record(
      'Email/Password registration (live Firebase Auth)',
      'PASS',
      `Account created (uid=${regCred.user.uid}, emailVerified=${regCred.user.emailVerified}).`
    );

    await signOut(auth);
    record(
      'Sign out (live Firebase Auth)',
      auth.currentUser === null ? 'PASS' : 'FAIL',
      auth.currentUser === null ? 'auth.currentUser cleared to null.' : 'User still present after signOut.'
    );

    const loginCred = await signInWithEmailAndPassword(auth, testEmail, testPass);
    record(
      'Email/Password login (live Firebase Auth)',
      loginCred.user.uid === regCred.user.uid ? 'PASS' : 'FAIL',
      `Signed back in as uid=${loginCred.user.uid}.`
    );

    // Unverified email Firestore write blocked
    try {
      await setDoc(doc(db, 'scans', 'unverified_probe_scan'), {
        id: 'unverified_probe_scan',
        userId: loginCred.user.uid,
        scanType: 'url',
        targetPreview: 'https://example.invalid',
        rawInput: 'https://example.invalid',
        riskLevel: 'Unknown/Unverified',
        riskScore: 0,
        heuristicScore: 0,
        reputationStatus: 'unverified',
        reputationSummary: 'Probe',
        scoreBreakdownSummary: '',
        verdictSummary: 'Probe',
        aiExplanation: 'Probe',
        indicators: [],
        recommendations: [],
        isDemoMode: true,
        archived: false,
        analystNote: '',
      });
      record('Unverified email Firestore write blocked', 'FAIL', 'Unverified user write succeeded.');
    } catch (writeErr) {
      const wCode = (writeErr as { code?: string })?.code || '';
      record(
        'Unverified email Firestore write blocked',
        wCode === 'permission-denied' ? 'PASS' : 'FAIL',
        wCode === 'permission-denied' ? 'Rejected with permission-denied.' : String(writeErr)
      );
    }

    // Cross-user GET blocked
    try {
      await getDoc(doc(db, 'scans', 'other_user_scan_id'));
      record('Cross-user GET /scans/{otherId} blocked', 'FAIL', 'Read succeeded unexpectedly.');
    } catch (readErr) {
      const rCode = (readErr as { code?: string })?.code || '';
      record(
        'Cross-user GET /scans/{otherId} blocked',
        rCode === 'permission-denied' ? 'PASS' : 'FAIL',
        rCode === 'permission-denied' ? 'Rejected with permission-denied.' : String(readErr)
      );
    }

    // Cross-user LIST blocked (querying another user's uid)
    try {
      await getDocs(query(collection(db, 'scans'), where('userId', '==', 'different_user_uid')));
      record('Cross-user LIST /scans?userId=other blocked', 'FAIL', 'Cross-user query succeeded.');
    } catch (listErr) {
      const lCode = (listErr as { code?: string })?.code || '';
      record(
        'Cross-user LIST /scans?userId=other blocked',
        lCode === 'permission-denied' ? 'PASS' : 'FAIL',
        lCode === 'permission-denied' ? 'Rejected with permission-denied.' : String(listErr)
      );
    }

    await deleteUser(loginCred.user);
    await signOut(auth).catch(() => {});
  } catch (authErr) {
    record('Email/Password Auth lifecycle', 'FAIL', String(authErr));
  }

  console.log(JSON.stringify(results, null, 2));
  process.exit(0);
}

runAudit().catch((err) => {
  console.error(err);
  process.exit(1);
});
