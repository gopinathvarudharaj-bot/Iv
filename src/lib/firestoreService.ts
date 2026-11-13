import type { User } from 'firebase/auth';
import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  limit,
  onSnapshot,
  query,
  serverTimestamp,
  setDoc,
  Timestamp,
  updateDoc,
  where,
} from 'firebase/firestore';
import { BLUEPRINT_LIMITS } from '../types/phishshield';
import type {
  ReportFormat,
  ScanChannel,
  ScanRecord,
  SecurityReport,
  SensitivityLevel,
  UserPreferences,
} from '../types/phishshield';
import { db, handleFirestoreError, OperationType } from './firebase';
import {
  buildScanRecordFirestorePayload,
  clampString,
  clampStringArray,
  normalizeRiskLevel,
} from './scanPayload';

function timestampToMs(ts: unknown): number {
  if (ts instanceof Timestamp) return ts.toMillis();
  if (
    ts &&
    typeof ts === 'object' &&
    'toMillis' in ts &&
    typeof (ts as { toMillis: () => number }).toMillis === 'function'
  ) {
    return (ts as { toMillis: () => number }).toMillis();
  }
  return Date.now();
}

export function generateValidDocId(prefix: string): string {
  const raw = `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
  return raw.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, BLUEPRINT_LIMITS.ID_MAX);
}

export async function ensureUserProfile(user: User): Promise<void> {
  if (!user.emailVerified) return;
  const path = `users/${user.uid}`;
  const userRef = doc(db, 'users', user.uid);
  const displayName = clampString(
    user.displayName || 'Security Analyst',
    BLUEPRINT_LIMITS.DISPLAY_NAME_MAX,
    'Security Analyst'
  );

  try {
    const snap = await getDoc(userRef);
    if (!snap.exists()) {
      await setDoc(userRef, {
        uid: user.uid,
        displayName,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(userRef, {
        displayName,
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export const DEFAULT_PREFERENCES: Omit<UserPreferences, 'userId'> = {
  sensitivity: 'standard',
  autoExplainWithAi: true,
  defaultReportFormat: 'pdf',
};

export async function getUserPreferences(uid: string): Promise<UserPreferences> {
  const path = `userPreferences/${uid}`;
  try {
    const prefRef = doc(db, 'userPreferences', uid);
    const snap = await getDoc(prefRef);
    if (!snap.exists()) {
      return { userId: uid, ...DEFAULT_PREFERENCES };
    }
    const data = snap.data();
    return {
      userId: uid,
      sensitivity: (data.sensitivity as SensitivityLevel) || 'standard',
      autoExplainWithAi:
        typeof data.autoExplainWithAi === 'boolean' ? data.autoExplainWithAi : true,
      defaultReportFormat: (data.defaultReportFormat as ReportFormat) || 'pdf',
    };
  } catch (error) {
    handleFirestoreError(error, OperationType.GET, path);
  }
}

export async function saveUserPreferences(
  uid: string,
  prefs: Omit<UserPreferences, 'userId' | 'createdAt' | 'updatedAt'>
): Promise<void> {
  const path = `userPreferences/${uid}`;
  const prefRef = doc(db, 'userPreferences', uid);
  try {
    const existingSnap = await getDoc(prefRef);
    if (!existingSnap.exists()) {
      await setDoc(prefRef, {
        userId: uid,
        sensitivity: prefs.sensitivity,
        autoExplainWithAi: prefs.autoExplainWithAi,
        defaultReportFormat: prefs.defaultReportFormat,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(prefRef, {
        userId: uid,
        sensitivity: prefs.sensitivity,
        autoExplainWithAi: prefs.autoExplainWithAi,
        defaultReportFormat: prefs.defaultReportFormat,
        createdAt: existingSnap.data().createdAt ?? serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export function subscribeUserScans(
  uid: string,
  onData: (scans: ScanRecord[]) => void,
  onError: (err: Error) => void
): () => void {
  const path = 'scans';
  const q = query(collection(db, path), where('userId', '==', uid), limit(150));

  return onSnapshot(
    q,
    (snapshot) => {
      const records: ScanRecord[] = snapshot.docs
        .map((d) => {
          const data = d.data();
          return {
            id: String(data.id || d.id),
            userId: String(data.userId || uid),
            scanType: (data.scanType as ScanChannel) || 'url',
            targetPreview: String(data.targetPreview || ''),
            rawInput: String(data.rawInput || ''),
            riskLevel: normalizeRiskLevel(data.riskLevel),
            riskScore: Number(data.riskScore ?? 0),
            heuristicScore:
              typeof data.heuristicScore === 'number' ? data.heuristicScore : undefined,
            submittedUrl:
              typeof data.submittedUrl === 'string' ? data.submittedUrl : undefined,
            reputationStatus:
              typeof data.reputationStatus === 'string' ? data.reputationStatus : undefined,
            reputationResult:
              typeof data.reputationResult === 'string' ? data.reputationResult : undefined,
            reputationProvider:
              typeof data.reputationProvider === 'string' ? data.reputationProvider : undefined,
            reputationCheckedAt:
              typeof data.reputationCheckedAt === 'string' ? data.reputationCheckedAt : undefined,
            threatCategories: Array.isArray(data.threatCategories)
              ? data.threatCategories.map(String)
              : undefined,
            reputationSummary:
              typeof data.reputationSummary === 'string' ? data.reputationSummary : undefined,
            scoreBreakdownSummary:
              typeof data.scoreBreakdownSummary === 'string'
                ? data.scoreBreakdownSummary
                : undefined,
            mlProbability:
              typeof data.mlProbability === 'number' ? data.mlProbability : undefined,
            mlSummary: typeof data.mlSummary === 'string' ? data.mlSummary : undefined,
            verdictSummary: String(data.verdictSummary || ''),
            aiExplanation: String(data.aiExplanation || ''),
            indicators: Array.isArray(data.indicators) ? data.indicators.map(String) : [],
            recommendations: Array.isArray(data.recommendations)
              ? data.recommendations.map(String)
              : [],
            isDemoMode: Boolean(data.isDemoMode),
            archived: Boolean(data.archived),
            analystNote: String(data.analystNote || ''),
            createdAtMs: timestampToMs(data.createdAt),
            updatedAtMs: timestampToMs(data.updatedAt),
          };
        })
        .sort((a, b) => b.createdAtMs - a.createdAtMs);
      onData(records);
    },
    (error) => {
      try {
        handleFirestoreError(error, OperationType.LIST, path);
      } catch (wrapped) {
        onError(wrapped instanceof Error ? wrapped : new Error(String(wrapped)));
      }
    }
  );
}

export async function saveScanRecord(
  uid: string,
  input: Omit<ScanRecord, 'id' | 'userId' | 'createdAtMs' | 'updatedAtMs'>
): Promise<string> {
  const id = generateValidDocId('scan');
  const path = `scans/${id}`;
  const payload = buildScanRecordFirestorePayload(uid, id, input, {
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
  });

  try {
    await setDoc(doc(db, 'scans', id), payload);
    return id;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function updateScanNoteOrArchive(
  scanId: string,
  updates: { archived?: boolean; analystNote?: string }
): Promise<void> {
  const path = `scans/${scanId}`;
  const payload: Record<string, unknown> = {
    updatedAt: serverTimestamp(),
  };
  if (typeof updates.archived === 'boolean') {
    payload.archived = updates.archived;
  }
  if (typeof updates.analystNote === 'string') {
    payload.analystNote = clampString(updates.analystNote, BLUEPRINT_LIMITS.ANALYST_NOTE_MAX, '');
  }

  try {
    await updateDoc(doc(db, 'scans', scanId), payload);
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function updateScanAnalysisResults(
  scanId: string,
  corrected: {
    riskLevel: ScanRecord['riskLevel'];
    riskScore: number;
    heuristicScore: number;
    submittedUrl?: string;
    reputationStatus: string;
    reputationResult?: string;
    reputationProvider?: string;
    reputationCheckedAt?: string;
    threatCategories?: string[];
    reputationSummary: string;
    scoreBreakdownSummary: string;
    mlProbability: number;
    mlSummary: string;
    verdictSummary: string;
    indicators: string[];
    recommendations: string[];
  }
): Promise<void> {
  const path = `scans/${scanId}`;
  const rawRepResult = (corrected.reputationResult || '').trim();
  const normalizedRepResult =
    rawRepResult === 'Known Malicious' ||
    rawRepResult === 'No Known Threat Found' ||
    rawRepResult === 'Unknown / Unverified'
      ? rawRepResult
      : 'Unknown / Unverified';

  const payload: Record<string, unknown> = {
    riskLevel: normalizeRiskLevel(corrected.riskLevel),
    riskScore: Math.max(0, Math.min(100, Math.round(corrected.riskScore))),
    heuristicScore: Math.max(0, Math.min(100, Math.round(corrected.heuristicScore))),
    reputationStatus: clampString(
      corrected.reputationStatus,
      BLUEPRINT_LIMITS.REPUTATION_STATUS_MAX,
      'unverified'
    ),
    reputationResult: normalizedRepResult,
    reputationProvider: clampString(
      corrected.reputationProvider || 'Google Safe Browsing API v4',
      BLUEPRINT_LIMITS.REPUTATION_PROVIDER_MAX,
      'Google Safe Browsing API v4'
    ),
    reputationCheckedAt: clampString(
      corrected.reputationCheckedAt || new Date().toISOString(),
      BLUEPRINT_LIMITS.REPUTATION_CHECKED_AT_MAX,
      new Date().toISOString()
    ),
    threatCategories: Array.isArray(corrected.threatCategories)
      ? clampStringArray(
          corrected.threatCategories,
          BLUEPRINT_LIMITS.THREAT_CATEGORIES_MAX,
          BLUEPRINT_LIMITS.THREAT_CATEGORY_ITEM_MAX
        )
      : [],
    reputationSummary: clampString(
      corrected.reputationSummary,
      BLUEPRINT_LIMITS.REPUTATION_SUMMARY_MAX,
      ''
    ),
    scoreBreakdownSummary: clampString(
      corrected.scoreBreakdownSummary,
      BLUEPRINT_LIMITS.SCORE_BREAKDOWN_SUMMARY_MAX,
      ''
    ),
    mlProbability: Math.max(0, Math.min(100, Math.round(corrected.mlProbability))),
    mlSummary: clampString(corrected.mlSummary, BLUEPRINT_LIMITS.ML_SUMMARY_MAX, ''),
    verdictSummary: clampString(
      corrected.verdictSummary,
      BLUEPRINT_LIMITS.VERDICT_SUMMARY_MAX,
      'Completed static analysis.'
    ),
    indicators: corrected.indicators
      .map((item) => clampString(String(item), BLUEPRINT_LIMITS.INDICATOR_ITEM_MAX))
      .filter(Boolean)
      .slice(0, BLUEPRINT_LIMITS.INDICATORS_MAX),
    recommendations: corrected.recommendations
      .map((item) => clampString(String(item), BLUEPRINT_LIMITS.RECOMMENDATION_ITEM_MAX))
      .filter(Boolean)
      .slice(0, BLUEPRINT_LIMITS.RECOMMENDATIONS_MAX),
    updatedAt: serverTimestamp(),
  };

  if (corrected.submittedUrl) {
    payload.submittedUrl = clampString(
      corrected.submittedUrl,
      BLUEPRINT_LIMITS.SUBMITTED_URL_MAX
    );
  }

  try {
    await updateDoc(doc(db, 'scans', scanId), payload);
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function deleteScanRecord(scanId: string): Promise<void> {
  const path = `scans/${scanId}`;
  try {
    await deleteDoc(doc(db, 'scans', scanId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

export function subscribeUserReports(
  uid: string,
  onData: (reports: SecurityReport[]) => void,
  onError: (err: Error) => void
): () => void {
  const path = 'reports';
  const q = query(collection(db, path), where('userId', '==', uid), limit(60));

  return onSnapshot(
    q,
    (snapshot) => {
      const items: SecurityReport[] = snapshot.docs
        .map((d) => {
          const data = d.data();
          return {
            id: String(data.id || d.id),
            userId: String(data.userId || uid),
            title: String(data.title || 'Security Report'),
            format: (data.format as ReportFormat) || 'pdf',
            scanCount: Number(data.scanCount ?? 0),
            highRiskCount: Number(data.highRiskCount ?? 0),
            summary: String(data.summary || ''),
            content: String(data.content || ''),
            createdAtMs: timestampToMs(data.createdAt),
            updatedAtMs: timestampToMs(data.updatedAt),
          };
        })
        .sort((a, b) => b.createdAtMs - a.createdAtMs);
      onData(items);
    },
    (error) => {
      try {
        handleFirestoreError(error, OperationType.LIST, path);
      } catch (wrapped) {
        onError(wrapped instanceof Error ? wrapped : new Error(String(wrapped)));
      }
    }
  );
}

export async function saveSecurityReport(
  uid: string,
  input: Omit<SecurityReport, 'id' | 'userId' | 'createdAtMs' | 'updatedAtMs'>
): Promise<string> {
  const id = generateValidDocId('report');
  const path = `reports/${id}`;
  const payload: Record<string, unknown> = {
    id,
    userId: uid,
    title: clampString(
      input.title,
      BLUEPRINT_LIMITS.REPORT_TITLE_MAX,
      'PhishShield Security Report'
    ),
    format: input.format,
    scanCount: Math.max(0, Math.min(10000, Math.round(input.scanCount))),
    highRiskCount: Math.max(0, Math.min(10000, Math.round(input.highRiskCount))),
    summary: clampString(input.summary, BLUEPRINT_LIMITS.REPORT_SUMMARY_MAX, 'Report summary'),
    content: clampString(input.content, BLUEPRINT_LIMITS.REPORT_CONTENT_MAX, 'Empty report'),
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
  };

  try {
    await setDoc(doc(db, 'reports', id), payload);
    return id;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function deleteSecurityReport(reportId: string): Promise<void> {
  const path = `reports/${reportId}`;
  try {
    await deleteDoc(doc(db, 'reports', reportId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}
