import React, { useEffect, useState } from 'react';
import { onAuthStateChanged, sendEmailVerification, signOut } from 'firebase/auth';
import type { User } from 'firebase/auth';
import {
  Bot,
  FileText,
  History,
  LayoutDashboard,
  Link2,
  LogOut,
  Mail,
  Menu,
  QrCode,
  ShieldCheck,
  X,
} from 'lucide-react';
import { AssistantView } from './components/AssistantView';
import { AuthModal } from './components/AuthModal';
import { DashboardView } from './components/DashboardView';
import { HistoryView } from './components/HistoryView';
import { MessageScannerView } from './components/MessageScannerView';
import { QrScannerView } from './components/QrScannerView';
import { ReportsView } from './components/ReportsView';
import { UrlScannerView } from './components/UrlScannerView';
import { rescoreScansApi } from './lib/apiClient';
import { auth } from './lib/firebase';
import {
  DEFAULT_PREFERENCES,
  deleteScanRecord,
  deleteSecurityReport,
  ensureUserProfile,
  generateValidDocId,
  getUserPreferences,
  saveScanRecord,
  saveSecurityReport,
  saveUserPreferences,
  subscribeUserReports,
  subscribeUserScans,
  updateScanAnalysisResults,
  updateScanNoteOrArchive,
} from './lib/firestoreService';
import type {
  NavTab,
  ScanRecord,
  SecurityReport,
  UserPreferences,
} from './types/phishshield';

const NAV_ITEMS: Array<{
  id: NavTab;
  label: string;
  Icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: 'dashboard', label: 'Dashboard', Icon: LayoutDashboard },
  { id: 'url-scanner', label: 'URL Scanner', Icon: Link2 },
  { id: 'message-scanner', label: 'Email / SMS Scanner', Icon: Mail },
  { id: 'qr-scanner', label: 'QR Scanner', Icon: QrCode },
  { id: 'assistant', label: 'AI Assistant', Icon: Bot },
  { id: 'history', label: 'Scan History', Icon: History },
  { id: 'reports', label: 'Reports', Icon: FileText },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [authModalOpen, setAuthModalOpen] = useState(false);

  const [user, setUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [authRefreshTick, setAuthRefreshTick] = useState(0);
  const [loadingData, setLoadingData] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [verificationMsg, setVerificationMsg] = useState<string | null>(null);

  const [preferences, setPreferences] = useState<UserPreferences>({
    userId: 'demo-session',
    ...DEFAULT_PREFERENCES,
  });

  const [cloudScans, setCloudScans] = useState<ScanRecord[]>([]);
  const [demoScans, setDemoScans] = useState<ScanRecord[]>([]);
  const [cloudReports, setCloudReports] = useState<SecurityReport[]>([]);
  const [demoReports, setDemoReports] = useState<SecurityReport[]>([]);
  const [rescoringHistory, setRescoringHistory] = useState(false);
  const [rescoreNotice, setRescoreNotice] = useState<string | null>(null);
  const autoRescoredUidRef = React.useRef<string | null>(null);

  const [assistantContext, setAssistantContext] = useState<{
    scanType: string;
    targetPreview: string;
    riskLevel: string;
    riskScore: number;
    indicators: string[];
  } | null>(null);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (firebaseUser) => {
      setUser(firebaseUser);
      setAuthReady(true);
      setSyncError(null);
      setVerificationMsg(null);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    if (!authReady || !user) {
      setCloudScans([]);
      setCloudReports([]);
      setPreferences({ userId: 'demo-session', ...DEFAULT_PREFERENCES });
      setLoadingData(false);
      return;
    }

    let unsubScans: (() => void) | undefined;
    let unsubReports: (() => void) | undefined;
    let cancelled = false;

    const initUserWorkspace = async () => {
      setLoadingData(true);
      try {
        if (user.emailVerified) {
          await ensureUserProfile(user);
        }
        const loadedPrefs = await getUserPreferences(user.uid);
        if (!cancelled) setPreferences(loadedPrefs);

        unsubScans = subscribeUserScans(
          user.uid,
          (items) => {
            if (!cancelled) {
              setCloudScans(items);
              setLoadingData(false);
            }
          },
          (err) => {
            if (!cancelled) {
              setSyncError(err.message);
              setLoadingData(false);
            }
          }
        );

        unsubReports = subscribeUserReports(
          user.uid,
          (items) => {
            if (!cancelled) setCloudReports(items);
          },
          (err) => {
            if (!cancelled) setSyncError(err.message);
          }
        );
      } catch (err) {
        if (!cancelled) {
          setSyncError(err instanceof Error ? err.message : 'Workspace sync error.');
          setLoadingData(false);
        }
      }
    };

    void initUserWorkspace();

    return () => {
      cancelled = true;
      unsubScans?.();
      unsubReports?.();
    };
  }, [authReady, user, authRefreshTick]);

  const activeScans = user ? cloudScans : demoScans;
  const activeReports = user ? cloudReports : demoReports;
  const isVerified = Boolean(user?.emailVerified);

  const runHistoryRescore = React.useCallback(
    async (scansToCheck: ScanRecord[], silentIfUnchanged = false) => {
      if (scansToCheck.length === 0) {
        if (!silentIfUnchanged) setRescoreNotice('No scan history records to re-score.');
        return;
      }
      setRescoringHistory(true);
      if (!silentIfUnchanged) setRescoreNotice(null);
      try {
        const batch = scansToCheck.slice(0, 50);
        const { updated } = await rescoreScansApi({
          scans: batch.map((s) => ({
            id: s.id,
            scanType: s.scanType,
            rawInput: s.rawInput,
            targetPreview: s.targetPreview,
            submittedUrl: s.submittedUrl,
            riskScore: s.riskScore,
            heuristicScore: s.heuristicScore,
            verdictSummary: s.verdictSummary,
            indicators: s.indicators,
            recommendations: s.recommendations,
            mlProbability: s.mlProbability,
            mlSummary: s.mlSummary,
          })),
          sensitivity: preferences.sensitivity,
        });

        const byId = new Map(updated.map((u) => [u.id, u]));
        const changedRecords = batch.filter((orig) => {
          const next = byId.get(orig.id);
          if (!next) return false;
          return (
            orig.riskScore !== next.riskScore ||
            orig.riskLevel !== next.riskLevel ||
            orig.heuristicScore !== next.heuristicScore ||
            orig.reputationStatus !== next.reputationStatus ||
            orig.reputationResult !== next.reputationResult ||
            orig.reputationProvider !== next.reputationProvider ||
            orig.mlProbability !== next.mlProbability ||
            !orig.mlSummary
          );
        });

        if (changedRecords.length === 0) {
          if (!silentIfUnchanged) {
            setRescoreNotice('All scan history records already match the latest detection engine.');
          }
          return;
        }

        if (user && user.emailVerified) {
          await Promise.all(
            changedRecords.map((orig) => {
              const next = byId.get(orig.id)!;
              return updateScanAnalysisResults(orig.id, {
                riskLevel: next.riskLevel,
                riskScore: next.riskScore,
                heuristicScore: next.heuristicScore,
                submittedUrl: next.submittedUrl,
                reputationStatus: next.reputationStatus,
                reputationResult: next.reputationResult,
                reputationProvider: next.reputationProvider,
                reputationCheckedAt: next.reputationCheckedAt,
                threatCategories: next.threatCategories,
                reputationSummary: next.reputationSummary,
                scoreBreakdownSummary: next.scoreBreakdownSummary,
                mlProbability: next.mlProbability,
                mlSummary: next.mlSummary,
                verdictSummary: next.verdictSummary,
                indicators: next.indicators,
                recommendations: next.recommendations,
              });
            })
          );
        } else {
          setDemoScans((prev) =>
            prev.map((s) => {
              const next = byId.get(s.id);
              if (!next) return s;
              return {
                ...s,
                riskLevel: next.riskLevel,
                riskScore: next.riskScore,
                heuristicScore: next.heuristicScore,
                submittedUrl: next.submittedUrl,
                reputationStatus: next.reputationStatus,
                reputationResult: next.reputationResult,
                reputationProvider: next.reputationProvider,
                reputationCheckedAt: next.reputationCheckedAt,
                threatCategories: next.threatCategories,
                reputationSummary: next.reputationSummary,
                scoreBreakdownSummary: next.scoreBreakdownSummary,
                mlProbability: next.mlProbability,
                mlSummary: next.mlSummary,
                verdictSummary: next.verdictSummary,
                indicators: next.indicators,
                recommendations: next.recommendations,
                updatedAtMs: Date.now(),
              };
            })
          );
        }

        setRescoreNotice(
          `Updated ${changedRecords.length} scan record${changedRecords.length === 1 ? '' : 's'} with corrected scores and reputation/ML evidence.`
        );
      } catch (err) {
        if (!silentIfUnchanged) {
          setRescoreNotice(err instanceof Error ? err.message : 'Failed to re-score scan history.');
        }
      } finally {
        setRescoringHistory(false);
      }
    },
    [preferences.sensitivity, user]
  );

  useEffect(() => {
    if (!user?.emailVerified) {
      autoRescoredUidRef.current = null;
      return;
    }
    if (cloudScans.length === 0 || autoRescoredUidRef.current === user.uid) return;
    const hasStaleScan = cloudScans.some(
      (s) =>
        typeof s.mlProbability !== 'number' ||
        typeof s.heuristicScore !== 'number' ||
        !s.reputationStatus ||
        !s.reputationResult
    );
    autoRescoredUidRef.current = user.uid;
    if (hasStaleScan) {
      void runHistoryRescore(cloudScans, true);
    }
  }, [user, cloudScans, runHistoryRescore]);

  const handleSavePreferences = async (
    next: Omit<UserPreferences, 'userId' | 'createdAt' | 'updatedAt'>
  ) => {
    setPreferences((prev) => ({ ...prev, ...next }));
    if (user && user.emailVerified) {
      await ensureUserProfile(user);
      await saveUserPreferences(user.uid, next);
    }
  };

  const handlePersistScan = async (
    scan: Omit<ScanRecord, 'id' | 'userId' | 'createdAtMs' | 'updatedAtMs'>
  ): Promise<{ savedId?: string; warning?: string }> => {
    if (user && user.emailVerified) {
      await ensureUserProfile(user);
      const id = await saveScanRecord(user.uid, scan);
      return { savedId: id };
    }

    const localId = generateValidDocId('demo');
    const localRecord: ScanRecord = {
      ...scan,
      id: localId,
      userId: user?.uid || 'demo-session',
      createdAtMs: Date.now(),
      updatedAtMs: Date.now(),
    };
    setDemoScans((prev) => [localRecord, ...prev]);

    if (user && !user.emailVerified) {
      return {
        warning:
          'Verify your email address to persist scans to Cloud Firestore. Saved to temporary session history.',
      };
    }

    return {
      warning:
        'Signed-out demo session: scan kept in temporary browser memory. Sign in to save to Cloud Firestore.',
    };
  };

  const handleUpdateScan = async (
    scanId: string,
    updates: { archived?: boolean; analystNote?: string }
  ) => {
    if (user && user.emailVerified) {
      await updateScanNoteOrArchive(scanId, updates);
      return;
    }
    setDemoScans((prev) =>
      prev.map((s) => (s.id === scanId ? { ...s, ...updates, updatedAtMs: Date.now() } : s))
    );
  };

  const handleDeleteScan = async (scanId: string) => {
    if (user && user.emailVerified) {
      await deleteScanRecord(scanId);
      return;
    }
    setDemoScans((prev) => prev.filter((s) => s.id !== scanId));
  };

  const handleSaveReport = async (
    report: Omit<SecurityReport, 'id' | 'userId' | 'createdAtMs' | 'updatedAtMs'>
  ): Promise<string> => {
    if (user && user.emailVerified) {
      await ensureUserProfile(user);
      return saveSecurityReport(user.uid, report);
    }
    const localId = generateValidDocId('report');
    const localReport: SecurityReport = {
      ...report,
      id: localId,
      userId: 'demo-session',
      createdAtMs: Date.now(),
      updatedAtMs: Date.now(),
    };
    setDemoReports((prev) => [localReport, ...prev]);
    return localId;
  };

  const handleDeleteReport = async (reportId: string) => {
    if (user && user.emailVerified) {
      await deleteSecurityReport(reportId);
      return;
    }
    setDemoReports((prev) => prev.filter((r) => r.id !== reportId));
  };

  const openAssistantWithScan = (ctx: {
    scanType: string;
    targetPreview: string;
    riskLevel: string;
    riskScore: number;
    indicators: string[];
  }) => {
    setAssistantContext(ctx);
    setActiveTab('assistant');
  };

  const activeNavLabel = NAV_ITEMS.find((item) => item.id === activeTab)?.label || 'Dashboard';

  const handleResendVerification = async () => {
    if (!user) return;
    try {
      await sendEmailVerification(user);
      setVerificationMsg('Verification email sent. Check your inbox, then click Refresh Status.');
    } catch (err) {
      setVerificationMsg(err instanceof Error ? err.message : 'Unable to send email.');
    }
  };

  const handleRefreshVerification = async () => {
    if (!user) return;
    await user.reload();
    if (auth.currentUser?.emailVerified) {
      setUser(auth.currentUser);
      setAuthRefreshTick((t) => t + 1);
      setVerificationMsg(null);
    } else {
      setVerificationMsg('Email is still unverified. Click the link sent to your inbox first.');
    }
  };

  return (
    <div className="min-h-screen bg-[#0A0F1A] text-slate-100 flex overflow-x-hidden">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:w-64 lg:flex-col lg:fixed lg:inset-y-0 border-r border-slate-800/90 bg-[#0D1322]">
        <div className="h-16 px-5 flex items-center gap-2.5 border-b border-slate-800/90">
          <ShieldCheck className="h-5 w-5 text-blue-500 shrink-0" />
          <span className="font-display text-lg font-semibold tracking-tight text-slate-50 whitespace-nowrap">
            PhishShield AI
          </span>
        </div>

        <nav aria-label="Primary Navigation" className="flex-1 px-3 py-4 space-y-1">
          {NAV_ITEMS.map(({ id, label, Icon }) => {
            const active = activeTab === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => setActiveTab(id)}
                className={`w-full flex items-center gap-3 rounded-lg px-3.5 py-2.5 text-sm font-medium transition-colors whitespace-nowrap cursor-pointer ${
                  active
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-600/30'
                    : 'text-slate-300 hover:bg-slate-800/50 hover:text-white border border-transparent'
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span>{label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800/90 space-y-3">
          {user ? (
            <div className="space-y-2.5">
              <div className="flex items-center gap-2.5">
                {user.photoURL ? (
                  <img
                    src={user.photoURL}
                    alt={user.displayName || 'User avatar'}
                    referrerPolicy="no-referrer"
                    className="h-8 w-8 rounded-full object-cover border border-slate-700 shrink-0"
                  />
                ) : (
                  <div className="h-8 w-8 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-xs font-semibold text-blue-300 shrink-0">
                    {(user.displayName || user.email || 'U').charAt(0).toUpperCase()}
                  </div>
                )}
                <div className="min-w-0">
                  <div className="text-xs font-medium text-slate-100 truncate">
                    {user.displayName || 'Security Analyst'}
                  </div>
                  <div className="text-[11px] text-slate-400 truncate">{user.email}</div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => void signOut(auth)}
                className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-800 bg-[#0A0F1A] px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer"
              >
                <LogOut className="h-3.5 w-3.5" />
                <span>Sign Out</span>
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => setAuthModalOpen(true)}
              className="w-full rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-500 transition-colors cursor-pointer"
            >
              Sign In / Register
            </button>
          )}
        </div>
      </aside>

      {/* Mobile Navigation Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-40 lg:hidden flex">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileMenuOpen(false)}
          />
          <aside className="relative z-50 w-64 bg-[#0D1322] border-r border-slate-800 flex flex-col">
            <div className="h-16 px-5 flex items-center justify-between border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-blue-500" />
                <span className="font-display text-lg font-semibold text-slate-50">
                  PhishShield AI
                </span>
              </div>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close navigation menu"
                className="rounded p-1 text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
              {NAV_ITEMS.map(({ id, label, Icon }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => {
                    setActiveTab(id);
                    setMobileMenuOpen(false);
                  }}
                  className={`w-full flex items-center gap-3 rounded-lg px-3.5 py-2.5 min-h-[44px] text-sm font-medium transition-colors cursor-pointer ${
                    activeTab === id
                      ? 'bg-blue-600/15 text-blue-400 border border-blue-600/30'
                      : 'text-slate-300 hover:bg-slate-800/50 hover:text-white border border-transparent'
                  }`}
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  <span>{label}</span>
                </button>
              ))}
            </nav>

            <div className="p-4 border-t border-slate-800/90 space-y-3">
              {user ? (
                <div className="space-y-2.5">
                  <div className="flex items-center gap-2.5">
                    {user.photoURL ? (
                      <img
                        src={user.photoURL}
                        alt={user.displayName || 'User avatar'}
                        referrerPolicy="no-referrer"
                        className="h-8 w-8 rounded-full object-cover border border-slate-700 shrink-0"
                      />
                    ) : (
                      <div className="h-8 w-8 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-xs font-semibold text-blue-300 shrink-0">
                        {(user.displayName || user.email || 'U').charAt(0).toUpperCase()}
                      </div>
                    )}
                    <div className="min-w-0">
                      <div className="text-xs font-medium text-slate-100 truncate">
                        {user.displayName || 'Security Analyst'}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate">{user.email}</div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setMobileMenuOpen(false);
                      void signOut(auth);
                    }}
                    className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-800 bg-[#0A0F1A] px-3 py-2 min-h-[44px] text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors cursor-pointer"
                  >
                    <LogOut className="h-3.5 w-3.5" />
                    <span>Sign Out</span>
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    setAuthModalOpen(true);
                  }}
                  className="w-full rounded-lg bg-blue-600 px-3.5 py-2.5 min-h-[44px] text-xs font-medium text-white hover:bg-blue-500 transition-colors cursor-pointer"
                >
                  Sign In / Register
                </button>
              )}
            </div>
          </aside>
        </div>
      )}

      {/* Main Content Viewport */}
      <div className="flex-1 lg:pl-64 flex flex-col min-w-0">
        <header className="h-16 border-b border-slate-800/90 bg-[#0A0F1A]/95 backdrop-blur px-4 sm:px-8 flex items-center justify-between gap-4 sticky top-0 z-30">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation menu"
              className="lg:hidden rounded-lg border border-slate-800 p-2.5 text-slate-300 hover:bg-slate-800 cursor-pointer"
            >
              <Menu className="h-4 w-4" />
            </button>
            <div className="flex items-center gap-2 text-sm truncate">
              <span className="text-slate-400 hidden sm:inline">PhishShield AI</span>
              <span className="text-slate-600 hidden sm:inline">/</span>
              <span className="font-medium text-slate-100 truncate">{activeNavLabel}</span>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            {user ? (
              <>
                <span className="text-xs text-slate-400 hidden md:inline whitespace-nowrap">
                  {user.emailVerified ? 'Firestore Sync Active' : 'Email Verification Pending'}
                </span>
                <button
                  type="button"
                  onClick={() => void signOut(auth)}
                  aria-label="Sign out"
                  className="lg:hidden inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-[#111827] px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-colors whitespace-nowrap cursor-pointer"
                >
                  <LogOut className="h-3.5 w-3.5" />
                  <span>Sign Out</span>
                </button>
              </>
            ) : (
              <button
                type="button"
                onClick={() => setAuthModalOpen(true)}
                className="rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Sign In
              </button>
            )}
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-8 max-w-[1280px] w-full mx-auto space-y-6">
          {user && !user.emailVerified && (
            <div className="rounded-xl border border-amber-900/60 bg-amber-950/25 p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div className="space-y-1">
                <p className="text-sm font-medium text-amber-200">
                  Verify your email address to enable Cloud Firestore persistence
                </p>
                <p className="text-xs text-amber-300/80">
                  {verificationMsg ||
                    'Firestore security rules require a verified email before writing scans, preferences, or reports.'}
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => void handleResendVerification()}
                  className="rounded-lg border border-amber-700/60 bg-amber-950/40 px-3 py-1.5 text-xs font-medium text-amber-200 hover:bg-amber-900/40 cursor-pointer"
                >
                  Resend Email
                </button>
                <button
                  type="button"
                  onClick={() => void handleRefreshVerification()}
                  className="rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-500 cursor-pointer"
                >
                  Refresh Status
                </button>
              </div>
            </div>
          )}

          {syncError && (
            <div className="rounded-xl border border-red-900/60 bg-red-950/30 p-4 text-xs text-red-300 break-all">
              Firestore sync error: {syncError}
            </div>
          )}

          {activeTab === 'dashboard' && (
            <DashboardView
              scans={activeScans}
              reports={activeReports}
              preferences={preferences}
              isSignedIn={Boolean(user)}
              isVerified={isVerified}
              loadingData={loadingData}
              onNavigate={setActiveTab}
              onSavePreferences={handleSavePreferences}
              onSelectScanForAssistant={(scan) =>
                openAssistantWithScan({
                  scanType: scan.scanType,
                  targetPreview: scan.targetPreview,
                  riskLevel: scan.riskLevel,
                  riskScore: scan.riskScore,
                  indicators: scan.indicators,
                })
              }
              onOpenAuth={() => setAuthModalOpen(true)}
            />
          )}

          {activeTab === 'url-scanner' && (
            <UrlScannerView
              preferences={preferences}
              onPersistScan={handlePersistScan}
              onAskAssistant={openAssistantWithScan}
            />
          )}

          {activeTab === 'message-scanner' && (
            <MessageScannerView
              preferences={preferences}
              onPersistScan={handlePersistScan}
              onAskAssistant={openAssistantWithScan}
            />
          )}

          {activeTab === 'qr-scanner' && (
            <QrScannerView
              preferences={preferences}
              onPersistScan={handlePersistScan}
              onAskAssistant={openAssistantWithScan}
            />
          )}

          {activeTab === 'assistant' && (
            <AssistantView
              attachedContext={assistantContext}
              onClearContext={() => setAssistantContext(null)}
            />
          )}

          {activeTab === 'history' && (
            <HistoryView
              scans={activeScans}
              isSignedIn={Boolean(user)}
              loadingData={loadingData}
              rescoring={rescoringHistory}
              rescoreNotice={rescoreNotice}
              onRescoreHistory={() => runHistoryRescore(activeScans, false)}
              onUpdateScan={handleUpdateScan}
              onDeleteScan={handleDeleteScan}
              onAskAssistant={(scan) =>
                openAssistantWithScan({
                  scanType: scan.scanType,
                  targetPreview: scan.targetPreview,
                  riskLevel: scan.riskLevel,
                  riskScore: scan.riskScore,
                  indicators: scan.indicators,
                })
              }
              onOpenAuth={() => setAuthModalOpen(true)}
            />
          )}

          {activeTab === 'reports' && (
            <ReportsView
              scans={activeScans}
              reports={activeReports}
              userId={user?.uid}
              isVerified={isVerified}
              preferences={preferences}
              onSaveReport={handleSaveReport}
              onDeleteReport={handleDeleteReport}
            />
          )}
        </main>
      </div>

      <AuthModal isOpen={authModalOpen} onClose={() => setAuthModalOpen(false)} />
    </div>
  );
}
