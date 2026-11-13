import React, { useState } from 'react';
import {
  createUserWithEmailAndPassword,
  sendEmailVerification,
  signInWithEmailAndPassword,
  signInWithPopup,
  updateProfile,
} from 'firebase/auth';
import { Lock, Mail, ShieldCheck, X } from 'lucide-react';
import { auth, googleProvider } from '../lib/firebase';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose }) => {
  const [authTab, setAuthTab] = useState<'google' | 'email'>('google');
  const [emailMode, setEmailMode] = useState<'login' | 'register'>('login');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const mapAuthError = (err: unknown): string => {
    const code = (err as { code?: string })?.code || '';
    switch (code) {
      case 'auth/operation-not-allowed':
        return 'Email/Password sign-in is not yet enabled in your Firebase project. Enable Email/Password under Firebase Console -> Authentication -> Sign-in method, or use Continue with Google above.';
      case 'auth/email-already-in-use':
        return 'An account with this email already exists. Switch to Sign In instead.';
      case 'auth/invalid-credential':
      case 'auth/wrong-password':
      case 'auth/user-not-found':
        return 'Invalid email or password.';
      case 'auth/weak-password':
        return 'Password must be at least 6 characters.';
      case 'auth/popup-closed-by-user':
        return 'Google sign-in popup was closed before completion.';
      case 'auth/popup-blocked':
        return 'Sign-in popup was blocked by your browser. Please allow popups for this site.';
      default:
        return err instanceof Error ? err.message : 'Authentication failed.';
    }
  };

  const handleGoogleSignIn = async () => {
    setLoading(true);
    setErrorMsg(null);
    setInfoMsg(null);
    try {
      await signInWithPopup(auth, googleProvider);
      onClose();
    } catch (err) {
      setErrorMsg(mapAuthError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg(null);
    setInfoMsg(null);

    try {
      if (emailMode === 'register') {
        const cred = await createUserWithEmailAndPassword(auth, email.trim(), password);
        if (displayName.trim()) {
          await updateProfile(cred.user, { displayName: displayName.trim().slice(0, 100) });
        }
        await sendEmailVerification(cred.user);
        setInfoMsg(
          'Account created! A verification email has been sent. Please verify your email address before saving scans to Cloud Firestore.'
        );
      } else {
        await signInWithEmailAndPassword(auth, email.trim(), password);
        onClose();
      }
    } catch (err) {
      setErrorMsg(mapAuthError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-modal-title"
    >
      <div className="w-full max-w-md max-h-[90vh] overflow-y-auto rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-5">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-blue-400">
              <ShieldCheck className="h-5 w-5" />
              <span className="text-sm font-medium">Firebase Authentication</span>
            </div>
            <h2 id="auth-modal-title" className="text-xl font-semibold text-slate-100">
              Sign in to PhishShield AI
            </h2>
            <p className="text-xs text-slate-400">
              Persist your scan history, security preferences, and report metadata.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close sign in dialog"
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-colors cursor-pointer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex items-center gap-1 rounded-lg bg-[#0A0F1A] p-1 border border-slate-800">
          <button
            type="button"
            onClick={() => {
              setAuthTab('google');
              setErrorMsg(null);
            }}
            className={`flex-1 rounded-md px-3 py-2 text-xs font-medium transition-colors whitespace-nowrap cursor-pointer ${
              authTab === 'google'
                ? 'bg-slate-800 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Google Sign-In
          </button>
          <button
            type="button"
            onClick={() => {
              setAuthTab('email');
              setErrorMsg(null);
            }}
            className={`flex-1 rounded-md px-3 py-2 text-xs font-medium transition-colors whitespace-nowrap cursor-pointer ${
              authTab === 'email'
                ? 'bg-slate-800 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Email &amp; Password
          </button>
        </div>

        {errorMsg && (
          <div className="rounded-lg border border-red-900/60 bg-red-950/30 px-3.5 py-2.5 text-xs text-red-300 leading-relaxed">
            {errorMsg}
          </div>
        )}

        {infoMsg && (
          <div className="rounded-lg border border-emerald-900/60 bg-emerald-950/30 px-3.5 py-2.5 text-xs text-emerald-300 leading-relaxed">
            {infoMsg}
          </div>
        )}

        {authTab === 'google' ? (
          <div className="space-y-4">
            <p className="text-sm text-slate-300 leading-relaxed">
              Sign in with your Google account for instant verified access to your private Firestore
              workspace.
            </p>
            <button
              type="button"
              onClick={handleGoogleSignIn}
              disabled={loading}
              className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60 transition-colors cursor-pointer"
            >
              <span>{loading ? 'Signing in...' : 'Continue with Google'}</span>
            </button>
          </div>
        ) : (
          <form onSubmit={handleEmailSubmit} className="space-y-3.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">
                {emailMode === 'login' ? 'Sign in with existing account' : 'Create a new account'}
              </span>
              <button
                type="button"
                onClick={() => setEmailMode(emailMode === 'login' ? 'register' : 'login')}
                className="text-blue-400 hover:text-blue-300 font-medium cursor-pointer"
              >
                {emailMode === 'login' ? 'Switch to Register' : 'Switch to Sign In'}
              </button>
            </div>

            {emailMode === 'register' && (
              <label className="block space-y-1">
                <span className="text-xs font-medium text-slate-300">Display Name</span>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Alex Rivera"
                  required
                  className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] px-3 py-2.5 text-base sm:text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                />
              </label>
            )}

            <label className="block space-y-1">
              <span className="text-xs font-medium text-slate-300">Email Address</span>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-500" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@company.com"
                  required
                  className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] pl-9 pr-3 py-2.5 text-base sm:text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                />
              </div>
            </label>

            <label className="block space-y-1">
              <span className="text-xs font-medium text-slate-300">Password</span>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-500" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Minimum 6 characters"
                  minLength={6}
                  required
                  className="w-full rounded-lg border border-slate-800 bg-[#0A0F1A] pl-9 pr-3 py-2.5 text-base sm:text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                />
              </div>
            </label>

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60 transition-colors cursor-pointer"
            >
              {loading
                ? 'Processing...'
                : emailMode === 'login'
                  ? 'Sign In'
                  : 'Create Account'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};
