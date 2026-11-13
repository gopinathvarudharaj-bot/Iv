import React, { useState } from 'react';
import { Bot, RefreshCw, Send, X } from 'lucide-react';
import { sendAssistantChatApi } from '../lib/apiClient';
import type { ChatMessage } from '../types/phishshield';

interface ScanContextSummary {
  scanType: string;
  targetPreview: string;
  riskLevel: string;
  riskScore: number;
  indicators: string[];
}

interface AssistantViewProps {
  attachedContext: ScanContextSummary | null;
  onClearContext: () => void;
}

const STARTER_PROMPTS = [
  'Why is an unknown URL never classified as safe without out-of-band verification?',
  'What should I do immediately if I clicked a lookalike login link and entered my password?',
  'How do attackers abuse QR codes (Quishing) to bypass email security gateways?',
];

export const AssistantView: React.FC<AssistantViewProps> = ({
  attachedContext,
  onClearContext,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'model',
      text: 'I am the PhishShield AI Security Assistant powered by the server-side Gemini runtime. Ask about suspicious links, message headers, QR payloads, or incident response steps.',
      timestampMs: Date.now(),
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastFailedMessages, setLastFailedMessages] = useState<
    Array<{ role: 'user' | 'model'; text: string }> | null
  >(null);

  const dispatchChat = async (apiMessages: Array<{ role: 'user' | 'model'; text: string }>) => {
    setLoading(true);
    setError(null);
    setLastFailedMessages(null);

    try {
      const res = await sendAssistantChatApi({
        messages: apiMessages,
        scanContext: attachedContext || undefined,
      });

      setMessages((prev) => [
        ...prev,
        {
          id: `model_${Date.now()}`,
          role: 'model',
          text: res.reply,
          timestampMs: Date.now(),
        },
      ]);
    } catch (err) {
      setLastFailedMessages(apiMessages);
      setError(
        err instanceof Error
          ? err.message
          : 'AI explanation temporarily unavailable.'
      );
    } finally {
      setLoading(false);
    }
  };

  const sendMessage = async (text: string) => {
    const clean = text.trim();
    if (!clean || loading) return;

    const userMsg: ChatMessage = {
      id: `user_${Date.now()}`,
      role: 'user',
      text: clean,
      timestampMs: Date.now(),
    };

    const nextHistory = [...messages, userMsg];
    setMessages(nextHistory);
    setInput('');

    const apiMessages = nextHistory
      .filter((m) => m.id !== 'welcome')
      .map((m) => ({ role: m.role, text: m.text }));

    await dispatchChat(apiMessages);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void sendMessage(input);
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-4 border-b border-slate-800">
          <div className="space-y-1">
            <div className="text-xs text-slate-400">
              Server-Side Gemini Security Analyst · Zero External URL Crawling
            </div>
            <h1 className="text-2xl font-semibold text-slate-50">AI Security Assistant</h1>
          </div>
        </div>

        {attachedContext && (
          <div className="rounded-lg border border-blue-900/60 bg-blue-950/20 p-3.5 flex items-start justify-between gap-4">
            <div className="space-y-1 min-w-0">
              <div className="text-xs text-blue-300 font-medium">
                Attached Scan Context · {attachedContext.scanType.toUpperCase()} ·{' '}
                {attachedContext.riskLevel} ({attachedContext.riskScore}/100)
              </div>
              <div className="text-xs font-mono text-slate-300 truncate">
                {attachedContext.targetPreview}
              </div>
            </div>
            <button
              type="button"
              onClick={onClearContext}
              aria-label="Detach scan context"
              className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-100 cursor-pointer"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        <div className="space-y-3 max-h-[460px] overflow-y-auto pr-1">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`rounded-xl border p-4 space-y-1.5 ${
                msg.role === 'user'
                  ? 'border-blue-900/50 bg-[#152036] ml-6 sm:ml-16'
                  : 'border-slate-800 bg-[#0D1322] mr-6 sm:mr-16'
              }`}
            >
              <div className="flex items-center gap-2 text-xs text-slate-400">
                {msg.role === 'model' && <Bot className="h-3.5 w-3.5 text-blue-400" />}
                <span className="font-medium text-slate-300">
                  {msg.role === 'user' ? 'You' : 'PhishShield AI Analyst'}
                </span>
                <span aria-hidden="true">·</span>
                <span className="font-mono tabular-nums">
                  {new Date(msg.timestampMs).toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                  })}
                </span>
              </div>
              <div className="text-sm text-slate-200 leading-relaxed whitespace-pre-line">
                {msg.text}
              </div>
            </div>
          ))}

          {loading && (
            <div className="rounded-xl border border-slate-800 bg-[#0D1322] p-4 mr-16 space-y-2">
              <div className="h-4 w-32 rounded bg-slate-800 animate-pulse" />
              <div className="h-4 w-3/4 rounded bg-slate-800/70 animate-pulse" />
            </div>
          )}
        </div>

        {error && (
          <div className="rounded-lg border border-amber-900/60 bg-amber-950/25 px-4 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div className="space-y-0.5 text-xs text-amber-200">
              <p className="font-medium">AI explanation temporarily unavailable</p>
              <p className="text-amber-300/85">{error}</p>
            </div>
            {lastFailedMessages && (
              <button
                type="button"
                disabled={loading}
                onClick={() => void dispatchChat(lastFailedMessages)}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-amber-700/60 bg-amber-950/50 px-3 py-1.5 text-xs font-medium text-amber-100 hover:bg-amber-900/50 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
                <span>Retry AI Explanation</span>
              </button>
            )}
          </div>
        )}

        <div className="flex flex-wrap gap-2">
          {STARTER_PROMPTS.map((prompt) => (
            <button
              key={prompt}
              type="button"
              onClick={() => void sendMessage(prompt)}
              className="rounded-md border border-slate-800 bg-[#0A0F1A] px-3 py-1.5 text-xs text-slate-300 hover:border-slate-700 hover:text-white transition-colors text-left cursor-pointer"
            >
              {prompt}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3 pt-1">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask a security question or request remediation steps..."
            className="flex-1 rounded-lg border border-slate-800 bg-[#0A0F1A] px-4 py-2.5 min-h-[44px] text-base sm:text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 min-h-[44px] text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Send className="h-4 w-4" />
            <span>Send</span>
          </button>
        </form>
      </section>
    </div>
  );
};
