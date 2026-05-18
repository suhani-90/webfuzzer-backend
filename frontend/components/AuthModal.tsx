// src/components/AuthModal.tsx
import React, { useState } from 'react';
import { Shield, X, Loader2 } from 'lucide-react';
import { loginUser, registerUser } from '../services/api';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (mode === 'register') {
        await registerUser(email, username, password);
        // Auto-login after register
        await loginUser(email, password);
      } else {
        await loginUser(email, password);
      }
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-md">
      <div className="bg-white w-full max-w-md rounded-[3rem] shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-300">
        {/* Header */}
        <div className="p-10 flex items-center justify-between border-b border-slate-100">
          <div className="flex items-center gap-4">
            <div className="bg-emerald-500 p-2.5 rounded-2xl shadow-lg shadow-emerald-100">
              <Shield className="text-white" size={22} strokeWidth={2.5} />
            </div>
            <h2 className="text-2xl font-black text-slate-900 tracking-tight">
              {mode === 'login' ? 'Sign In' : 'Create Account'}
            </h2>
          </div>
          <button onClick={onClose} className="p-2 text-slate-300 hover:text-slate-900 transition-colors">
            <X size={28} strokeWidth={2.5} />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-10 space-y-6">
          {error && (
            <div className="p-4 bg-rose-50 border border-rose-100 rounded-2xl text-rose-600 text-sm font-bold">
              {error}
            </div>
          )}

          <div>
            <label className="block text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] mb-3">
              Email Address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
              className="w-full bg-slate-50 border-2 border-slate-100 text-slate-900 px-6 py-4 rounded-2xl focus:ring-4 focus:ring-emerald-50 focus:border-emerald-400 outline-none transition-all font-bold"
            />
          </div>

          {mode === 'register' && (
            <div>
              <label className="block text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] mb-3">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="your_username"
                required
                pattern="[a-zA-Z0-9_-]+"
                minLength={3}
                className="w-full bg-slate-50 border-2 border-slate-100 text-slate-900 px-6 py-4 rounded-2xl focus:ring-4 focus:ring-emerald-50 focus:border-emerald-400 outline-none transition-all font-bold"
              />
            </div>
          )}

          <div>
            <label className="block text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] mb-3">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={mode === 'register' ? 'Min 8 chars, 1 uppercase, 1 digit' : '••••••••'}
              required
              minLength={8}
              className="w-full bg-slate-50 border-2 border-slate-100 text-slate-900 px-6 py-4 rounded-2xl focus:ring-4 focus:ring-emerald-50 focus:border-emerald-400 outline-none transition-all font-bold"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-5 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-60 text-white rounded-2xl font-black transition-all shadow-xl shadow-emerald-100 flex items-center justify-center gap-3 text-lg active:scale-95"
          >
            {loading ? (
              <><Loader2 size={22} className="animate-spin" /> Processing...</>
            ) : mode === 'login' ? (
              'Sign In & Continue'
            ) : (
              'Create Account & Start'
            )}
          </button>

          <p className="text-center text-sm text-slate-400 font-bold">
            {mode === 'login' ? "Don't have an account? " : 'Already have an account? '}
            <button
              type="button"
              onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(''); }}
              className="text-emerald-500 hover:text-emerald-600 font-black transition-colors"
            >
              {mode === 'login' ? 'Register' : 'Sign In'}
            </button>
          </p>
        </form>
      </div>
    </div>
  );
};

export default AuthModal;
