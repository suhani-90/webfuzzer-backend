# SmartFuzz — Frontend ↔ Backend Integration Guide

## What Changes and Why

The frontend currently runs 100% in-browser:
- Gemini is called directly from React (client-side SDK)
- Scan progress is a fake `setInterval` loop
- Vulnerabilities are randomly generated
- All state lives in `localStorage`

After integration:
- **Only `App.tsx` changes** — every other frontend file stays identical
- The backend replaces the fake interval with a real Celery scan pipeline
- A WebSocket replaces `setInterval` for live log streaming
- Auth is added (register/login) before scanning
- All other pages (Dashboard, LiveScan, Results, Reports, Landing, all components) are **untouched**

---

## Step 1 — Backend: Add CORS for the frontend origin

Open `app/core/config.py` in the backend.
Make sure `ALLOWED_ORIGINS` includes the Vite dev server:

```python
ALLOWED_ORIGINS: List[str] = [
    "http://localhost:3000",
    "http://localhost:5173",   # Vite default port
    "http://127.0.0.1:5173",
]
```

Also confirm `app/main.py` has this middleware (it already does):

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)
```

---

## Step 2 — Backend: Fix the login endpoint to accept JSON

The actual backend `auth.py` uses `OAuth2PasswordRequestForm` (form data),
but the frontend will send JSON. Change the login route:

Open `app/api/routes/auth.py`. Find the `login` function and replace it:

**BEFORE (uses form data):**
```python
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(form_data.password, user.hashed_password):
```

**AFTER (accepts JSON — matches what frontend sends):**
```python
async def login(
    payload: UserLoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(payload.password, user.hashed_password):
```

Also remove the `OAuth2PasswordRequestForm` import since it's no longer used.

---

## Step 3 — Frontend: Create an API service file

Create a new file in the frontend root:
**`src/services/api.ts`**

```typescript
// src/services/api.ts
// ─────────────────────
// All HTTP calls to the FastAPI backend.
// The frontend never changes its component code — only App.tsx uses this.

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
const WS_BASE  = import.meta.env.VITE_WS_URL  || 'ws://localhost:8000';

// ── Token storage ──────────────────────────────────────────────────────────────
export const tokenStore = {
  get: (): string | null => localStorage.getItem('sf_access_token'),
  set: (t: string)       => localStorage.setItem('sf_access_token', t),
  getRefresh: (): string | null => localStorage.getItem('sf_refresh_token'),
  setRefresh: (t: string)       => localStorage.setItem('sf_refresh_token', t),
  clear: () => {
    localStorage.removeItem('sf_access_token');
    localStorage.removeItem('sf_refresh_token');
  },
};

// ── Authenticated fetch helper ─────────────────────────────────────────────────
async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const token = tokenStore.get();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${BASE_URL}${path}`, { ...options, headers });

  // Auto-refresh on 401
  if (res.status === 401) {
    const refreshed = await tryRefreshToken();
    if (refreshed) {
      headers['Authorization'] = `Bearer ${tokenStore.get()}`;
      return fetch(`${BASE_URL}${path}`, { ...options, headers });
    }
    tokenStore.clear();
  }
  return res;
}

async function tryRefreshToken(): Promise<boolean> {
  const rt = tokenStore.getRefresh();
  if (!rt) return false;
  try {
    const res = await fetch(`${BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: rt }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    tokenStore.set(data.access_token);
    tokenStore.setRefresh(data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

// ── Auth endpoints ─────────────────────────────────────────────────────────────
export async function registerUser(email: string, username: string, password: string) {
  const res = await fetch(`${BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, username, password }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Registration failed');
  return res.json();
}

export async function loginUser(email: string, password: string) {
  const res = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Login failed');
  const data = await res.json();
  tokenStore.set(data.access_token);
  tokenStore.setRefresh(data.refresh_token);
  return data;
}

export function logoutUser() {
  tokenStore.clear();
}

export function isLoggedIn(): boolean {
  return !!tokenStore.get();
}

// ── Scan endpoints ─────────────────────────────────────────────────────────────
export interface ScanStartPayload {
  targetUrl: string;
  scanType: string;
  depth: number;
  payloads: {
    sql: boolean;
    xss: boolean;
    longString: boolean;
    specialChar: boolean;
    custom: string;
  };
}

export async function startScan(config: ScanStartPayload): Promise<{ scan_id: string; status: string }> {
  const res = await apiFetch('/scans/start', {
    method: 'POST',
    body: JSON.stringify(config),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to start scan');
  }
  return res.json();
}

export async function getScanStatus(scanId: string) {
  const res = await apiFetch(`/scans/${scanId}/status`);
  if (!res.ok) throw new Error('Failed to get scan status');
  return res.json();
}

export async function getScanVulnerabilities(scanId: string) {
  const res = await apiFetch(`/fuzz/results/${scanId}`);
  if (!res.ok) throw new Error('Failed to get vulnerabilities');
  return res.json();
}

export async function stopScan(scanId: string) {
  const res = await apiFetch(`/scans/${scanId}/stop`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to stop scan');
  return res.json();
}

export async function getReport(scanId: string) {
  const res = await apiFetch(`/reports/${scanId}`);
  if (!res.ok) throw new Error('Failed to get report');
  return res.json();
}

export function getPdfReportUrl(scanId: string): string {
  return `${BASE_URL}/reports/${scanId}/pdf`;
}

// ── WebSocket factory ──────────────────────────────────────────────────────────
export function createScanWebSocket(
  scanId: string,
  handlers: {
    onLog: (log: any) => void;
    onVulnerability: (vuln: any) => void;
    onProgress: (data: { progress: number; total_requests: number }) => void;
    onStatusChange: (status: string) => void;
    onComplete: () => void;
    onError?: (err: Event) => void;
  }
): WebSocket {
  const token = tokenStore.get() || '';
  const ws = new WebSocket(`${WS_BASE}/ws/scans/${scanId}?token=${token}`);

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      const { type, data } = msg;

      switch (type) {
        case 'scan_log':
          handlers.onLog(data);
          break;
        case 'vulnerability_found':
          handlers.onVulnerability(data);
          break;
        case 'progress_update':
          handlers.onProgress(data);
          break;
        case 'status_update':
          handlers.onStatusChange(data.status);
          break;
        case 'scan_complete':
          handlers.onProgress({ progress: 100, total_requests: data.total_requests || 0 });
          handlers.onComplete();
          break;
        case 'scan_failed':
          handlers.onStatusChange('failed');
          handlers.onComplete();
          break;
        case 'connected':
          // Initial connection confirmation — restore progress state
          handlers.onProgress({ progress: data.progress || 0, total_requests: 0 });
          handlers.onStatusChange(data.status);
          break;
        default:
          break;
      }
    } catch (e) {
      console.warn('WS parse error:', e);
    }
  };

  ws.onerror = handlers.onError || ((e) => console.error('WS error', e));

  ws.onclose = () => {
    console.log(`WebSocket closed for scan ${scanId}`);
  };

  // Keepalive ping every 25s
  const pingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.send('ping');
  }, 25000);

  ws.addEventListener('close', () => clearInterval(pingInterval));

  return ws;
}
```

---

## Step 4 — Frontend: Create `.env` file

Create `.env` in the frontend root (next to `package.json`):

```
VITE_API_URL=http://localhost:8000/api/v1
VITE_WS_URL=ws://localhost:8000
VITE_GEMINI_API_KEY=your-gemini-key-here
```

---

## Step 5 — Frontend: Create Auth modal component

Create `src/components/AuthModal.tsx` — a simple login/register modal that appears when the user clicks "Begin Audit" without being logged in. **This does not touch any existing component.**

```typescript
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
```

---

## Step 6 — Frontend: Replace App.tsx (THE ONLY FILE THAT CHANGES)

Replace the entire `App.tsx` with the version below.
Every single page component and all other files remain **exactly as they are**.

Key differences from the original:
1. `handleStartScan` → calls `POST /api/v1/scans/start` instead of Gemini directly
2. `setInterval` loop → replaced by `WebSocket` from backend
3. Auth state + `AuthModal` added
4. `handleDownloadReport` → also fetches PDF from backend
5. All state shapes (`ScanLog`, `Vulnerability`) remain **identical** — backend sends same field names

```typescript
// App.tsx — Integrated version
// ONLY this file changes. All pages and components are untouched.

import React, { useState, useEffect, useRef, useCallback } from 'react';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import LiveScan from './pages/LiveScan';
import Results from './pages/Results';
import Landing from './pages/Landing';
import AuthModal from './components/AuthModal';
import { ScanLog, Vulnerability, ScanConfig } from './types';
import { FileText, Download, ShieldCheck } from 'lucide-react';
import {
  startScan,
  getScanVulnerabilities,
  stopScan,
  createScanWebSocket,
  isLoggedIn,
  logoutUser,
  getPdfReportUrl,
  tokenStore,
} from './services/api';

// ── localStorage keys (unchanged from original) ────────────────────────────────
const STORAGE_KEYS = {
  LOGS:             'webfuzzer_logs_v3',
  VULNS:            'webfuzzer_vulnerabilities_v3',
  PROGRESS:         'webfuzzer_progress_v3',
  CONFIG:           'webfuzzer_scanConfig_v3',
  TOTAL_REQS:       'webfuzzer_totalRequests_v3',
  TOTAL_ENDPOINTS:  'webfuzzer_totalEndpoints_v3',
  IS_SCANNING:      'webfuzzer_isScanning_v3',
  ACTIVE_TAB:       'webfuzzer_activeTab_v3',
  SCAN_ID:          'webfuzzer_current_scan_id',
};

const App: React.FC = () => {
  // ── State (identical shapes to original) ──────────────────────────────────────
  const [activeTab, setActiveTab] = useState(
    () => localStorage.getItem(STORAGE_KEYS.ACTIVE_TAB) || 'landing'
  );
  const [logs, setLogs] = useState<ScanLog[]>(() => {
    const s = localStorage.getItem(STORAGE_KEYS.LOGS);
    return s ? JSON.parse(s) : [];
  });
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>(() => {
    const s = localStorage.getItem(STORAGE_KEYS.VULNS);
    return s ? JSON.parse(s) : [];
  });
  const [progress, setProgress]           = useState(() => parseInt(localStorage.getItem(STORAGE_KEYS.PROGRESS) || '0'));
  const [scanConfig, setScanConfig]       = useState<ScanConfig | null>(() => {
    const s = localStorage.getItem(STORAGE_KEYS.CONFIG);
    return s ? JSON.parse(s) : null;
  });
  const [totalRequests, setTotalRequests] = useState(() => parseInt(localStorage.getItem(STORAGE_KEYS.TOTAL_REQS) || '0'));
  const [totalEndpoints, setTotalEndpoints] = useState(() => parseInt(localStorage.getItem(STORAGE_KEYS.TOTAL_ENDPOINTS) || '0'));
  const [isScanning, setIsScanning]       = useState(() => localStorage.getItem(STORAGE_KEYS.IS_SCANNING) === 'true');
  const [isAiGenerating, setIsAiGenerating] = useState(false);

  // ── NEW: auth + scan ID state ─────────────────────────────────────────────────
  const [authOpen, setAuthOpen]   = useState(false);
  const [loggedIn, setLoggedIn]   = useState(isLoggedIn);
  const [currentScanId, setCurrentScanId] = useState<string | null>(
    () => localStorage.getItem(STORAGE_KEYS.SCAN_ID)
  );
  const [pendingConfig, setPendingConfig] = useState<ScanConfig | null>(null);

  const wsRef               = useRef<WebSocket | null>(null);
  const uniqueEndpointsRef  = useRef<Set<string>>(new Set());

  // ── Persist state to localStorage (unchanged) ─────────────────────────────────
  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.LOGS,             JSON.stringify(logs));
    localStorage.setItem(STORAGE_KEYS.VULNS,            JSON.stringify(vulnerabilities));
    localStorage.setItem(STORAGE_KEYS.PROGRESS,         progress.toString());
    localStorage.setItem(STORAGE_KEYS.TOTAL_REQS,       totalRequests.toString());
    localStorage.setItem(STORAGE_KEYS.TOTAL_ENDPOINTS,  totalEndpoints.toString());
    localStorage.setItem(STORAGE_KEYS.IS_SCANNING,      isScanning.toString());
    localStorage.setItem(STORAGE_KEYS.ACTIVE_TAB,       activeTab);
    if (scanConfig) localStorage.setItem(STORAGE_KEYS.CONFIG, JSON.stringify(scanConfig));
    if (currentScanId) localStorage.setItem(STORAGE_KEYS.SCAN_ID, currentScanId);
  }, [logs, vulnerabilities, progress, scanConfig, totalRequests, totalEndpoints, isScanning, activeTab, currentScanId]);

  // ── Track unique endpoints from logs ──────────────────────────────────────────
  useEffect(() => {
    uniqueEndpointsRef.current.clear();
    logs.forEach(log => uniqueEndpointsRef.current.add(log.url));
  }, [logs.length]);

  // ── WebSocket connection ───────────────────────────────────────────────────────
  const connectWebSocket = useCallback((scanId: string) => {
    // Close any existing connection first
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    const ws = createScanWebSocket(scanId, {
      onLog: (logEntry) => {
        // Map backend field names to frontend ScanLog interface
        const newLog: ScanLog = {
          id:        logEntry.id        || Math.random().toString(36),
          timestamp: logEntry.timestamp || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          url:       logEntry.url,
          payload:   logEntry.payload,
          status:    logEntry.status,
          method:    logEntry.method    || 'GET',
        };

        // Track unique endpoints
        if (!uniqueEndpointsRef.current.has(newLog.url)) {
          uniqueEndpointsRef.current.add(newLog.url);
          setTotalEndpoints(uniqueEndpointsRef.current.size);
        }

        setLogs(prev => [...prev.slice(-99), newLog]);
        setTotalRequests(prev => prev + 1);
      },

      onVulnerability: (vuln) => {
        // Map backend Vulnerability to frontend Vulnerability interface
        const newVuln: Vulnerability = {
          id:              vuln.id,
          url:             vuln.url,
          parameter:       vuln.parameter,
          payload:         vuln.payload,
          type:            vuln.type,
          severity:        vuln.severity,
          // Backend sends responseSnippet OR response_snippet — handle both
          responseSnippet: vuln.responseSnippet || vuln.response_snippet || '',
          fixRecommendation: vuln.fixRecommendation || vuln.fix_recommendation || '',
        };
        setVulnerabilities(prev => [newVuln, ...prev]);
      },

      onProgress: ({ progress: p, total_requests }) => {
        setProgress(p);
        if (total_requests) setTotalRequests(total_requests);
      },

      onStatusChange: (status) => {
        const stillScanning = !['completed', 'failed', 'cancelled'].includes(status);
        if (status === 'ai_generating') setIsAiGenerating(true);
        else setIsAiGenerating(false);
        setIsScanning(stillScanning);
      },

      onComplete: async () => {
        setIsScanning(false);
        setIsAiGenerating(false);
        setProgress(100);

        // Fetch final vulnerability list from REST API to ensure completeness
        if (currentScanId) {
          try {
            const finalVulns = await getScanVulnerabilities(currentScanId);
            setVulnerabilities(finalVulns.map((v: any) => ({
              id:               v.id,
              url:              v.url,
              parameter:        v.parameter,
              payload:          v.payload,
              type:             v.type,
              severity:         v.severity,
              responseSnippet:  v.responseSnippet || v.response_snippet || '',
              fixRecommendation: v.fixRecommendation || v.fix_recommendation || '',
            })));
          } catch (e) {
            console.warn('Could not fetch final vulnerabilities:', e);
          }
        }
      },

      onError: (e) => {
        console.error('WebSocket error:', e);
        setIsScanning(false);
        setIsAiGenerating(false);
      },
    });

    wsRef.current = ws;
  }, [currentScanId]);

  // ── Reconnect WS on page reload if scan was in progress ───────────────────────
  useEffect(() => {
    if (currentScanId && isScanning && loggedIn) {
      connectWebSocket(currentScanId);
    }
    return () => {
      wsRef.current?.close();
    };
  }, []); // Only on mount

  // ── Handle scan start ─────────────────────────────────────────────────────────
  const handleStartScan = async (config: ScanConfig) => {
    // If not logged in, show auth modal and save config for after login
    if (!isLoggedIn()) {
      setPendingConfig(config);
      setAuthOpen(true);
      return;
    }
    await doStartScan(config);
  };

  const doStartScan = async (config: ScanConfig) => {
    // Reset all state exactly like the original
    setScanConfig(config);
    setProgress(0);
    setLogs([]);
    setVulnerabilities([]);
    setTotalRequests(0);
    setTotalEndpoints(0);
    uniqueEndpointsRef.current.clear();
    setIsAiGenerating(true);
    setIsScanning(false);
    setActiveTab('scans');

    try {
      // POST to backend — returns { scan_id, status }
      const result = await startScan({
        targetUrl:  config.targetUrl,
        scanType:   config.scanType,
        depth:      config.depth,
        payloads:   config.payloads,
      });

      setCurrentScanId(result.scan_id);

      // Connect WebSocket to receive live stream
      connectWebSocket(result.scan_id);

    } catch (err: any) {
      console.error('Scan start error:', err);
      setIsAiGenerating(false);
      setIsScanning(false);
      alert(`Failed to start scan: ${err.message}`);
    }
  };

  // ── Auth modal success callback ───────────────────────────────────────────────
  const handleAuthSuccess = () => {
    setLoggedIn(true);
    if (pendingConfig) {
      doStartScan(pendingConfig);
      setPendingConfig(null);
    }
  };

  // ── Download report (tries PDF from backend, falls back to text) ──────────────
  const handleDownloadReport = async () => {
    if (!scanConfig || vulnerabilities.length === 0) return;

    // Try PDF from backend first
    if (currentScanId && loggedIn) {
      try {
        const pdfUrl = getPdfReportUrl(currentScanId);
        const res = await fetch(pdfUrl, {
          headers: { Authorization: `Bearer ${tokenStore.get()}` },
        });
        if (res.ok) {
          const blob = await res.blob();
          const url  = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href     = url;
          link.download = `SmartFuzz_Report_${currentScanId.substring(0, 8)}.pdf`;
          link.click();
          return;
        }
      } catch (e) {
        console.warn('PDF download failed, falling back to text');
      }
    }

    // Fallback: original text export (unchanged logic)
    let content = `SECURITY AUDIT REPORT\n--------------------\nTarget: ${scanConfig.targetUrl}\nTotal Vulnerabilities: ${vulnerabilities.length}\n`;
    vulnerabilities.forEach(v => {
      content += `\n[${v.severity}] ${v.type}\nURL: ${v.url}\nPayload: ${v.payload}\nRec: ${v.fixRecommendation}\n`;
    });
    const blob = new Blob([content], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href     = url;
    link.download = `Audit_Report_${new Date().getTime()}.txt`;
    link.click();
  };

  // ── Render (identical structure to original) ───────────────────────────────────
  const renderContent = () => {
    if (activeTab === 'landing') {
      return <Landing onStartScan={() => setActiveTab('new-scan')} />;
    }

    return (
      <div className="max-w-7xl mx-auto px-6 py-12">
        {(() => {
          switch (activeTab) {
            case 'dashboard':
              return (
                <Dashboard
                  progress={progress}
                  onNewScan={() => setActiveTab('new-scan')}
                  isScanning={isScanning}
                  vulnerabilities={vulnerabilities}
                  totalRequests={totalRequests}
                  totalEndpoints={totalEndpoints}
                />
              );
            case 'new-scan':
              return <NewScan onStartScan={handleStartScan} isAiGenerating={isAiGenerating} />;
            case 'scans':
              return <LiveScan logs={logs} progress={progress} isScanning={isScanning} isAiThinking={isAiGenerating} />;
            case 'results':
              return <Results vulnerabilities={vulnerabilities} />;
            case 'reports':
              return (
                <div className="space-y-12 animate-in fade-in duration-1000">
                  <div className="flex items-end justify-between border-b-4 border-slate-100 pb-12">
                    <div>
                      <h1 className="text-5xl font-black text-slate-900 tracking-tight">Audit <span className="text-emerald-500">Reports</span></h1>
                      <p className="text-slate-500 mt-2 font-bold text-lg">Historical forensics from your scanning sessions.</p>
                    </div>
                  </div>

                  {(vulnerabilities.length > 0 || isScanning) ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-10 pb-12">
                      <div className="bg-white border-2 border-slate-100 rounded-[3rem] p-12 shadow-soft group hover:border-emerald-200 transition-all flex flex-col">
                        <div className="flex justify-between items-start mb-10">
                          <div className="p-5 bg-emerald-50 rounded-[1.5rem] text-emerald-600 group-hover:scale-110 transition-transform shadow-sm">
                            <FileText size={36} strokeWidth={2.5} />
                          </div>
                          <span className={`px-5 py-2 rounded-full text-[10px] font-black uppercase tracking-widest ${isScanning ? 'bg-amber-100 text-amber-600' : 'bg-emerald-100 text-emerald-600'}`}>
                            {isScanning ? 'Syncing...' : 'Archived'}
                          </span>
                        </div>
                        <h3 className="text-2xl font-black text-slate-900 mb-2 truncate">
                          Target: {scanConfig?.targetUrl.replace('https://', '').replace('http://', '') || 'Previous Audit'}
                        </h3>
                        <p className="text-slate-400 text-sm font-black uppercase tracking-widest mb-10">
                          Total Findings: <span className="text-emerald-500">{vulnerabilities.length}</span>
                        </p>
                        <div className="mt-auto">
                          <button
                            onClick={handleDownloadReport}
                            disabled={vulnerabilities.length === 0}
                            className="w-full py-5 bg-emerald-500 hover:bg-emerald-600 text-white border-2 border-transparent rounded-[1.5rem] font-black transition-all flex items-center justify-center gap-4 disabled:opacity-50 shadow-lg shadow-emerald-100 active:scale-95"
                          >
                            <Download size={20} strokeWidth={3} />
                            Export Full Audit
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-[50vh] text-center">
                      <div className="w-32 h-32 bg-slate-50 rounded-full flex items-center justify-center mb-10 border-2 border-slate-100 shadow-inner">
                        <ShieldCheck size={56} className="text-slate-200" strokeWidth={2.5} />
                      </div>
                      <h3 className="text-3xl font-black text-slate-900 tracking-tight">No Reports Found</h3>
                      <p className="text-slate-500 font-bold mt-4 max-w-sm mx-auto text-lg leading-relaxed">
                        Initiate a security scan to generate intelligence forensics and remediation guides.
                      </p>
                    </div>
                  )}
                </div>
              );
            default:
              return null;
          }
        })()}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-white selection:bg-emerald-100 selection:text-emerald-900">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />
      <main className="relative overflow-hidden">
        {renderContent()}
      </main>

      {/* Auth Modal — only shown when scan is attempted without login */}
      <AuthModal
        isOpen={authOpen}
        onClose={() => { setAuthOpen(false); setPendingConfig(null); }}
        onSuccess={handleAuthSuccess}
      />
    </div>
  );
};

export default App;
```

---

## Step 7 — Frontend: Update vite.config.ts

Add the API proxy so you avoid CORS issues during development:

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
});
```

When using the proxy, update `.env`:
```
VITE_API_URL=/api/v1
VITE_WS_URL=
```
And in `api.ts` update the WS line:
```typescript
const WS_BASE = import.meta.env.VITE_WS_URL || '';
// WebSocket URL becomes ws://localhost:5173/ws/... which Vite proxies to backend
```

---

## Step 8 — Backend .env setup

Copy `.env.example` to `.env` in the backend and fill in:

```
DATABASE_URL=sqlite+aiosqlite:///./smartfuzz.db   # start with SQLite, no PostgreSQL needed
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
SECRET_KEY=any-random-32-char-string-here
GEMINI_API_KEY=your-actual-gemini-key
```

---

## Step 9 — Start everything (run order matters)

**Terminal 1 — Redis:**
```bash
redis-server
# OR with Docker:
docker run -p 6379:6379 redis:7-alpine
```

**Terminal 2 — Backend:**
```bash
cd webfuzzer-backend
python -m venv venv && source venv/bin/activate
pip install -r requirments.txt
uvicorn app.main:app --reload --port 8000
```

**Terminal 3 — Celery Worker:**
```bash
cd webfuzzer-backend
source venv/bin/activate
celery -A app.core.celery_app worker --loglevel=info -Q fuzzing,crawling
```

**Terminal 4 — Frontend:**
```bash
cd webfuzzer (frontend)
npm install
npm run dev
# Opens at http://localhost:5173
```

---

## Step 10 — Test the integration end to end

1. Open `http://localhost:5173`
2. Click **Start Scan** on landing page
3. Enter any target URL on NewScan page
4. Click **Begin Audit** — AuthModal appears
5. Register with email/password (e.g. `test@test.com` / `TestPass1`)
6. After login, scan starts automatically
7. LiveScan terminal shows real log entries from WebSocket
8. Progress bar updates in real time
9. Vulnerabilities appear in Results page as they are found
10. After completion, Reports page → Export Full Audit downloads PDF

---

## What was NOT changed

| File | Status |
|---|---|
| `pages/Dashboard.tsx` | Untouched |
| `pages/Landing.tsx` | Untouched |
| `pages/LiveScan.tsx` | Untouched |
| `pages/NewScan.tsx` | Untouched |
| `pages/Results.tsx` | Untouched |
| `components/Modal.tsx` | Untouched |
| `components/Navbar.tsx` | Untouched |
| `components/Sidebar.tsx` | Untouched |
| `components/StatCard.tsx` | Untouched |
| `components/Terminal.tsx` | Untouched |
| `types.ts` | Untouched |
| `constants.tsx` | Untouched |
| `index.tsx` | Untouched |
| `index.html` | Untouched |
| `tailwind.config.js` | Untouched |

**Changed/Added in frontend:**
- `App.tsx` — replaced (same structure, same state shapes)
- `services/api.ts` — new file
- `components/AuthModal.tsx` — new file
- `.env` — new file
- `vite.config.ts` — proxy added

**Changed in backend:**
- `app/api/routes/auth.py` — login uses `UserLoginRequest` JSON instead of form data