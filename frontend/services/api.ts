
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
