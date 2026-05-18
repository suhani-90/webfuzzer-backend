
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
