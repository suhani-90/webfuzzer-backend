
import React, { useMemo } from 'react';
import Terminal from '../components/Terminal';
import { ScanLog } from '../types';
import { Activity, ShieldAlert, Search, Sparkles, Loader2 } from 'lucide-react';

interface LiveScanProps {
  logs: ScanLog[];
  progress: number;
  isScanning: boolean;
  isAiThinking?: boolean;
}

const LiveScan: React.FC<LiveScanProps> = ({ logs, progress, isScanning, isAiThinking }) => {
  const stats = useMemo(() => {
    if (logs.length === 0) return { success: 0, missing: 0, errors: 0 };
    const success = logs.filter(l => l.status < 400).length;
    const missing = logs.filter(l => l.status >= 400 && l.status < 500).length;
    const errors = logs.filter(l => l.status >= 500).length;
    const total = logs.length;
    
    return {
      success: ((success / total) * 100).toFixed(1),
      missing: ((missing / total) * 100).toFixed(1),
      errors: ((errors / total) * 100).toFixed(1),
    };
  }, [logs]);

  return (
    <div className="space-y-12 animate-in fade-in duration-700 pb-12">
      <div className="flex items-center justify-between border-b-4 border-slate-100 pb-12">
        <div>
          <h1 className="text-5xl font-black text-slate-900 tracking-tight">Runtime <span className="text-emerald-500">Stream</span></h1>
          <p className="text-slate-500 mt-2 font-bold text-lg">Real-time fuzzer activity and AI-generated payload analysis.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-12">
        <div className="lg:col-span-2">
          {isAiThinking && logs.length === 0 ? (
            <div className="bg-white border-2 border-slate-100 rounded-[3rem] h-[600px] flex flex-col items-center justify-center p-12 text-center shadow-soft">
              <div className="p-8 bg-emerald-50 rounded-full mb-10 relative">
                <Sparkles size={64} className="text-emerald-500 animate-pulse" fill="currentColor" />
                <div className="absolute inset-0 bg-emerald-200/20 rounded-full animate-ping"></div>
              </div>
              <h3 className="text-3xl font-black text-slate-900 mb-6 tracking-tight">AI Brainstorming Initialized</h3>
              <p className="text-slate-500 font-bold max-w-sm mx-auto leading-relaxed text-lg">
                Gemini is currently analyzing your target URL and synthesizing a bespoke set of security vectors...
              </p>
              <div className="mt-10 flex items-center gap-4 text-emerald-600 font-black text-sm uppercase tracking-[0.2em] bg-emerald-50 px-8 py-3 rounded-full border-2 border-emerald-100">
                <Loader2 size={20} className="animate-spin" strokeWidth={3} />
                Building Wordlist
              </div>
            </div>
          ) : (
            <Terminal logs={logs} />
          )}
        </div>
        
        <div className="space-y-10">
           <div className="bg-white border-2 border-slate-100 rounded-[3rem] p-12 shadow-soft">
              <h3 className="text-slate-900 font-black mb-10 flex items-center gap-5">
                <div className="p-3 bg-emerald-50 rounded-2xl">
                  <Search size={24} className="text-emerald-500" strokeWidth={3} />
                </div>
                Audit Metrics
              </h3>
              <div className="space-y-8">
                 <div className="space-y-3">
                    <div className="flex justify-between text-[11px] font-black uppercase tracking-widest">
                       <span className="text-slate-400">Stable Response (2xx/3xx)</span>
                       <span className="text-emerald-600 mono">{stats.success}%</span>
                    </div>
                    <div className="w-full h-3 bg-slate-50 rounded-full overflow-hidden border-2 border-slate-100">
                       <div className="bg-emerald-500 h-full rounded-full transition-all duration-500 shadow-sm" style={{ width: `${stats.success}%` }}></div>
                    </div>
                 </div>
                 <div className="space-y-3">
                    <div className="flex justify-between text-[11px] font-black uppercase tracking-widest">
                       <span className="text-slate-400">Endpoint Missing (404)</span>
                       <span className="text-amber-600 mono">{stats.missing}%</span>
                    </div>
                    <div className="w-full h-3 bg-slate-50 rounded-full overflow-hidden border-2 border-slate-100">
                       <div className="bg-amber-500 h-full rounded-full transition-all duration-500 shadow-sm" style={{ width: `${stats.missing}%` }}></div>
                    </div>
                 </div>
                 <div className="space-y-3">
                    <div className="flex justify-between text-[11px] font-black uppercase tracking-widest">
                       <span className="text-slate-400">Threat Anomalies (5xx)</span>
                       <span className="text-rose-600 mono">{stats.errors}%</span>
                    </div>
                    <div className="w-full h-3 bg-slate-50 rounded-full overflow-hidden border-2 border-slate-100">
                       <div className="bg-rose-500 h-full rounded-full transition-all duration-500 shadow-sm" style={{ width: `${stats.errors}%` }}></div>
                    </div>
                 </div>
              </div>
           </div>

           <div className="bg-white border-2 border-slate-100 rounded-[3rem] p-12 shadow-soft">
              <h3 className="text-slate-900 font-black mb-10 flex items-center gap-5">
                <div className="p-3 bg-rose-50 rounded-2xl">
                  <ShieldAlert size={24} className="text-rose-600" strokeWidth={3} />
                </div>
                Active Alarms
              </h3>
              <div className="space-y-5">
                 {logs.filter(l => l.status >= 500).slice(-3).map((alert, i) => (
                    <div key={i} className="p-5 bg-rose-50 border-2 border-rose-100 rounded-[1.5rem] animate-in slide-in-from-right-4">
                       <p className="text-rose-600 font-black text-[10px] uppercase tracking-widest mb-2">Threat Detected</p>
                       <p className="text-slate-600 truncate mono text-[11px] font-bold">{alert.url}</p>
                    </div>
                 ))}
                 {logs.filter(l => l.status >= 500).length === 0 && (
                   <div className="text-center py-10">
                      <div className="w-16 h-16 bg-slate-50 rounded-full flex items-center justify-center mx-auto mb-6 border-2 border-slate-100">
                        <Activity size={28} className="text-slate-300" />
                      </div>
                      <p className="text-slate-400 text-sm font-black uppercase tracking-widest">Listening for Pulse...</p>
                   </div>
                 )}
              </div>
           </div>

           <div className="bg-emerald-500 p-12 rounded-[3rem] text-center shadow-xl shadow-emerald-100">
              <p className="text-emerald-50 text-[11px] uppercase tracking-[0.25em] font-black mb-4">Current Audit Depth</p>
              <div className="text-6xl font-black text-white mb-8 tracking-tighter">{progress}%</div>
              <div className="w-full h-5 bg-emerald-900/20 rounded-full overflow-hidden border-2 border-emerald-400/50">
                 <div className="bg-white h-full rounded-full transition-all duration-500 shadow-lg" style={{ width: `${progress}%` }}></div>
              </div>
           </div>
        </div>
      </div>
    </div>
  );
};

export default LiveScan;
