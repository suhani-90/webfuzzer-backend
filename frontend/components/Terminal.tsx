
import React, { useEffect, useRef } from 'react';
import { ScanLog } from '../types';

interface TerminalProps {
  logs: ScanLog[];
}

const Terminal: React.FC<TerminalProps> = ({ logs }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="bg-[#1E293B] border-4 border-slate-800 rounded-[3rem] overflow-hidden shadow-2xl flex flex-col h-[600px] relative">
      <div className="bg-[#0F172A] px-10 py-5 border-b border-slate-800 flex items-center justify-between">
        <div className="flex gap-2.5">
          <div className="w-3.5 h-3.5 rounded-full bg-rose-500"></div>
          <div className="w-3.5 h-3.5 rounded-full bg-amber-500"></div>
          <div className="w-3.5 h-3.5 rounded-full bg-emerald-500"></div>
        </div>
        <span className="text-[10px] text-slate-500 mono font-black uppercase tracking-[0.25em]">smartfuzz_core_v3.runtime</span>
        <div className="w-12"></div>
      </div>
      <div 
        ref={scrollRef}
        className="flex-1 p-10 mono text-[13px] overflow-y-auto space-y-3 selection:bg-emerald-500/30 selection:text-white"
      >
        {logs.length === 0 ? (
          <div className="text-slate-500 italic font-bold">Ready for deployment. Awaiting AI initialization pulse...</div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="grid grid-cols-[110px_70px_50px_1fr_180px] gap-6 py-2.5 px-5 rounded-2xl hover:bg-slate-800/50 transition-colors group">
              <span className="text-slate-500 font-bold group-hover:text-slate-400">[{log.timestamp}]</span>
              <span className="text-emerald-500 font-black tracking-widest">{log.method}</span>
              <span className={`font-black ${log.status >= 500 ? 'text-rose-500' : log.status >= 400 ? 'text-amber-500' : 'text-emerald-400'}`}>
                {log.status}
              </span>
              <span className="text-slate-300 font-medium truncate">
                {log.url}
              </span>
              <span className="text-slate-500 truncate text-right text-[11px] font-bold">
                payload: <span className="text-emerald-500/70">{log.payload}</span>
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Terminal;
