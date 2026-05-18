
import React from 'react';
import { X, ExternalLink, ShieldCheck, AlertTriangle } from 'lucide-react';
import { Vulnerability } from '../types';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  vulnerability: Vulnerability | null;
}

const Modal: React.FC<ModalProps> = ({ isOpen, onClose, vulnerability }) => {
  if (!isOpen || !vulnerability) return null;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 md:p-6 bg-slate-900/60 backdrop-blur-md">
      <div className="bg-white w-full max-w-2xl rounded-[3rem] shadow-[0_32px_128px_rgba(0,0,0,0.25)] overflow-hidden animate-in fade-in zoom-in duration-300 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-8 md:p-10 flex items-start justify-between relative">
          <div className="flex items-center gap-6">
            <div className={`p-4 rounded-2xl ${
              vulnerability.severity === 'High' ? 'bg-rose-50 text-rose-500' : 
              vulnerability.severity === 'Medium' ? 'bg-amber-50 text-amber-500' : 'bg-emerald-50 text-emerald-600'
            }`}>
              <AlertTriangle size={40} strokeWidth={2} />
            </div>
            <div>
              <h2 className="text-3xl font-black text-slate-900 tracking-tight leading-none mb-3">
                {vulnerability.type}
              </h2>
              <div className="inline-flex items-center px-4 py-1.5 rounded-full bg-slate-50 border border-slate-100 text-[10px] font-black text-slate-400 uppercase tracking-[0.15em]">
                Report ID: SEC-{vulnerability.id.toUpperCase()}
              </div>
            </div>
          </div>
          <button 
            onClick={onClose} 
            className="p-2 text-slate-300 hover:text-slate-900 transition-colors absolute top-8 right-8"
          >
            <X size={32} strokeWidth={2.5} />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto px-8 md:px-10 pb-10 space-y-10 custom-scrollbar">
          {/* Affected Resource */}
          <section>
            <h3 className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] mb-4">Affected Resource</h3>
            <div className="bg-emerald-50/30 p-5 rounded-2xl border border-emerald-100/50 flex items-center justify-between group cursor-pointer hover:bg-emerald-50 transition-colors">
              <code className="text-emerald-700 text-sm mono font-bold truncate pr-4">{vulnerability.url}</code>
              <ExternalLink size={18} className="text-slate-300 group-hover:text-emerald-600 transition-colors shrink-0" />
            </div>
          </section>

          {/* Grid: Target Attribute & Threat Rating */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <section>
              <h3 className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] mb-4">Target Attribute</h3>
              <div className="bg-emerald-50 px-5 py-3 rounded-xl inline-flex border border-emerald-100">
                <span className="text-emerald-700 font-black mono text-sm">{vulnerability.parameter}</span>
              </div>
            </section>
            <section>
              <h3 className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] mb-4">Threat Rating</h3>
              <div className={`px-5 py-3 rounded-xl text-[10px] font-black uppercase tracking-widest border inline-flex ${
                vulnerability.severity === 'High' ? 'bg-rose-50 text-rose-600 border-rose-100' : 
                vulnerability.severity === 'Medium' ? 'bg-amber-50 text-amber-600 border-amber-100' : 
                'bg-emerald-50 text-emerald-600 border-emerald-100'
              }`}>
                {vulnerability.severity} Risk Factor
              </div>
            </section>
          </div>

          {/* Active Payload */}
          <section>
            <h3 className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] mb-4">Active Payload</h3>
            <div className="bg-slate-50 p-6 rounded-2xl border border-slate-100 shadow-inner">
              <code className="text-amber-600 text-sm md:text-base mono font-black break-all">{vulnerability.payload}</code>
            </div>
          </section>

          {/* Response Excerpt */}
          <section>
            <h3 className="text-[11px] font-black text-slate-400 uppercase tracking-[0.2em] mb-4">Response Excerpt</h3>
            <div className="bg-[#1E293B] p-6 rounded-2xl mono text-[12px] text-slate-300 leading-relaxed shadow-lg border border-slate-700/50">
              <div className="flex items-center gap-2 mb-3 text-emerald-400 text-[10px] font-black uppercase tracking-widest opacity-80">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                Inbound Response Stream
              </div>
              <pre className="whitespace-pre-wrap break-all opacity-90">{vulnerability.responseSnippet}</pre>
            </div>
          </section>

          {/* Remediation Guide */}
          <section className="bg-emerald-500/5 border border-emerald-500/10 p-8 rounded-3xl relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:scale-125 transition-transform duration-500">
              <ShieldCheck size={80} />
            </div>
            <div className="flex items-center gap-3 mb-4">
              <ShieldCheck size={20} className="text-emerald-600" />
              <h3 className="text-[11px] font-black text-emerald-800 uppercase tracking-widest">Remediation Guide</h3>
            </div>
            <p className="text-sm text-slate-600 leading-relaxed font-bold relative z-10">
              {vulnerability.fixRecommendation}
            </p>
          </section>
        </div>

        {/* Footer Actions */}
        <div className="px-8 md:px-10 py-8 bg-slate-50/50 border-t border-slate-100 flex flex-col md:flex-row items-center justify-end gap-4 md:gap-6 shrink-0">
          <button 
            onClick={onClose}
            className="px-6 py-3 text-slate-400 hover:text-slate-900 transition-colors font-black text-[11px] uppercase tracking-[0.2em]"
          >
            Dismiss
          </button>
          <button className="w-full md:w-auto px-10 py-5 bg-emerald-500 hover:bg-emerald-600 text-white rounded-2xl font-black transition-all shadow-xl shadow-emerald-200 text-[11px] uppercase tracking-widest active:scale-95">
            Download Audit Report
          </button>
        </div>
      </div>
    </div>
  );
};

export default Modal;
