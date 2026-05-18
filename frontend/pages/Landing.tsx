
import React from 'react';
import { Zap, Shield, Activity, FileText, Download, Search, Target, ChevronRight, Sparkles } from 'lucide-react';

interface LandingProps {
  onStartScan: () => void;
}

interface FeatureItem {
  icon: React.ReactNode;
  title: string;
  desc: string;
}

const Landing: React.FC<LandingProps> = ({ onStartScan }) => {
  const features: FeatureItem[] = [
    { 
      icon: <Sparkles className="text-emerald-500" />, 
      title: 'AI Payload Synthesis', 
      desc: 'Gemini 3 dynamically generates sophisticated attack vectors based on your target URL and scan parameters.' 
    },
    { 
      icon: <Search className="text-emerald-500" />, 
      title: 'Intelligent Fuzzing', 
      desc: 'Multi-threaded execution engine with smart rate limiting to detect SQLi, XSS, and broken authentication.' 
    },
    { 
      icon: <Shield className="text-emerald-500" />, 
      title: 'Evidence Validation', 
      desc: 'View actual response snippets and forensics for every finding to eliminate noise and verify threats.' 
    },
    { 
      icon: <Zap className="text-emerald-500" />, 
      title: 'Live Runtime Stream', 
      desc: 'Monitor the fuzzer activity in real-time with our high-fidelity terminal interface and live metrics.' 
    },
    { 
      icon: <FileText className="text-emerald-500" />, 
      title: 'Remediation Intelligence', 
      desc: 'Every vulnerability comes with bespoke fix recommendations and remediation guidance for your developers.' 
    },
    { 
      icon: <Activity className="text-emerald-500" />, 
      title: 'Threat Surface Mapping', 
      desc: 'Visualize your security posture with dashboard analytics covering hit rates, latency, and threat distribution.' 
    },
    { 
      icon: <Target className="text-emerald-500" />, 
      title: 'Adaptive Depth Control', 
      desc: 'Tune your audit intensity with configurable scan iterations and focused payload logic for specific vectors.' 
    },
    { 
      icon: <Download className="text-emerald-500" />, 
      title: 'Audit-Ready Exports', 
      desc: 'Instantly generate CSV datasets or detailed text reports for stakeholders and compliance forensics.' 
    }
  ];

  return (
    <div className="bg-white min-h-screen">
      {/* Hero Section */}
      <section className="pt-20 pb-32 px-6">
        <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
          <div className="space-y-8 animate-in slide-in-from-left duration-1000">
            <div className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-50 border border-emerald-100 rounded-full text-emerald-600 text-xs font-black uppercase tracking-widest">
              <Zap size={14} fill="currentColor" />
              AI-Powered Security Testing
            </div>
            
            <h1 className="text-7xl font-black text-slate-900 leading-[1.1] tracking-tight">
              Intelligent <span className="text-emerald-500">Fuzzing</span> for Modern Web Security
            </h1>
            
            <p className="text-xl text-slate-500 font-medium leading-relaxed max-w-xl">
              Detect vulnerabilities with precision using AI-enhanced payload generation. SmartFuzz combines intelligent fuzzing with real-time analysis to protect your web applications from SQLi, XSS, and beyond.
            </p>
            
            <div className="flex flex-wrap gap-4 pt-4">
              <button 
                onClick={onStartScan}
                className="px-10 py-5 bg-emerald-500 hover:bg-emerald-600 text-white rounded-2xl font-black text-lg transition-all shadow-xl shadow-emerald-100 flex items-center gap-3 active:scale-95"
              >
                Start Scan <ChevronRight size={20} strokeWidth={3} />
              </button>
            </div>
          </div>

          <div className="relative animate-in zoom-in duration-1000 delay-200">
            <div className="absolute -top-10 -right-10 w-64 h-64 bg-emerald-100/50 rounded-full blur-3xl -z-10"></div>
            <div className="absolute -bottom-10 -left-10 w-64 h-64 bg-indigo-100/50 rounded-full blur-3xl -z-10"></div>
            
            {/* Terminal Mockup */}
            <div className="bg-[#1E293B] rounded-[2rem] overflow-hidden shadow-2xl border-4 border-slate-800">
              <div className="bg-[#0F172A] px-6 py-4 flex items-center justify-between border-b border-slate-800">
                <div className="flex gap-2">
                  <div className="w-3 h-3 rounded-full bg-rose-500"></div>
                  <div className="w-3 h-3 rounded-full bg-amber-500"></div>
                  <div className="w-3 h-3 rounded-full bg-emerald-500"></div>
                </div>
                <div className="text-[10px] text-slate-500 font-bold tracking-widest uppercase mono">smartfuzz --scan active</div>
              </div>
              <div className="p-8 mono text-sm space-y-4">
                <div className="flex gap-3">
                  <Target size={18} className="text-emerald-500" />
                  <span className="text-slate-400">Target: <span className="text-indigo-400">https://example.com/api</span></span>
                </div>
                <div className="flex items-center gap-2 text-emerald-400">
                  <ChevronRight size={16} />
                  <span>Initializing AI payload generator...</span>
                </div>
                <div className="mt-8 pt-8 border-t border-slate-700">
                  <div className="bg-amber-900/20 border border-amber-500/30 p-5 rounded-2xl space-y-2">
                    <div className="flex items-center gap-2 text-amber-500 font-black text-xs uppercase tracking-widest">
                      <Shield size={14} fill="currentColor" />
                      Vulnerability Found
                    </div>
                    <p className="text-amber-100 font-bold">SQLi detected in /api/users?id=</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Hero Stats */}
        <div className="max-w-4xl mx-auto mt-24 grid grid-cols-1 md:grid-cols-2 gap-12 text-center">
          <div className="space-y-1">
            <div className="text-6xl font-black text-emerald-500 tracking-tighter">92%</div>
            <div className="text-slate-500 font-bold text-lg uppercase tracking-widest">Detection Rate</div>
          </div>
          <div className="space-y-1">
            <div className="text-6xl font-black text-slate-900 tracking-tighter">5%</div>
            <div className="text-slate-500 font-bold text-lg uppercase tracking-widest">False Positives</div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="bg-slate-50 py-32 px-6">
        <div className="max-w-7xl mx-auto space-y-20">
          <div className="text-center space-y-6 max-w-3xl mx-auto">
            <h2 className="text-5xl font-black text-slate-900 tracking-tight">
              Security Testing, <span className="text-emerald-500">Reimagined</span>
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature: FeatureItem, i: number) => (
              <div key={i} className="bg-white p-10 rounded-[2.5rem] border-2 border-transparent hover:border-emerald-100 shadow-soft hover-lift transition-all group">
                <div className="w-14 h-14 bg-slate-50 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-emerald-50 group-hover:scale-110 transition-all">
                  {React.isValidElement(feature.icon) ? React.cloneElement(feature.icon as React.ReactElement<any>, { size: 28, strokeWidth: 2.5 }) : feature.icon}
                </div>
                <h3 className="text-xl font-black text-slate-900 mb-3">{feature.title}</h3>
                <p className="text-slate-500 text-sm font-bold leading-relaxed">{feature.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer Section */}
      <footer className="bg-white pb-12 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="pt-12 border-t border-slate-100 flex flex-col md:flex-row justify-between items-center gap-6">
            <span className="text-slate-400 font-bold text-sm">
              © 2026 SmartFuzz. All rights reserved.
            </span>
            <span className="text-slate-400 font-black text-xs uppercase tracking-[0.2em]">
              Next-Gen Security Engineering • SmartFuzz by 4 bits
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
