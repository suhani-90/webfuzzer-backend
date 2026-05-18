
import React from 'react';
import { Globe, Bug, Database, Activity, Play, Zap } from 'lucide-react';
import StatCard from '../components/StatCard';
import { Vulnerability } from '../types';

interface DashboardProps {
  progress: number;
  onNewScan: () => void;
  isScanning: boolean;
  vulnerabilities: Vulnerability[];
  totalRequests: number;
  totalEndpoints: number;
}

const Dashboard: React.FC<DashboardProps> = ({ progress, onNewScan, isScanning, vulnerabilities, totalRequests, totalEndpoints }) => {
  const criticalCount = vulnerabilities.filter(v => v.severity === 'High').length;
  
  const vulnStats = [
    { label: 'SQL Injection', count: vulnerabilities.filter(v => v.type === 'SQL Injection').length, max: 10, color: 'bg-rose-500' },
    { label: 'XSS (Reflected)', count: vulnerabilities.filter(v => v.type === 'Cross-Site Scripting').length, max: 10, color: 'bg-amber-500' },
    { label: 'Broken Auth', count: vulnerabilities.filter(v => v.type === 'Broken Auth').length, max: 10, color: 'bg-emerald-500' },
    { label: 'Other Vectors', count: vulnerabilities.filter(v => !['SQL Injection', 'Cross-Site Scripting', 'Broken Auth'].includes(v.type)).length, max: 10, color: 'bg-slate-400' },
  ];

  return (
    <div className="space-y-12 animate-in fade-in duration-1000">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <h1 className="text-5xl font-black text-slate-900 tracking-tight">Security <span className="text-emerald-500">Suite</span></h1>
          <p className="text-slate-500 mt-2 font-bold text-lg">Targeting vulnerabilities with surgical precision.</p>
        </div>
        <button 
          onClick={onNewScan}
          disabled={isScanning}
          className="flex items-center justify-center gap-4 px-10 py-5 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-white rounded-[1.5rem] font-black transition-all shadow-xl shadow-emerald-100 group active:scale-95 whitespace-nowrap"
        >
          <Play size={20} fill="currentColor" strokeWidth={2.5} className="group-hover:translate-x-1 transition-transform" />
          {isScanning ? 'Scan Active' : 'Launch Fuzzer'}
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
        <StatCard 
          label="Endpoints Hit" 
          value={totalEndpoints.toLocaleString()} 
          icon={<Globe />} 
          trend={isScanning ? "Active Mapped" : ""} 
          trendType="up" 
        />
        <StatCard 
          label="Total Requests" 
          value={totalRequests.toLocaleString()} 
          icon={<Database />} 
          trend={isScanning ? "Burst Mode" : ""} 
          trendType="up" 
        />
        <StatCard 
          label="Critical Threats" 
          value={criticalCount.toString().padStart(2, '0')} 
          icon={<Bug />} 
          trend={criticalCount > 0 ? "Action Required" : "Clean"} 
          trendType={criticalCount > 0 ? "down" : "up"} 
        />
        <StatCard 
          label="AI Logic Pulse" 
          value={isScanning ? "Synchronized" : "Standby"} 
          icon={<Zap />} 
          trendType="up"
        />
      </div>

      <div className="bg-white border-2 border-slate-100 rounded-[3rem] p-12 shadow-soft relative overflow-hidden group">
        <div className="absolute top-0 right-0 w-48 h-48 bg-emerald-50/50 rounded-full -mr-24 -mt-24 group-hover:scale-110 transition-transform duration-700"></div>
        
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-12 gap-6">
          <div className="flex items-center gap-6">
            <div className={`w-5 h-5 rounded-full ${isScanning ? 'bg-emerald-500 shadow-[0_0_20px_rgba(16,185,129,0.5)] animate-pulse' : 'bg-slate-300'}`}></div>
            <h2 className="text-3xl font-black text-slate-900 tracking-tight">Sequence Execution</h2>
          </div>
          <span className="text-xs font-black text-emerald-600 bg-emerald-50 px-6 py-2.5 rounded-full border-2 border-emerald-100 uppercase tracking-widest">{progress}% Analyzed</span>
        </div>
        
        <div className="w-full bg-slate-100 h-8 rounded-full overflow-hidden mb-12 shadow-inner border-4 border-white">
          <div 
            className="h-full bg-emerald-500 transition-all duration-1000 ease-out rounded-full shadow-lg shadow-emerald-100"
            style={{ width: `${progress}%` }}
          ></div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-10">
          {[
            { label: 'Audit Velocity', val: isScanning ? `${Math.floor(Math.random() * 50 + 200)} req/s` : '0 req/s', icon: <Zap size={22} />, color: 'text-emerald-600' },
            { label: 'Avg Latency', val: isScanning ? `${Math.floor(Math.random() * 20 + 30)}ms` : '0ms', icon: <Activity size={22} />, color: 'text-slate-900' },
            { label: 'Findings Logged', val: vulnerabilities.length.toString(), icon: <Bug size={22} />, color: 'text-rose-600' },
          ].map((item, idx) => (
            <div key={idx} className="p-8 bg-slate-50/50 rounded-[2.5rem] border-2 border-slate-100 flex flex-col items-center text-center hover-lift transition-all">
              <div className={`mb-4 ${item.color} p-3 bg-white rounded-2xl shadow-sm border border-slate-100`}>
                {item.icon}
              </div>
              <p className="text-[10px] text-slate-400 mb-3 uppercase tracking-[0.2em] font-black">{item.label}</p>
              <div className={`flex items-center gap-3 mb-1 ${item.color}`}>
                <p className="text-4xl font-black tracking-tighter">{item.val}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-10 pb-12">
        <div className="bg-white border-2 border-slate-100 rounded-[3rem] p-12 shadow-soft">
          <h2 className="text-2xl font-black text-slate-900 mb-12 flex items-center gap-4">
            <span className="w-2 h-10 bg-emerald-500 rounded-full"></span>
            Threat Surface Distribution
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-x-20 gap-y-10">
            {vulnStats.map((item) => (
              <div key={item.label} className="space-y-4">
                <div className="flex justify-between items-end">
                  <span className="text-sm font-black text-slate-600 uppercase tracking-widest">{item.label}</span>
                  <span className="text-slate-900 text-[10px] font-black mono bg-slate-100 px-4 py-2 rounded-xl border border-slate-200 uppercase tracking-widest">{item.count} Detected</span>
                </div>
                <div className="w-full bg-slate-100 h-4 rounded-full overflow-hidden border-2 border-white shadow-inner">
                  <div 
                    className={`h-full ${item.color} rounded-full transition-all duration-1000 shadow-sm`} 
                    style={{ width: `${Math.min((item.count / item.max) * 100, 100)}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
