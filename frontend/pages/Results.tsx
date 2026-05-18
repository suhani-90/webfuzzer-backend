
import React, { useState } from 'react';
import { Search, AlertCircle, ChevronRight, Bug, Download } from 'lucide-react';
import { Vulnerability } from '../types';
import Modal from '../components/Modal';

interface ResultsProps {
  vulnerabilities: Vulnerability[];
}

const Results: React.FC<ResultsProps> = ({ vulnerabilities }) => {
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const filteredVulns = vulnerabilities.filter(v => 
    v.type.toLowerCase().includes(searchQuery.toLowerCase()) || 
    v.url.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleRowClick = (vuln: Vulnerability) => {
    setSelectedVuln(vuln);
    setIsModalOpen(true);
  };

  const handleExportCSV = () => {
    if (vulnerabilities.length === 0) return;
    
    const headers = ['ID', 'Vulnerability Type', 'Severity', 'URL', 'Parameter', 'Payload', 'Recommendation'];
    const rows = vulnerabilities.map(v => [
      v.id, 
      `"${v.type.replace(/"/g, '""')}"`, 
      v.severity, 
      `"${v.url}"`, 
      `"${v.parameter}"`, 
      `"${v.payload.replace(/"/g, '""')}"`,
      `"${v.fixRecommendation.replace(/"/g, '""')}"`
    ]);
    
    const csvContent = [headers, ...rows].map(e => e.join(",")).join("\n");
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `security_audit_export_${new Date().getTime()}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-12 animate-in fade-in duration-1000 pb-12">
      <div className="flex items-end justify-between border-b-4 border-slate-100 pb-12">
        <div>
          <h1 className="text-5xl font-black text-slate-900 tracking-tight">Audit <span className="text-emerald-500">Inventory</span></h1>
          <p className="text-slate-500 mt-2 font-bold text-lg">Verified findings from your current security dive operations.</p>
        </div>
        <button 
          onClick={handleExportCSV}
          disabled={vulnerabilities.length === 0}
          className="flex items-center gap-4 px-10 py-5 bg-white hover:bg-slate-50 disabled:opacity-50 disabled:cursor-not-allowed text-slate-900 rounded-[1.5rem] font-black transition-all border-2 border-slate-100 shadow-soft active:scale-95"
        >
          <Download size={22} className="text-emerald-500" strokeWidth={2.5} />
          Export Dataset
        </button>
      </div>

      <div className="flex gap-6">
        <div className="flex-1 relative group">
          <Search className="absolute left-8 top-1/2 -translate-y-1/2 text-slate-300 group-focus-within:text-emerald-500 transition-colors" size={24} strokeWidth={2.5} />
          <input 
            type="text" 
            placeholder="Search by vector ID or resource..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-white border-2 border-slate-100 text-slate-900 pl-20 pr-10 py-6 rounded-3xl focus:ring-4 focus:ring-emerald-50 shadow-sm outline-none transition-all placeholder:text-slate-200 font-black text-lg"
          />
        </div>
      </div>

      {vulnerabilities.length > 0 ? (
        <div className="bg-white border-2 border-slate-100 rounded-[3rem] overflow-hidden shadow-soft">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="bg-slate-50/50 border-b-2 border-slate-100">
                  <th className="px-12 py-8 text-[11px] font-black text-slate-400 uppercase tracking-[0.25em]">Threat Class</th>
                  <th className="px-12 py-8 text-[11px] font-black text-slate-400 uppercase tracking-[0.25em]">Target Endpoint</th>
                  <th className="px-12 py-8 text-[11px] font-black text-slate-400 uppercase tracking-[0.25em]">Attribute</th>
                  <th className="px-12 py-8 text-[11px] font-black text-slate-400 uppercase tracking-[0.25em]">Risk Rating</th>
                  <th className="px-12 py-8 text-[11px] font-black text-slate-400 uppercase tracking-[0.25em] text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y-2 divide-slate-50">
                {filteredVulns.map((vuln) => (
                  <tr 
                    key={vuln.id} 
                    className="hover:bg-emerald-50/30 transition-colors cursor-pointer group"
                    onClick={() => handleRowClick(vuln)}
                  >
                    <td className="px-12 py-10">
                      <div className="flex items-center gap-6">
                        <div className={`p-4 rounded-2xl shadow-sm ${
                          vuln.severity === 'High' ? 'text-rose-500 bg-rose-50' : 
                          vuln.severity === 'Medium' ? 'text-amber-500 bg-amber-50' : 'text-emerald-600 bg-emerald-50'
                        }`}>
                          <AlertCircle size={24} strokeWidth={2.5} />
                        </div>
                        <span className="text-slate-900 font-black tracking-tight text-lg">{vuln.type}</span>
                      </div>
                    </td>
                    <td className="px-12 py-10">
                      <div className="max-w-[250px] truncate text-slate-500 text-xs font-black mono bg-slate-100 px-4 py-2.5 rounded-xl border border-slate-200">
                        {vuln.url}
                      </div>
                    </td>
                    <td className="px-12 py-10">
                      <span className="text-slate-900 text-sm font-black mono bg-white px-4 py-2 rounded-xl border-2 border-slate-100">{vuln.parameter}</span>
                    </td>
                    <td className="px-12 py-10">
                      <span className={`px-6 py-2 rounded-full text-[10px] font-black uppercase tracking-widest border-2 shadow-sm ${
                        vuln.severity === 'High' ? 'bg-rose-50 text-rose-600 border-rose-100' : 
                        vuln.severity === 'Medium' ? 'bg-amber-50 text-amber-600 border-amber-100' : 
                        'bg-emerald-50 text-emerald-600 border-emerald-100'
                      }`}>
                        {vuln.severity}
                      </span>
                    </td>
                    <td className="px-12 py-10 text-right">
                      <button className="text-slate-400 group-hover:text-emerald-600 transition-all flex items-center gap-3 ml-auto text-[11px] font-black uppercase tracking-widest">
                        View Forensics
                        <ChevronRight size={20} strokeWidth={3} className="group-hover:translate-x-1 transition-transform" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="bg-white border-2 border-slate-100 rounded-[3.5rem] p-32 flex flex-col items-center justify-center text-center shadow-soft">
           <div className="w-32 h-32 bg-emerald-50 rounded-full flex items-center justify-center mb-10 border-2 border-emerald-100 relative">
              <Bug size={56} className="text-emerald-300" strokeWidth={2.5} />
              <div className="absolute inset-0 bg-emerald-100/20 rounded-full animate-pulse"></div>
           </div>
           <h3 className="text-3xl font-black text-slate-900 tracking-tight">Observation Mode Active</h3>
           <p className="text-slate-500 font-bold mt-4 max-w-sm text-lg leading-relaxed">No security anomalies detected in the current stream. Any identified threats will populate this inventory automatically.</p>
        </div>
      )}

      <Modal 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)} 
        vulnerability={selectedVuln} 
      />
    </div>
  );
};

export default Results;
