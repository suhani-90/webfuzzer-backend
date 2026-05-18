
import React from 'react';
import { Shield } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onSignIn?: () => void;
}

const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab }) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'scans', label: 'Scans' },
    { id: 'results', label: 'Results' },
    { id: 'reports', label: 'Reports' },
  ];

  return (
    <header className="sticky top-0 z-50 w-full bg-white/80 backdrop-blur-md border-b border-slate-100">
      <div className="max-w-7xl mx-auto px-6 h-24 flex items-center justify-between">
        {/* Brand Logo */}
        <div 
          className="flex items-center gap-4 cursor-pointer group shrink-0" 
          onClick={() => setActiveTab('landing')}
        >
          <div className="bg-emerald-500 p-2.5 rounded-2xl shadow-lg shadow-emerald-100 group-hover:rotate-6 transition-all duration-300">
            <Shield className="text-white" size={26} fill="currentColor" />
          </div>
          <span className="text-2xl font-black text-slate-900 tracking-tighter">SmartFuzz</span>
        </div>

        {/* Navigation - Properly aligned to the right side of the container */}
        <nav className="hidden md:flex items-center gap-10 lg:gap-14">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`relative py-2 text-[15px] font-black tracking-tight transition-all duration-300 ${
                activeTab === item.id 
                  ? 'text-emerald-500' 
                  : 'text-slate-500 hover:text-slate-900'
              }`}
            >
              {item.label}
              {activeTab === item.id && (
                <span className="absolute -bottom-1 left-0 w-full h-1 bg-emerald-500 rounded-full animate-in zoom-in duration-300"></span>
              )}
            </button>
          ))}
        </nav>

        {/* Responsive Mobile Menu Trigger Placeholder (if needed in future) */}
        <div className="md:hidden flex items-center">
          <button className="p-2 text-slate-500">
            <div className="w-6 h-1 bg-slate-900 rounded-full mb-1"></div>
            <div className="w-6 h-1 bg-slate-900 rounded-full mb-1"></div>
            <div className="w-4 h-1 bg-slate-900 rounded-full ml-auto"></div>
          </button>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
