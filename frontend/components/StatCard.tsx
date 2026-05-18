
import React from 'react';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  trend?: string;
  trendType?: 'up' | 'down';
}

const StatCard: React.FC<StatCardProps> = ({ label, value, icon, trend, trendType }) => {
  // Check if the value is a long string to adjust font size dynamically
  const isLongValue = typeof value === 'string' && value.length > 10;

  return (
    <div className="bg-white border-2 border-slate-100 p-7 rounded-[2.5rem] flex items-start justify-between shadow-soft hover-lift transition-all min-h-[180px] overflow-hidden group">
      <div className="flex-1 min-w-0 pr-2 h-full flex flex-col">
        <p className="text-slate-400 text-[9px] font-black uppercase tracking-[0.2em] mb-3 truncate">
          {label}
        </p>
        
        <h3 className={`font-black text-slate-900 tracking-tighter mb-auto ${
          isLongValue ? 'text-2xl leading-tight' : 'text-4xl'
        }`}>
          {value}
        </h3>

        {trend && (
          <div className="mt-4">
            <span className={`inline-flex items-center text-[9px] font-black px-4 py-1.5 rounded-full uppercase tracking-widest whitespace-nowrap ${
              trendType === 'down' ? 'bg-rose-100 text-rose-600' : 'bg-emerald-100 text-emerald-600'
            }`}>
              {trend}
            </span>
          </div>
        )}
      </div>

      <div className={`p-4 rounded-2xl shrink-0 group-hover:scale-110 transition-transform duration-300 ${
        trendType === 'down' ? 'bg-rose-50 text-rose-500' : 'bg-emerald-50 text-emerald-500'
      }`}>
        {React.isValidElement(icon) ? React.cloneElement(icon as React.ReactElement<any>, { size: 24, strokeWidth: 2.5 }) : icon}
      </div>
    </div>
  );
};

export default StatCard;
