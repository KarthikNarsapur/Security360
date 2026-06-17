// components/Framework/shared/SummaryCards.jsx
import { CheckCircle, XCircle, AlertTriangle, Activity } from "lucide-react";

/**
 * The 4 overview stat cards shown below the charts.
 * Clickable — calls onCardClick(filter) to filter findings in-page.
 *
 * Props:
 *   meta — { totalScanned, totalAffected, severityCounts, securityScore }
 *   onCardClick — fn(filter) where filter is "passed"|"failed"|"critical"|"all"
 */
const SummaryCards = ({ meta, onCardClick }) => {
  const passed = (meta?.totalScanned || 0) - (meta?.totalAffected || 0);
  const failed = meta?.totalAffected || 0;
  const critical = meta?.severityCounts?.Critical || 0;
  const total = meta?.totalScanned || 0;

  const cards = [
    { label: "Passed", value: passed, color: "text-green-600", icon: <CheckCircle className="w-8 h-8 text-green-500" />, filter: "passed" },
    { label: "Total Affected", value: failed, color: "text-red-600", icon: <XCircle className="w-8 h-8 text-red-500" />, filter: "failed" },
    { label: "Critical Issues", value: critical, color: "text-red-700", icon: <AlertTriangle className="w-8 h-8 text-orange-500" />, filter: "critical" },
    { label: "Total Scanned", value: total, color: "text-indigo-600", icon: <Activity className="w-8 h-8 text-indigo-500" />, filter: "all" },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
      {cards.map((card) => (
        <div
          key={card.label}
          onClick={() => onCardClick?.(card.filter)}
          className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 transition-all duration-200 hover:scale-105 cursor-pointer"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-slate-600 dark:text-slate-400">{card.label}</p>
              <p className={`text-4xl font-bold ${card.color}`}>{card.value}</p>
            </div>
            {card.icon}
          </div>
        </div>
      ))}
    </div>
  );
};

export default SummaryCards;
