// components/Framework/shared/ScanCharts.jsx
import { Doughnut, Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
} from "chart.js";
import {
  buildDoughnutData,
  buildBarData,
  DOUGHNUT_OPTIONS,
  BAR_OPTIONS,
} from "../../../utils/frameworkUtils";

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
);

/**
 * Security score doughnut + severity bar chart side by side.
 * Identical layout to CIS dashboard charts.
 *
 * Props:
 *   meta — { securityScore, totalScanned, totalAffected, severityCounts }
 */
const ScanCharts = ({ meta }) => {
  const score = meta?.securityScore || 0;
  const scanned = meta?.totalScanned || 0;
  const affected = meta?.totalAffected || 0;
  const counts = meta?.severityCounts || {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
      {/* Doughnut — Security Score */}
      <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
          Security Score
        </h2>
        <div className="relative h-64">
          <Doughnut
            data={buildDoughnutData(score)}
            options={DOUGHNUT_OPTIONS}
          />
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <div className="text-4xl font-bold text-slate-900 dark:text-white">
                {score}%
              </div>
              <div className="text-sm text-slate-500 dark:text-slate-400">
                Security Score
              </div>
            </div>
          </div>
        </div>
        <div className="mt-4 text-center text-sm text-slate-600 dark:text-slate-400">
          {scanned - affected} of {scanned} checks passed
        </div>
      </div>

      {/* Bar — Findings by Severity */}
      <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
          Findings by Severity
        </h2>
        <div className="h-64">
          <Bar data={buildBarData(counts)} options={BAR_OPTIONS} />
        </div>
      </div>
    </div>
  );
};

export default ScanCharts;
