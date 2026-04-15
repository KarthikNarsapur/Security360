import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend,
} from "chart.js";
import { BarChart3, ChevronDown, ChevronUp } from "lucide-react";

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

export default function BarChartFindings({
  findings,
  isBarExpanded,
  setIsBarExpanded,
}) {
  const aggregated = {};

  findings.forEach((f) => {
    if (!f.additional_info?.total_scanned) return;
    const type = f.check_name.replaceAll("_", " ");
    if (!aggregated[type]) {
      aggregated[type] = { affected: 0, total_scanned: 0 };
    }
    aggregated[type].affected += f.additional_info?.affected || 0;
    aggregated[type].total_scanned += f.additional_info?.total_scanned || 0;
  });

  const topRows = Object.entries(aggregated)
    .sort(([, a], [, b]) => b.affected - a.affected)
    .slice(
      0,
      isBarExpanded
        ? Math.min(10, Object.keys(aggregated).length)
        : Math.min(5, Object.keys(aggregated).length)
    );

  const labels = topRows.map(([type]) => type);
  const affected = topRows.map(([, data]) => data.affected);
  const scanned = topRows.map(([, data]) => data.total_scanned);

  const handleExpand = () => {
    setIsBarExpanded(!isBarExpanded);
  };

  return (
    <div
      className={`bg-white/80 dark:bg-slate-900/80 rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 transition-all duration-300 h-[400px] animate-fade-in-up w-full`}
    >
      <div className="flex items-center gap-3 mb-6">
        <div className="bg-gradient-to-r from-indigo-600 to-purple-600 p-2 rounded-xl shadow-lg shadow-indigo-500/20">
          <BarChart3 className="w-5 h-5 text-white" />
        </div>
        <h3 className="text-xl font-semibold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
          Affected vs Scanned
        </h3>
      </div>

      <div className="h-[280px]">
        <Bar
          data={{
            labels,
            datasets: [
              {
                label: "Affected",
                data: affected,
                backgroundColor: "rgba(239, 68, 68, 0.8)",
                borderColor: "rgb(239, 68, 68)",
                borderWidth: 1,
                borderRadius: 6,
              },
              {
                label: "Total Scanned",
                data: scanned,
                backgroundColor: "rgba(99, 102, 241, 0.8)",
                borderColor: "rgb(99, 102, 241)",
                borderWidth: 1,
                borderRadius: 6,
              },
            ],
          }}
          options={{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: "top",
                labels: {
                  usePointStyle: true,
                  padding: 20,
                  font: {
                    size: 12,
                    weight: "500",
                  },
                },
              },
            },
            scales: {
              x: {
                grid: {
                  display: false,
                },
                ticks: {
                  font: {
                    size: 11,
                  },
                },
              },
              y: {
                grid: {
                  color: "rgba(148, 163, 184, 0.1)",
                },
                ticks: {
                  font: {
                    size: 11,
                  },
                },
              },
            },
          }}
        />
      </div>

      <button
        onClick={handleExpand}
        className="flex items-center gap-2 text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 font-medium transition-colors duration-200 mt-4 mx-auto"
      >
        {isBarExpanded ? (
          <>
            <ChevronUp className="w-4 h-4" />
            Show Less
          </>
        ) : (
          <>
            <ChevronDown className="w-4 h-4" />
            Show More
          </>
        )}
      </button>
    </div>
  );
}
