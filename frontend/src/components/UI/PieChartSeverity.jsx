import { Pie, Doughnut } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import { PieChart } from "lucide-react";
import { getSeverityColor, getSeverityColorsBasicScan } from "../Utils";

ChartJS.register(ArcElement, Tooltip, Legend);

export default function PieChartSeverity({ findings }) {
  const filteredFindings = findings.filter(
    (f) => f.additional_info?.affected > 0
  );
  const severityCount = { High: 0, Medium: 0, Low: 0, Critical: 0 };
  filteredFindings.forEach(
    (f) =>
      (severityCount[f.severity_level] =
        (severityCount[f.severity_level] || 0) + 1)
  );
  const total = Object.values(severityCount).reduce((a, b) => a + b, 0);

  const doughnutChartLabels = ["Critical", "High", "Medium", "Low"].filter(
    (label) => severityCount[label] > 0
  );
  const doughnutChartData = doughnutChartLabels.map(
    (label) => severityCount[label]
  );

  const doughnutChartBackgroundColors = doughnutChartLabels.map((label) => {
    const { background } = getSeverityColorsBasicScan(label);
    return background;
  });

  const doughnutChartBorderColors = doughnutChartLabels.map((label) => {
    const { border } = getSeverityColorsBasicScan(label);
    return border;
  });

  return (
    <div className="bg-white/80 dark:bg-slate-900/80 rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 w-full h-[400px] animate-fade-in-up">
      <div className="flex items-center gap-3 mb-6">
        <div className="bg-gradient-to-r from-indigo-600 to-purple-600 p-2 rounded-xl shadow-lg shadow-indigo-500/20">
          <PieChart className="w-5 h-5 text-white" />
        </div>
        <h3 className="text-xl font-semibold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
          Severity Distribution
        </h3>
      </div>

      <div className="h-[280px] flex items-center justify-center">
        <Doughnut
          data={{
            labels: doughnutChartLabels,
            datasets: [
              {
                data: doughnutChartData,
                backgroundColor: doughnutChartBackgroundColors,
                borderColor: doughnutChartBorderColors,
                borderWidth: 2,
                hoverOffset: 8,
              },
            ],
          }}
          options={{
            responsive: true,
            plugins: { legend: { position: "top" } },
            tooltip: {
              callbacks: {
                label: (context) => {
                  const label = context.label || "";
                  const value = context.raw || 0;
                  const total = context.dataset.data.reduce((a, b) => a + b, 0);
                  const percentage = Math.round((value / total) * 100);
                  return `${label}: ${value} (${percentage}%)`;
                },
              },
            },
          }}
        />
      </div>
    </div>
  );
}
