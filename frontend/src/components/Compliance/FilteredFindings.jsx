// components/Compliance/FilteredFindings.jsx
import { useEffect, useState } from "react";
import { useParams, useSearchParams, useNavigate } from "react-router-dom";
import { Table, Button } from "antd";
import { ArrowLeft } from "lucide-react";
import { COMPLIANCE_FRAMEWORKS, normalizeFindings, sortBySeverity } from "../../utils/complianceConfig";
import { getPaginationConfig } from "../Utils";
import SeverityTag from "../Framework/shared/SeverityTag";
import FindingDrawer from "../Framework/shared/FindingDrawer";

const SEVERITY_SORT_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

const FilteredFindings = () => {
  const { frameworkKey } = useParams();
  const [searchParams] = useSearchParams();
  const filter = searchParams.get("filter") || "all"; // passed | failed | critical | all
  const navigate = useNavigate();

  const config = COMPLIANCE_FRAMEWORKS[frameworkKey];
  const backendUrl = process.env.REACT_APP_BACKEND_URL;

  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [pageSize, setPageSize] = useState(20);

  const filterLabels = {
    passed: "Passed Checks",
    failed: "Failed Checks (Affected)",
    critical: "Critical Issues",
    all: "All Checks",
  };

  useEffect(() => {
    const loadReport = async () => {
      setLoading(true);
      try {
        // Try loading the last scanned account's report, fall back to sample
        const accounts = JSON.parse(localStorage.getItem("account_details") || "[]");
        const lastAccount = accounts[0]?.account_id || "";

        const attempts = [
          { account_id: lastAccount, is_sample: false },
          { account_id: "", is_sample: true },
        ];

        for (const attempt of attempts) {
          const payload = {
            account_id: attempt.account_id,
            username: localStorage.getItem("username"),
            type: config?.reportType || frameworkKey,
            is_sample: attempt.is_sample,
          };
          const response = await fetch(`${backendUrl}/api/get-report`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });
          const apiResponse = await response.json();
          if (apiResponse?.status === "ok" && apiResponse.data) {
            const report = apiResponse.data;
            const results = Array.isArray(report?.results)
              ? report.results.flatMap((r) =>
                  Array.isArray(r.data) ? r.data : r.data ? Object.values(r.data) : [r]
                )
              : [];
            const normalized = normalizeFindings(results, "aws");
            if (normalized.length > 0) {
              setFindings(normalized);
              break;
            }
          }
        }
      } catch (err) {
        console.error("Failed to load report:", err);
      } finally {
        setLoading(false);
      }
    };
    loadReport();
  }, [frameworkKey]);

  const filteredData = sortBySeverity(
    findings.filter((f) => {
      if (filter === "passed") return f.affected === 0;
      if (filter === "failed") return f.affected > 0;
      if (filter === "critical") return f.affected > 0 && f.severity === "Critical";
      return true;
    })
  );

  const tableData = filteredData.map((f, i) => ({
    key: `${f.id}-${i}`,
    id: f.id,
    check_name: f.check_name,
    service: f.service,
    severity_level: f.severity,
    severity_score: f.severity_score,
    affected: f.affected,
    total_scanned: f.total_scanned,
    failed_checks: `${f.affected} out of ${f.total_scanned}`,
    region: f.region,
    fullData: f.fullData,
  }));

  const columns = [
    {
      title: "Severity",
      dataIndex: "severity_level",
      key: "severity_level",
      defaultSortOrder: "ascend",
      sorter: (a, b) => (SEVERITY_SORT_ORDER[a.severity_level] ?? 99) - (SEVERITY_SORT_ORDER[b.severity_level] ?? 99),
      render: (severity) => <SeverityTag severity={severity} />,
    },
    { title: "Control ID", dataIndex: "id", key: "id", sorter: (a, b) => a.id.localeCompare(b.id), render: (id) => <span className="font-mono text-sm text-indigo-700">{id}</span> },
    { title: "Check Name", dataIndex: "check_name", key: "check_name", sorter: (a, b) => a.check_name.localeCompare(b.check_name) },
    { title: "Service", dataIndex: "service", key: "service", sorter: (a, b) => (a.service || "").localeCompare(b.service || "") },
    { title: "Region", dataIndex: "region", key: "region" },
    {
      title: "Result",
      dataIndex: "affected",
      key: "result",
      render: (affected) => (
        <span className={`font-semibold ${affected > 0 ? "text-red-600" : "text-green-600"}`}>
          {affected > 0 ? "FAIL" : "PASS"}
        </span>
      ),
    },
    {
      title: "Failed Checks",
      dataIndex: "failed_checks",
      key: "failed_checks",
      render: (text, record) => (
        <span className={record.affected > 0 ? "text-red-600 font-medium" : "text-green-600"}>{text}</span>
      ),
    },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center gap-4 mb-6">
          <Button icon={<ArrowLeft className="w-4 h-4" />} onClick={() => window.history.length > 1 ? navigate(-1) : navigate("/dashboard")}>Back</Button>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
              {config?.fullName || frameworkKey.toUpperCase()} — {filterLabels[filter] || "Findings"}
            </h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {filteredData.length} checks shown
            </p>
          </div>
        </div>

        <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl border border-indigo-100 dark:border-slate-700 p-6">
          <Table
            columns={columns}
            dataSource={tableData}
            loading={loading}
            pagination={getPaginationConfig(pageSize, setPageSize)}
            onRow={(record) => ({
              onClick: () => { setSelectedFinding(record); setDrawerVisible(true); },
              className: "cursor-pointer hover:bg-indigo-50 dark:hover:bg-slate-800 transition-colors",
            })}
          />
        </div>

        <FindingDrawer open={drawerVisible} onClose={() => setDrawerVisible(false)} finding={selectedFinding} />
      </div>
    </div>
  );
};

export default FilteredFindings;
