// components/Framework/shared/FindingsTable.jsx
import { Table, Button, Divider, Popconfirm } from "antd";
import { DownloadOutlined, EyeInvisibleOutlined } from "@ant-design/icons";
import { notifySuccess } from "../../Notification";
import DropdownFilter from "./DropdownFilter";
import SeverityTag from "./SeverityTag";
import { getPaginationConfig } from "../../Utils";
import {
  downloadJSON,
  downloadCSV,
  applyFilters,
  getFilterOptions,
} from "../../../utils/frameworkUtils";
import { useState } from "react";
import ExcelJS from "exceljs";
import { saveAs } from "file-saver";

const SEVERITY_SORT_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

// ── Excel Export with Summary + Findings sheets ───────────────────────────────
const exportToExcel = async (data, allFindings, frameworkKey) => {
  const workbook = new ExcelJS.Workbook();

  // Calculate stats from ALL findings (including passed)
  const totalChecks = allFindings.length;
  const failedChecks = allFindings.filter((f) => f.affected > 0).length;
  const passedChecks = totalChecks - failedChecks;
  const totalScanned = allFindings.reduce((s, f) => s + (f.total_scanned || 0), 0);
  const totalAffected = allFindings.reduce((s, f) => s + (f.affected || 0), 0);
  const complianceScore = totalScanned > 0 ? Math.round(((totalScanned - totalAffected) / totalScanned) * 100) : 0;
  const rating = complianceScore >= 90 ? "Compliant" : complianceScore >= 75 ? "Partially Compliant" : complianceScore >= 50 ? "Needs Improvement" : "Non-Compliant";

  const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  allFindings.filter((f) => f.affected > 0).forEach((f) => {
    if (severityCounts.hasOwnProperty(f.severity_level)) severityCounts[f.severity_level]++;
  });

  // ── Sheet 1: Summary ────────────────────────────────────────────────────────
  const summary = workbook.addWorksheet("Summary");
  summary.columns = [{ width: 30 }, { width: 25 }];

  const addSummaryRow = (label, value, bold = false) => {
    const row = summary.addRow([label, value]);
    row.getCell(1).font = { bold: true, size: 11 };
    row.getCell(2).font = { bold, size: 11 };
    row.getCell(1).border = { bottom: { style: "thin", color: { argb: "FFD0D0D0" } } };
    row.getCell(2).border = { bottom: { style: "thin", color: { argb: "FFD0D0D0" } } };
  };

  const titleRow = summary.addRow([`${frameworkKey.toUpperCase()} Compliance Report`]);
  titleRow.getCell(1).font = { bold: true, size: 16 };
  summary.addRow([]);

  addSummaryRow("Report Generated", new Date().toLocaleString());
  addSummaryRow("Framework", frameworkKey.toUpperCase());
  summary.addRow([]);

  const scoreRow = summary.addRow(["Compliance Score", `${complianceScore}%`]);
  scoreRow.getCell(1).font = { bold: true, size: 13 };
  scoreRow.getCell(2).font = { bold: true, size: 13, color: { argb: complianceScore >= 75 ? "FF10B981" : "FFEF4444" } };

  addSummaryRow("Compliance Rating", rating, true);
  summary.addRow([]);

  addSummaryRow("Total Checks Executed", totalChecks);
  addSummaryRow("Checks Passed", passedChecks);
  addSummaryRow("Checks Failed", failedChecks);
  addSummaryRow("Total Resources Scanned", totalScanned);
  addSummaryRow("Total Resources Affected", totalAffected);
  summary.addRow([]);

  addSummaryRow("Critical Findings", severityCounts.Critical);
  addSummaryRow("High Findings", severityCounts.High);
  addSummaryRow("Medium Findings", severityCounts.Medium);
  addSummaryRow("Low Findings", severityCounts.Low);

  // ── Sheet 2: Findings ───────────────────────────────────────────────────────
  const findings = workbook.addWorksheet("Findings");
  const headers = ["Key", "ID", "Cloud", "Source", "Check Name", "Description", "Service", "Severity Level", "Severity Score", "Affected", "Total Scanned", "Failed Checks", "Region", "Result"];
  const headerRow = findings.addRow(headers);
  headerRow.eachCell((cell) => {
    cell.font = { bold: true, size: 11, color: { argb: "FFFFFFFF" } };
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF4338CA" } };
    cell.alignment = { vertical: "middle", horizontal: "center" };
    cell.border = { bottom: { style: "thin" } };
  });

  findings.columns = [
    { width: 10 }, { width: 22 }, { width: 8 }, { width: 12 }, { width: 40 }, { width: 55 },
    { width: 15 }, { width: 12 }, { width: 12 }, { width: 10 }, { width: 12 }, { width: 16 }, { width: 14 }, { width: 10 },
  ];

  // Include ALL findings (passed + failed) in the Excel
  allFindings.forEach((row, idx) => {
    const result = (row.total_scanned === 0 && row.affected === 0) ? "NOT APPLICABLE" : row.affected > 0 ? "FAIL" : "PASS";
    const description = row.fullData?.problem_statement || row.fullData?.description || row.description || "";
    const failedChecksText = result === "NOT APPLICABLE" ? "No resources found" : `${row.affected || 0} out of ${row.total_scanned || 0}`;
    const r = findings.addRow([
      idx + 1,
      row.id || row.control_id || "",
      row.cloud || "aws",
      row.source || row.fullData?.service || "",
      row.check_name || "",
      description,
      row.service || "",
      row.severity_level || row.severity || "",
      row.severity_score || 0,
      row.affected || 0,
      row.total_scanned || 0,
      failedChecksText,
      row.region || "global",
      result,
    ]);
    // Color the result cell
    const resultCell = r.getCell(14);
    const resultColor = result === "PASS" ? "FF10B981" : result === "NOT APPLICABLE" ? "FF6B7280" : "FFEF4444";
    resultCell.font = { bold: true, color: { argb: resultColor } };
    // Severity color
    const sevCell = r.getCell(8);
    const sevColors = { Critical: "FFDC2626", High: "FFEA580C", Medium: "FFD97706", Low: "FF2563EB" };
    const sev = row.severity_level || row.severity || "";
    if (sevColors[sev]) sevCell.font = { bold: true, color: { argb: sevColors[sev] } };
  });

  // ── Sheet 3: Failed Resources & Remediation ─────────────────────────────────
  const remediation = workbook.addWorksheet("Remediation");
  const remHeaders = ["Sl No", "Resource Name", "Service", "Result", "Reason (Why Failed)", "Recommendations/Remediation"];
  const remHeaderRow = remediation.addRow(remHeaders);
  remHeaderRow.eachCell((cell) => {
    cell.font = { bold: true, size: 11, color: { argb: "FFFFFFFF" } };
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFDC2626" } };
    cell.alignment = { vertical: "middle", horizontal: "center" };
    cell.border = { bottom: { style: "thin" } };
  });
  remediation.columns = [{ width: 8 }, { width: 35 }, { width: 15 }, { width: 10 }, { width: 60 }, { width: 60 }];

  // Build failed resources list sorted by service
  const failedResources = [];
  allFindings.filter((row) => row.affected > 0)
    .sort((a, b) => (a.service || "").localeCompare(b.service || ""))
    .forEach((row) => {
      const resources = row.fullData?.resources_affected || [];
      const reason = row.fullData?.problem_statement || row.description || "";
      const service = row.service || "";
      if (resources.length > 0) {
        resources.forEach((res) => {
          failedResources.push({
            resource_name: res.resource_name || res.resource_id || res.arn || row.check_name || "",
            service,
            reason: res.note || res.issues?.join("; ") || reason,
          });
        });
      } else {
        failedResources.push({ resource_name: row.check_name || row.id || "", service, reason });
      }
    });

  // Call Bedrock for AI-generated remediation (batch 20 at a time)
  let aiRemediations = [];
  try {
    const backendUrl = process.env.REACT_APP_BACKEND_URL;
    const batchSize = 20;
    for (let i = 0; i < failedResources.length; i += batchSize) {
      const batch = failedResources.slice(i, i + batchSize).map((r) => ({
        resource_name: r.resource_name,
        service: r.service,
        reason: r.reason?.substring(0, 100),
      }));
      const resp = await fetch(`${backendUrl}/api/generate-remediation`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findings: batch }),
      });
      const result = await resp.json();
      if (result?.status === "ok" && result.remediations?.length) {
        // Parse each item - could be string or {remediation: "..."} object
        const parsed = result.remediations.map((r) => {
          if (typeof r === "string") {
            try { const obj = JSON.parse(r); return obj.remediation || obj.Remediation || r; } catch { return r; }
          }
          if (typeof r === "object") return r.remediation || r.Remediation || JSON.stringify(r);
          return String(r);
        });
        aiRemediations.push(...parsed);
      } else {
        aiRemediations.push(...batch.map(() => ""));
      }
    }
  } catch (e) {
    console.error("AI remediation fetch failed:", e);
  }

  failedResources.forEach((res, idx) => {
    const aiRec = aiRemediations[idx] || "";
    const r = remediation.addRow([
      idx + 1,
      res.resource_name,
      res.service,
      "FAIL",
      res.reason,
      aiRec,
    ]);
    r.getCell(4).font = { bold: true, color: { argb: "FFEF4444" } };
  });

  const buffer = await workbook.xlsx.writeBuffer();
  saveAs(new Blob([buffer]), `${frameworkKey}-compliance-report.xlsx`);
  notifySuccess("Exported to Excel!");
};

const CLOUD_BADGE_STYLES = {
  aws: "bg-orange-100 text-orange-700 border-orange-200",
  azure: "bg-blue-100 text-blue-700 border-blue-200",
  gcp: "bg-emerald-100 text-emerald-700 border-emerald-200",
};

const CLOUD_LABELS = { aws: "AWS", azure: "Azure", gcp: "GCP" };

const CloudBadge = ({ cloud }) => (
  <span
    className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${CLOUD_BADGE_STYLES[cloud] || "bg-gray-100 text-gray-600 border-gray-200"}`}
  >
    {CLOUD_LABELS[cloud] || cloud}
  </span>
);

/**
 * Reusable findings table used by all framework dashboards.
 *
 * Props:
 *   tableData         — flat array of row objects (built by frameworkUtils)
 *   frameworkKey      — string ("rbi" | "sebi" | "pcidss" | "owasp")
 *   onRowClick        — fn(record)
 *   extraColumns      — optional extra Ant Table column defs (prepended before Severity)
 *   hideRegionFilter  — hide region/url filter (default false)
 *   regionLabel       — label for region column header (default "Region")
 *   hiddenFindings    — array of IDs to hide
 *   onHideFinding     — fn(e, id)
 *   showHideAction    — show hide button (default true)
 *   showCloudColumn   — show Cloud + Source columns (default false)
 */
const FindingsTable = ({
  tableData = [],
  frameworkKey = "",
  onRowClick,
  extraColumns = [],
  hideRegionFilter = false,
  regionLabel = "Region",
  hiddenFindings = [],
  onHideFinding,
  showHideAction = true,
  showCloudColumn = false,
  allFindings = [],
}) => {
  const [selectedServices, setSelectedServices] = useState([]);
  const [selectedSeverities, setSelectedSeverities] = useState([]);
  const [selectedRegions, setSelectedRegions] = useState([]);
  const [selectedClouds, setSelectedClouds] = useState([]);
  const [pageSize, setPageSize] = useState(10);

  const filterOptions = getFilterOptions(tableData);
  const cloudOptions = showCloudColumn
    ? [...new Set(tableData.map((r) => r.cloud).filter(Boolean))].sort()
    : [];

  const visibleData = tableData.filter(
    (r) => !hiddenFindings.includes(r.id + r.region),
  );
  const filteredData = applyFilters(visibleData, {
    services: selectedServices,
    severities: selectedSeverities,
    regions: selectedRegions,
  }).filter((r) => selectedClouds.length === 0 || selectedClouds.includes(r.cloud));

  const clearAll = () => {
    setSelectedServices([]);
    setSelectedSeverities([]);
    setSelectedRegions([]);
    setSelectedClouds([]);
  };

  const handleExportJSON = async () => {
    try {
      notifySuccess("Generating JSON report with AI recommendations...");
      const backendUrl = process.env.REACT_APP_BACKEND_URL;

      // Build export data from filtered findings
      const exportData = filteredData.map(({ fullData, ...rest }) => ({
        ...rest,
        reason: fullData?.problem_statement || fullData?.description || rest.description || "",
      }));

      // Fetch AI remediations for failed findings only
      const failedItems = exportData.filter((f) => f.affected > 0);
      let aiRemediations = [];

      try {
        const batchSize = 20;
        for (let i = 0; i < failedItems.length; i += batchSize) {
          const batch = failedItems.slice(i, i + batchSize).map((r) => ({
            resource_name: r.check_name || r.id || "",
            service: r.service || "",
            reason: (r.reason || "").substring(0, 100),
          }));
          const resp = await fetch(`${backendUrl}/api/generate-remediation`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ findings: batch }),
          });
          const result = await resp.json();
          if (result?.status === "ok" && result.remediations?.length) {
            const parsed = result.remediations.map((r) => {
              if (typeof r === "string") {
                try { const obj = JSON.parse(r); return obj.remediation || obj.Remediation || r; } catch { return r; }
              }
              if (typeof r === "object") return r.remediation || r.Remediation || JSON.stringify(r);
              return String(r);
            });
            aiRemediations.push(...parsed);
          } else {
            aiRemediations.push(...batch.map(() => ""));
          }
        }
      } catch (e) {
        console.error("AI remediation fetch failed for JSON export:", e);
      }

      // Consolidate: merge AI recommendations into each finding
      let failedIdx = 0;
      const consolidatedFindings = exportData.map((finding) => {
        if (finding.affected > 0) {
          const rec = aiRemediations[failedIdx] || "";
          failedIdx++;
          return { ...finding, ai_recommendation: rec };
        }
        return { ...finding, ai_recommendation: "" };
      });

      const jsonOutput = {
        framework: frameworkKey?.toUpperCase(),
        exported_at: new Date().toISOString(),
        total_checks: consolidatedFindings.length,
        passed: consolidatedFindings.filter((f) => f.affected === 0).length,
        failed: consolidatedFindings.filter((f) => f.affected > 0).length,
        findings: consolidatedFindings,
      };

      const blob = new Blob([JSON.stringify(jsonOutput, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${frameworkKey}-findings.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      notifySuccess("Exported to JSON with AI recommendations!");
    } catch (err) {
      console.error("JSON export failed:", err);
      // Fallback to simple export without AI
      downloadJSON(filteredData, `${frameworkKey}-findings.json`);
      notifySuccess("Exported to JSON!");
    }
  };

  const handleExportCSV = () => {
    notifySuccess("Generating Excel report with AI recommendations...");
    exportToExcel(filteredData, allFindings.length > 0 ? allFindings : filteredData, frameworkKey);
  };

  const activeFilters = [
    selectedClouds.length > 0 && `Cloud: ${selectedClouds.map((c) => c.toUpperCase()).join(", ")}`,
    selectedServices.length > 0 && `Service: ${selectedServices.join(", ")}`,
    selectedSeverities.length > 0 &&
      `Severity: ${selectedSeverities.join(", ")}`,
    selectedRegions.length > 0 &&
      `${regionLabel}: ${selectedRegions.join(", ")}`,
  ].filter(Boolean);

  // ── Cloud columns (only when showCloudColumn is true) ────────────────────────
  const cloudColumns = showCloudColumn
    ? [
        {
          title: "Cloud",
          dataIndex: "cloud",
          key: "cloud",
          width: 100,
          render: (cloud) => <CloudBadge cloud={cloud} />,
          filters: [
            { text: "AWS", value: "aws" },
            { text: "Azure", value: "azure" },
            { text: "GCP", value: "gcp" },
          ],
          onFilter: (value, record) => record.cloud === value,
        },
        {
          title: "Source",
          dataIndex: "source",
          key: "source",
          sorter: (a, b) => (a.source || "").localeCompare(b.source || ""),
          render: (val) => (
            <span className="text-sm font-mono text-gray-600">{val || "—"}</span>
          ),
        },
      ]
    : [];

  // ── Base columns (always present) ──────────────────────────────────────────
  const baseColumns = [
    {
      title: "Severity",
      dataIndex: "severity_level",
      key: "severity_level",
      defaultSortOrder: "ascend",
      sorter: (a, b) =>
        (SEVERITY_SORT_ORDER[a.severity_level] ?? 99) -
        (SEVERITY_SORT_ORDER[b.severity_level] ?? 99),
      render: (severity) => <SeverityTag severity={severity} />,
    },
    {
      title: "Control ID",
      dataIndex: "id",
      key: "id",
      sorter: (a, b) => a.id.localeCompare(b.id),
      render: (id) => (
        <span className="font-mono text-sm text-indigo-700">{id}</span>
      ),
    },
    {
      title: "Check Name",
      dataIndex: "check_name",
      key: "check_name",
      sorter: (a, b) => a.check_name.localeCompare(b.check_name),
    },
    {
      title: "Service",
      dataIndex: "service",
      key: "service",
      sorter: (a, b) => (a.service || "").localeCompare(b.service || ""),
    },
    {
      title: regionLabel,
      dataIndex: "region",
      key: "region",
      sorter: (a, b) => (a.region || "").localeCompare(b.region || ""),
      render: (val) => (
        <span className="text-sm font-mono text-gray-600">{val || "—"}</span>
      ),
    },
    {
      title: "Failed Checks",
      dataIndex: "failed_checks",
      key: "failed_checks",
      render: (text, record) => (
        <span
          className={
            record.result === "NOT_APPLICABLE"
              ? "text-gray-500 italic"
              : record.affected > 0
                ? "text-red-600 font-medium"
                : "text-green-600"
          }
        >
          {text}
        </span>
      ),
    },
  ];

  // ── Optional hide action column ─────────────────────────────────────────────
  const actionColumn =
    showHideAction && onHideFinding
      ? [
          {
            title: "Action",
            key: "action",
            render: (_, record) => (
              <Popconfirm
                title="Hide this finding?"
                onConfirm={(e) => onHideFinding(e, record.id + record.region)}
                okText="Yes"
                cancelText="No"
                onCancel={(e) => e.stopPropagation()}
              >
                <Button
                  icon={<EyeInvisibleOutlined />}
                  size="small"
                  onClick={(e) => e.stopPropagation()}
                >
                  Hide
                </Button>
              </Popconfirm>
            ),
          },
        ]
      : [];

  const columns = [...extraColumns, ...cloudColumns, ...baseColumns, ...actionColumn];

  return (
    <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 border border-indigo-100 dark:border-slate-700">
      {/* Table header */}
      <div className="p-6 border-b border-indigo-100 dark:border-slate-700">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
          Security Findings
        </h2>
      </div>

      <div className="p-6">
        {/* Filters row */}
        <div className="mb-4">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <div className="flex flex-wrap items-center gap-2">
              {showCloudColumn && cloudOptions.length > 0 && (
                <DropdownFilter
                  label="Cloud"
                  options={cloudOptions}
                  selected={selectedClouds}
                  onChange={setSelectedClouds}
                />
              )}
              {filterOptions.services.length > 0 && (
                <DropdownFilter
                  label="Service"
                  options={filterOptions.services}
                  selected={selectedServices}
                  onChange={setSelectedServices}
                />
              )}
              <DropdownFilter
                label="Severity"
                options={filterOptions.severities}
                selected={selectedSeverities}
                onChange={setSelectedSeverities}
              />
              {!hideRegionFilter && filterOptions.regions.length > 0 && (
                <DropdownFilter
                  label={regionLabel}
                  options={filterOptions.regions}
                  selected={selectedRegions}
                  onChange={setSelectedRegions}
                />
              )}
              <Button danger onClick={clearAll}>
                Clear All
              </Button>
            </div>
            <div className="flex items-center gap-2">
              <Button
                icon={<DownloadOutlined />}
                onClick={handleExportJSON}
                className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-4 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
              >
                Export JSON
              </Button>
              <Button
                icon={<DownloadOutlined />}
                onClick={handleExportCSV}
                className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-4 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
              >
                Export CSV
              </Button>
            </div>
          </div>

          {/* Active filters summary */}
          {activeFilters.length > 0 && (
            <div className="text-sm text-gray-700 mt-1">
              {activeFilters.join(" | ")}
            </div>
          )}
        </div>

        <Divider />

        <Table
          columns={columns}
          dataSource={filteredData}
          onRow={(record) => ({
            onClick: () => onRowClick?.(record),
            className:
              "cursor-pointer hover:bg-indigo-50 dark:hover:bg-slate-800 transition-colors",
          })}
          pagination={getPaginationConfig(pageSize, setPageSize)}
          className="w-full"
        />
      </div>
    </div>
  );
};

export default FindingsTable;
