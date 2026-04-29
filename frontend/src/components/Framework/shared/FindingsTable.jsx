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

const SEVERITY_SORT_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

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

  const handleExportJSON = () => {
    downloadJSON(filteredData, `${frameworkKey}-findings.json`);
    notifySuccess("Exported to JSON!");
  };

  const handleExportCSV = () => {
    downloadCSV(filteredData, `${frameworkKey}-findings.csv`);
    notifySuccess("Exported to CSV!");
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
            record.affected > 0 ? "text-red-600 font-medium" : "text-green-600"
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
