import React, { useEffect, useMemo, useState } from "react";
import {
  Table,
  Checkbox,
  Divider,
  Row,
  Col,
  Space,
  message,
  Dropdown,
  Button,
  Tag,
  Popconfirm,
} from "antd";
import {
  FilterOutlined,
  DownloadOutlined,
  EyeInvisibleOutlined,
  LoadingOutlined,
} from "@ant-design/icons";
import { regionOptions, serviceOptions, severityOptions } from "../AWSFilters";
import { notifyError, notifySuccess } from "../Notification";
import { getPaginationConfig, getSeverityColor } from "../Utils";
import ExcelJS from "exceljs";
import { saveAs } from "file-saver";
import { formatDate } from "../Utils";
import Cookies from "js-cookie";

const downloadFile = (filename, content, type) => {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
};

const convertToCSV = (data) => {
  if (data.length === 0) return "";

  const keys = Object.keys(data[0]);
  const rows = data.map((row) =>
    keys.map((k) => JSON.stringify(row[k] ?? "")).join(",")
  );
  return [keys.join(","), ...rows].join("\n");
};

const DropdownFilter = ({ label, options, selected, onChange }) => {
  const handleCheckboxChange = (value, checked) => {
    let newSelected = checked
      ? [...selected, value]
      : selected.filter((v) => v !== value);
    onChange(newSelected);
  };

  return (
    <Dropdown
      trigger={["click"]}
      dropdownRender={() => (
        <div
          style={{
            padding: 12,
            background: "#fff",
            borderRadius: 8,
            boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
            display: "flex",
            flexDirection: "column",
            maxHeight: 160,
            overflowY: "auto",
          }}
        >
          {options?.map((opt) => (
            <Checkbox
              key={opt}
              checked={selected.includes(opt)}
              onChange={(e) => handleCheckboxChange(opt, e.target.checked)}
              style={{ marginBottom: 8 }}
            >
              {opt}
            </Checkbox>
          ))}
        </div>
      )}
    >
      <Button icon={<FilterOutlined />} className="mr-2">
        {label}
      </Button>
    </Dropdown>
  );
};

export default function FindingsTable({
  findings,
  onSelect,
  meta,
  fullName,
  securityServicesScanResults,
  globalServicesScanResults,
  isSampleReport,
  setIsSampleReport,
}) {
  const [selectedRegions, setSelectedRegions] = useState([]);
  const [selectedServices, setSelectedServices] = useState([]);
  const [selectedSeverities, setSelectedSeverities] = useState([]);
  const [resolvedIds, setResolvedIds] = useState([]);
  const [wordReportDownloading, setWordReportDownloading] = useState(false);
  const [pageSize, setPageSize] = useState(10);

  const [hiddenFindings, setHiddenFindings] = useState(() => {
    const saved = localStorage.getItem("hiddenFindings");
    return saved ? JSON.parse(saved) : [];
  });

  useEffect(() => {
    localStorage.setItem("hiddenFindings", JSON.stringify(hiddenFindings));
  }, [hiddenFindings]);

  const handleHideFinding = (e, findingId) => {
    e.stopPropagation();
    setHiddenFindings((prev) => [...prev, findingId]);
    notifySuccess("Finding hidden successfully");
  };

  const filteredData = findings
    .filter((f) => f.additional_info?.affected > 0)
    .filter(
      (f) => selectedRegions.length === 0 || selectedRegions.includes(f.region)
    )
    .filter(
      (f) =>
        selectedServices.length === 0 || selectedServices.includes(f.check_name)
    )
    .filter(
      (f) =>
        selectedSeverities.length === 0 ||
        selectedSeverities.includes(f.severity_level)
    )
    .filter((f) => !hiddenFindings.includes(f.check_name + f.region));
  // console.log("filteredData: ", filteredData);

  const exportToJSON = () => {
    const json = JSON.stringify(filteredData, null, 2);
    downloadFile(`${meta.account_id}_findings.json`, json, "application/json");
    notifySuccess("Exported to JSON!");
  };

  const exportToCSV = () => {
    const csv = convertToCSV(
      filteredData?.map((item) => ({
        ...item,
        resources: item?.resources?.length,
      }))
    );
    downloadFile(`${meta.account_id}_findings.csv`, csv, "text/csv");
    notifySuccess("Exported to CSV!");
  };

  const downloadWordReport = async () => {
    const backend_url = process.env.REACT_APP_BACKEND_URL;

    try {
      setWordReportDownloading(true);
      const payload = {
        account_id: isSampleReport
          ? ""
          : meta?.account_id
          ? meta.account_id
          : "",
        username: localStorage.getItem("username"),
        type: "summary",
        is_sample: isSampleReport,
      };

      const response = await fetch(`${backend_url}/api/get-report-word`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error("Failed to download Word report:", errorText);
        notifyError("Failed to generate report. Please try again.");
        return;
      }

      const contentDisposition = response.headers.get("content-disposition");
      let fileName = "";
      if (contentDisposition) {
        const match = contentDisposition.match(/filename="?([^"]+)"?/);
        if (match) {
          console.log("match: ", match);
          fileName = match[1];
        }
      } else {
        const accountId = meta?.account_id || "";
        const accountName = meta?.account_name || "";

        if (accountId && accountName) {
          fileName = `${accountId} (${accountName})_AWS_Security_Assessment_Report.docx`;
        } else if (accountId) {
          fileName = `${accountId}_AWS_Security_Assessment_Report.docx`;
        } else {
          fileName = "AWS_Security_Assessment_Report.docx";
        }
      }

      // Convert to Blob and trigger download
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", fileName);
      document.body.appendChild(link);
      link.click();
      link.remove();

      notifySuccess("Report downloaded successfully!");
    } catch (err) {
      console.error("Download failed due to:", err);
      notifyError("Something went wrong while downloading the report.");
    } finally {
      setWordReportDownloading(false);
    }
  };

  const exportToExcel = async () => {
    const workbook = new ExcelJS.Workbook();

    // === Helpers ===
    const getSeverityColor = (level) => {
      switch (level?.toLowerCase()) {
        case "high":
          return "FFEEEE";
        case "medium":
          return "FFD580";
        case "low":
          return "FFFFE0";
        default:
          return "FFFFFF";
      }
    };

    const getBorderStyle = () => ({
      top: { style: "thin", color: { argb: "00000000" } },
      left: { style: "thin", color: { argb: "00000000" } },
      bottom: { style: "thin", color: { argb: "00000000" } },
      right: { style: "thin", color: { argb: "00000000" } },
    });

    const getAlignment = () => ({
      vertical: "middle",
      horizontal: "center",
      wrapText: true,
    });

    const getFont = (type) => {
      if (type === "data") return { bold: false, size: 12 };
      if (type === "resource-header") return { bold: true, size: 14 };
      return { bold: true, size: 16 };
    };

    const getFill = (color) => ({
      type: "pattern",
      pattern: "solid",
      fgColor: { argb: color },
    });

    const sortBySeverity = (a, b) => {
      const aScore = a.severity_score ?? 0;
      const bScore = b.severity_score ?? 0;
      return bScore - aScore;
    };

    const sortBySeverityGS = (a, b) => {
      const aScore = a[1].severity_score ?? 0;
      const bScore = b[1].severity_score ?? 0;
      return bScore - aScore;
    };

    // === Summary Worksheet as First Sheet ===
    const summarySheet = workbook.addWorksheet("Summary");

    // === Set column widths ===
    summarySheet.getColumn(2).width = 25; // Column B
    summarySheet.getColumn(3).width = 30; // Column C
    summarySheet.getColumn(4).width = 20; // Column D
    summarySheet.getColumn(5).width = 30; // Column E

    // === Prepare Summary Fields ===
    const summaryData = [
      { field: "Name", value: meta.account_name || "" },
      { field: "Account ID", value: meta.account_id || "" },
      {
        field: "Last Scanned",
        value: formatDate(meta.last_scanned || meta.timestamp) || "N/A",
      },
      {
        field: "Regions Scanned",
        value: Array.isArray(meta.regions) ? meta.regions.join(", ") : "N/A",
      },
      {
        field: "Services Scanned",
        value:
          meta?.scanned_meta_data?.[0]?.data?.services_scanned?.join(", ") ||
          "N/A",
      },
    ];

    // === Insert Summary Fields ===
    summaryData.forEach((item, i) => {
      const rowIndex = i + 3;

      const fieldCell = summarySheet.getCell(`B${rowIndex}`);
      const valueCell = summarySheet.getCell(`C${rowIndex}`);

      fieldCell.value = item.field;
      fieldCell.font = { bold: true, size: 14 };
      fieldCell.alignment = getAlignment();
      fieldCell.fill = getFill("FFF2F2F2");
      fieldCell.border = getBorderStyle();

      valueCell.value = item.value;
      valueCell.font = { size: 14 };
      valueCell.alignment = getAlignment();
      valueCell.fill = getFill("FFFFFFFF");
      valueCell.border = getBorderStyle();
    });

    // === Insert Scanned Meta Data Table ===
    const metaStartRow = summaryData.length + 5;

    // Header Row
    summarySheet.getCell(`B${metaStartRow}`).value = "Region";
    summarySheet.getCell(`C${metaStartRow}`).value = "Metric";
    summarySheet.getCell(`D${metaStartRow}`).value = "Value";

    ["B", "C", "D"].forEach((col) => {
      const cell = summarySheet.getCell(`${col}${metaStartRow}`);
      cell.font = { bold: true, size: 13 };
      cell.alignment = getAlignment();
      cell.fill = getFill("FFCCE5FF");
      cell.border = getBorderStyle();
    });

    // Insert region data with merged region cells
    meta.scanned_meta_data.forEach((item, i) => {
      // const rowStart = metaStartRow + 1 + i * 2;

      const rowStart = metaStartRow + 1 + i * 7;

      // Merge region cell vertically
      summarySheet.mergeCells(`B${rowStart}:B${rowStart + 5}`);
      const regionCell = summarySheet.getCell(`B${rowStart}`);
      regionCell.value = item.region;
      regionCell.font = { bold: true, size: 12 };
      regionCell.alignment = getAlignment();
      regionCell.border = getBorderStyle();

      // Metric rows
      const metrics = [
        { metric: "Total no. of Resources", value: item.data.total_scanned },
        { metric: "No. of Issues Found", value: item.data.affected },
        { metric: "High", value: item.data.High },
        { metric: "Medium", value: item.data.Medium },
        { metric: "Low", value: item.data.Low },
        { metric: "Critical", value: item.data.Critical },
      ];

      metrics.forEach((entry, j) => {
        const currentRow = rowStart + j;
        const metricCell = summarySheet.getCell(`C${currentRow}`);
        const valueCell = summarySheet.getCell(`D${currentRow}`);

        metricCell.value = entry.metric;
        valueCell.value = entry.value;

        [metricCell, valueCell].forEach((cell) => {
          cell.font = { size: 12 };
          cell.alignment = getAlignment();
          cell.fill = getFill("FFFFFFFF");
          cell.border = getBorderStyle();
        });
      });
    });

    // === Insert Security Services Scan Results ===
    const servicesStartRow =
      metaStartRow + meta.scanned_meta_data.length * 7 + 2;
    // meta.scanned_meta_data[0].data.length;

    summarySheet.getCell(`B${servicesStartRow}`).value =
      "Security Services Scan Results";
    summarySheet.getCell(`B${servicesStartRow}`).font =
      getFont("resource-header");

    const serviceHeaderRow = servicesStartRow + 1;
    const headers = ["Region", "Service", "Enabled", "Recommendation"];
    ["B", "C", "D", "E"].forEach((col, idx) => {
      const cell = summarySheet.getCell(`${col}${serviceHeaderRow}`);
      cell.value = headers[idx];
      cell.font = getFont("data");
      cell.alignment = getAlignment();
      cell.fill = getFill("FFCCE5FF");
      cell.border = getBorderStyle();
    });

    let currentRow = serviceHeaderRow + 1;

    // Region-wise services
    securityServicesScanResults.forEach((regionData) => {
      const region = regionData.region;
      if (region == "global") {
        return;
      }
      const data = regionData.data;
      const serviceEntries = Object.entries(data);
      const startRow = currentRow;
      const endRow = currentRow + serviceEntries.length - 1;

      // Merge region cells
      if (startRow < endRow) {
        summarySheet.mergeCells(`B${startRow}:B${endRow}`);
      }

      serviceEntries.forEach(([serviceName, serviceResult], index) => {
        const row = currentRow + index;

        const regionCell = summarySheet.getCell(`B${row}`);
        const serviceCell = summarySheet.getCell(`C${row}`);
        const enabledCell = summarySheet.getCell(`D${row}`);
        const recommendationCell = summarySheet.getCell(`E${row}`);

        if (index === 0) {
          regionCell.value = region;
        }

        serviceCell.value = serviceName;
        enabledCell.value = serviceResult.is_enabled || "N/A";
        // recommendationCell.value = serviceResult.recommendation || "N/A";
        recommendationCell.value =
          serviceResult.is_enabled?.toLowerCase() === "yes"
            ? "-"
            : serviceResult.recommendation || "N/A";

        [regionCell, serviceCell, enabledCell, recommendationCell].forEach(
          (cell) => {
            cell.font = getFont("data");
            cell.alignment = getAlignment();
            cell.fill = getFill("FFFFFFFF");
            cell.border = getBorderStyle();
          }
        );
      });

      currentRow += serviceEntries.length;
    });

    // === Group Data by Region ===
    const regionMap = {};
    for (const item of filteredData) {
      const regionKey =
        item.region == "global" ? "Global Services" : item.region;
      if (!regionMap[regionKey]) {
        regionMap[regionKey] = [];
      }
      regionMap[regionKey].push(item);
    }

    for (const [region, regionData] of Object.entries(regionMap)) {
      regionData.sort(sortBySeverity);
      const worksheet = workbook.addWorksheet(region || "Unknown Region");

      // Header A1–E1 (fixed columns)
      const headers = [
        { cell: "A1", text: "Check Name" },
        { cell: "B1", text: "Problem Statement" },
        { cell: "C1", text: "Severity Level" },
        { cell: "D1", text: "Region" },
        { cell: "E1", text: "Account ID" },
      ];

      headers.forEach(({ cell, text }) => {
        const headerCell = worksheet.getCell(cell);
        headerCell.value = text;
        headerCell.font = getFont("headers");
        headerCell.alignment = getAlignment();
        headerCell.border = getBorderStyle();
      });

      worksheet.columns = [
        { width: 30 }, // A
        { width: 50 }, // B
        { width: 15 }, // C
        { width: 15 }, // D
        { width: 20 }, // E
      ];

      // Find max resource columns for merging
      const maxResourceColumns = Math.max(
        ...regionData.map((item) =>
          (item.resources_affected || []).reduce((acc, res) => {
            const keys = Object.keys(res || {});
            return Math.max(acc, keys.length);
          }, 0)
        )
      );

      const resourceStartCol = 6; // F
      const resourceEndCol = resourceStartCol + maxResourceColumns - 1;
      const startColLetter = worksheet.getColumn(resourceStartCol).letter;
      const endColLetter = worksheet.getColumn(resourceEndCol).letter;

      worksheet.mergeCells(`${startColLetter}1:${endColLetter}1`);
      // for (let col = resourceStartCol; col <= resourceEndCol; col++) {
      //   worksheet.getColumn(col).width = 25;
      // }
      const resourceHeaderCell = worksheet.getCell(`${startColLetter}1`);
      resourceHeaderCell.value = "Resource Details";
      resourceHeaderCell.font = getFont("header");
      resourceHeaderCell.alignment = getAlignment();

      let currentRow = 2;

      for (const item of regionData) {
        const resourceList = item.resources_affected || [];
        const severityColor = getSeverityColor(item.severity_level);

        // === Get Ordered Keys ===
        const nestedKeysMap = {};
        const orderedKeys = [];

        try {
          if (resourceList.length > 0) {
            const firstResource = resourceList[0];
            for (const key of Object.keys(firstResource)) {
              const val = firstResource[key];
              if (Array.isArray(val) && typeof val[0] === "object") {
                const subKeys = Array.from(
                  new Set(
                    resourceList.flatMap((res) =>
                      (res[key] || []).flatMap((item) =>
                        Object.keys(item || {})
                      )
                    )
                  )
                );
                nestedKeysMap[key] = subKeys;
                orderedKeys.push({ type: "nested", key, subKeys });
              } else {
                orderedKeys.push({ type: "flat", key });
              }
            }
          }
        } catch (error) {
          console.error("error: ", error);
        }

        // === Heading for the check (merged A-B with item_name) ===
        if (item?.check_name) {
          const headingRow = worksheet.getRow(currentRow + 1);
          worksheet.mergeCells(`A${currentRow + 1}:B${currentRow + 1}`);
          const headingCell = headingRow.getCell("A");
          headingCell.value = item.check_name;
          headingCell.font = { bold: true, size: 14 };
          headingCell.alignment = getAlignment();
          headingCell.fill = getFill("FFEFEFEF");
          headingCell.border = getBorderStyle();

          currentRow++;
        }
        // === Summary info (formatted key-value pairs) ===
        if (item?.additional_info && typeof item.additional_info === "object") {
          for (const [key, value] of Object.entries(item.additional_info)) {
            const row = worksheet.getRow(currentRow + 1);
            const keyCell = row.getCell("A");
            const valCell = row.getCell("B");
            let formattedKey = key.toLowerCase();
            if (formattedKey === "total_scanned") {
              formattedKey = "Total no. of Resources";
            } else if (formattedKey === "affected") {
              formattedKey = "No. of Issue found";
            } else {
              formattedKey = key
                .replace(/_/g, " ")
                .replace(/\b\w/g, (c) => c.toUpperCase());
            }
            keyCell.value = formattedKey;
            keyCell.font = { bold: true, size: 12 };
            keyCell.alignment = getAlignment();
            keyCell.border = getBorderStyle();
            keyCell.fill = getFill("FFD9D9D9");

            valCell.value = value;
            valCell.font = { bold: false, size: 12 };
            valCell.alignment = getAlignment();
            valCell.border = getBorderStyle();
            valCell.fill = getFill("FFDDEEFF");

            currentRow++;
          }
        }

        // === Create 2-row Header for Resource Details ===
        const headerRow1 = worksheet.getRow(currentRow);
        const headerRow2 = worksheet.getRow(currentRow + 1);
        let currentColIndex = resourceStartCol;

        orderedKeys.forEach(({ type, key, subKeys }) => {
          if (type === "nested") {
            const startCol = currentColIndex;
            subKeys.forEach((subKey) => {
              const cell = headerRow2.getCell(currentColIndex);
              cell.value = subKey;
              cell.font = getFont("resource-header");
              cell.alignment = getAlignment();
              cell.fill = getFill(severityColor);
              cell.border = getBorderStyle();
              worksheet.getColumn(currentColIndex).width = 25;
              currentColIndex++;
            });

            try {
              worksheet.mergeCells(
                `${worksheet.getColumn(startCol).letter}${currentRow}:${
                  worksheet.getColumn(currentColIndex - 1).letter
                }${currentRow}`
              );
            } catch (error) {
              console.log("error: ", error);
            }

            const mergedCell = headerRow1.getCell(startCol);
            mergedCell.value = key
              .replace(/_/g, " ")
              .replace(/\b\w/g, (l) => l.toUpperCase());
            mergedCell.font = getFont("resource-header");
            mergedCell.alignment = getAlignment();
            mergedCell.fill = getFill(severityColor);
            mergedCell.border = getBorderStyle();
          } else {
            const colLetter = worksheet.getColumn(currentColIndex).letter;

            worksheet.mergeCells(
              `${colLetter}${currentRow}:${colLetter}${currentRow + 1}`
            );

            const cell = headerRow1.getCell(currentColIndex);
            cell.value = key;
            cell.font = getFont("resource-header");
            cell.alignment = getAlignment();
            cell.fill = getFill(severityColor);
            cell.border = getBorderStyle();

            const cell2 = headerRow2.getCell(currentColIndex);
            cell2.border = getBorderStyle();

            worksheet.getColumn(currentColIndex).width = 25;
            currentColIndex++;
          }
        });

        currentRow += 2;

        // === Resource Data Rows ===
        for (const res of resourceList) {
          const nestedRowsCount = Math.max(
            1,
            ...orderedKeys
              .filter(({ type }) => type === "nested")
              .map(({ key }) => res[key]?.length || 1)
          );

          const startRow = currentRow;

          for (let i = 0; i < nestedRowsCount; i++) {
            const row = worksheet.getRow(currentRow);
            let colIndex = resourceStartCol;

            orderedKeys.forEach(({ type, key, subKeys }) => {
              if (type === "nested") {
                const nestedItem = res[key]?.[i] || {};
                subKeys.forEach((subKey) => {
                  const val = nestedItem[subKey];
                  const cell = row.getCell(colIndex);
                  cell.value =
                    val === null || val === undefined || val == "" ? "-" : val;
                  cell.font = getFont("data");
                  cell.alignment = getAlignment();
                  cell.fill = getFill(severityColor);
                  cell.border = getBorderStyle();
                  colIndex++;
                });
              } else {
                const cell = row.getCell(colIndex);
                cell.value =
                  res[key] === null || res[key] === undefined || res[key] === ""
                    ? "-"
                    : res[key];
                cell.font = getFont("data");
                cell.alignment = getAlignment();
                cell.fill = getFill(severityColor);
                cell.border = getBorderStyle();
                colIndex++;
              }
            });

            if (i === 0) {
              ["A", "B", "C", "D", "E"].forEach((col, idx) => {
                const value = [
                  item.check_name,
                  item.problem_statement,
                  item.severity_level,
                  item.region,
                  item.account_id,
                ][idx];
                const cell = row.getCell(col);
                cell.value = value;
                cell.font = getFont("data");
                cell.alignment = getAlignment();
                cell.fill = getFill(severityColor);
                cell.border = getBorderStyle();
              });
            }

            currentRow++;
          }

          if (nestedRowsCount > 1) {
            ["A", "B", "C", "D", "E"].forEach((col) => {
              worksheet.mergeCells(`${col}${startRow}:${col}${currentRow - 1}`);
            });
          }
        }
        // currentRow += 3;

        worksheet.views = [{ state: "frozen", ySplit: 1 }];
      }
    }

    const buffer = await workbook.xlsx.writeBuffer();
    const blob = new Blob([buffer], {
      type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    });

    saveAs(blob, `${meta.account_id}_findings.xlsx`);
    notifySuccess("Exported to Excel!");
  };

  const onFilterChange = (setFilter, label, values) => {
    // console.log(`${label} checked:`, values);
    setFilter(values);
  };

  const dynamicColumns = useMemo(() => {
    if (filteredData.length === 0) return [];

    const keys = Object.keys(filteredData[0]).filter(
      (key) =>
        (key !== "account_id" &&
          key != "type" &&
          typeof filteredData[0][key] !== "object") ||
        filteredData[0][key] === null
    );

    const columns = [
      ...keys
        .filter((key) => key !== "severity_score")
        .map((key) => ({
          title:
            key.charAt(0).toUpperCase() + key.slice(1).replaceAll("_", " "),

          dataIndex: key,

          key: key,

          sorter: (a, b) =>
            typeof a[key] === "string"
              ? a[key].localeCompare(b[key])
              : a[key] - b[key],

          ...(key === "severity_level" && {
            render: (severity) => (
              <Tag className={getSeverityColor(severity)}>{severity}</Tag>
            ),
          }),
        })),

      {
        title: "Action",
        key: "action",
        render: (_, record) => (
          <Popconfirm
            title="Are you sure you want to hide this finding?"
            onConfirm={(e) =>
              handleHideFinding(e, record.check_name + record.region)
            }
            // onConfirm={() =>
            //   handleHideFinding(record.check_name + record.region)
            // }
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
          // <Button
          //   icon={<EyeInvisibleOutlined />}
          //   onClick={() => handleHideFinding(record.check_name + record.region)}
          //   size="small"
          // >
          //   Hide
          // </Button>
        ),
      },
    ];
    return columns;
  }, [filteredData]);

  const getFilterOptions = () => {
    if (!findings) return { regions: [], services: [], severities: [] };

    const regions = [...new Set(findings?.map((item) => item?.region))].filter(
      Boolean
    );

    const services = [
      ...new Set(findings?.map((item) => item?.check_name)),
    ].filter(Boolean);

    const severities = [
      ...new Set(findings?.map((item) => item?.severity_level)),
    ].filter(Boolean);

    return { regions, services, severities };
  };

  const filterOptions = getFilterOptions();

  return (
    <div className="bg-white/80 dark:bg-slate-900/80 shadow-xl shadow-indigo-500/10 p-6 overflow-x-auto border border-indigo-100 dark:border-slate-700">
      <div className="mb-4">
        {/* <Space wrap className="mb-2"> */}
        <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
          <div className="flex flex-wrap items-center gap-2">
            <DropdownFilter
              label="Region"
              options={filterOptions.regions}
              selected={selectedRegions}
              onChange={(values) =>
                onFilterChange(setSelectedRegions, "Region", values)
              }
            />
            <DropdownFilter
              label="Check Name"
              options={filterOptions.services}
              selected={selectedServices}
              onChange={(values) =>
                onFilterChange(setSelectedServices, "Service", values)
              }
            />
            <DropdownFilter
              label="Severity"
              options={filterOptions.severities}
              selected={selectedSeverities}
              onChange={(values) =>
                onFilterChange(setSelectedSeverities, "Severity", values)
              }
            />
            <Button
              danger
              onClick={() => {
                setSelectedRegions([]);
                setSelectedServices([]);
                setSelectedSeverities([]);
                // console.log("All filters cleared.");
              }}
            >
              Clear All
            </Button>
            {/* </Space> */}
          </div>

          <div className="flex items-center gap-2">
            <Button
              icon={<DownloadOutlined />}
              className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
              onClick={exportToJSON}
            >
              Export to JSON
            </Button>
            <Button
              icon={<DownloadOutlined />}
              className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
              onClick={exportToExcel}
            >
              Export to Excel
            </Button>

            {/*  Download Word Report */}
            <Button
              icon={
                wordReportDownloading ? (
                  <LoadingOutlined />
                ) : (
                  <DownloadOutlined />
                )
              }
              loading={wordReportDownloading}
              disabled={wordReportDownloading}
              className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
              onClick={downloadWordReport}
            >
              {wordReportDownloading ? "Generating..." : "Export to Word"}
            </Button>
          </div>
        </div>

        <div className="mt-2 text-sm text-gray-700">
          {selectedRegions.length === 0 &&
          selectedServices.length === 0 &&
          selectedSeverities.length === 0 ? (
            <></>
          ) : (
            <span>
              {selectedRegions.length > 0 && (
                <span>
                  <strong>Regions:</strong> {selectedRegions.join(", ")} |{" "}
                </span>
              )}
              {selectedServices.length > 0 && (
                <span>
                  <strong>Services:</strong> {selectedServices.join(", ")} |{" "}
                </span>
              )}
              {selectedSeverities.length > 0 && (
                <span>
                  <strong>Severities:</strong> {selectedSeverities.join(", ")}
                </span>
              )}
            </span>
          )}
        </div>
      </div>

      <Divider className="border-slate-200 dark:border-slate-600" />

      <Table
        rowKey={(record, index) => index}
        columns={dynamicColumns}
        dataSource={filteredData}
        pagination={getPaginationConfig(pageSize, setPageSize)}
        onRow={(record) => ({
          onClick: () => onSelect(record),
          className:
            "cursor-pointer hover:bg-indigo-50 dark:hover:bg-slate-800 transition-colors duration-200",
        })}
        className="w-full"
      />
    </div>
  );
}
