import ExcelJS from "exceljs";
import { saveAs } from "file-saver";
import { notifySuccess } from "../Notification";

// === Helpers ===
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
  if (type === "header") return { bold: true, size: 14 };
  if (type === "resource-header") return { bold: true, size: 12 };
  return { size: 11 };
};

const getFill = (color) => ({
  type: "pattern",
  pattern: "solid",
  fgColor: { argb: color },
});

const getHeaderFill = () => getFill("FFCCE5FF"); // light blue

// Excel fill color mapping by severity
const getSeverityFill = (severity) => {
  switch ((severity || "").toLowerCase()) {
    case "critical":
      return getFill("FFFFC7CE"); // light pink/red
    case "high":
      return getFill("FFFFE0B2"); // light orange
    case "medium":
      return getFill("FFFFFF99"); // light yellow
    case "low":
      return getFill("FFC6EFCE"); // light green
    default:
      return getFill("FFFFFFFF"); // white
  }
};

export default async function exportCISFindingsToExcel(
  findings,
  accountDetails
) {
  const workbook = new ExcelJS.Workbook();

  // === 1) Summary Sheet ===
  const summary = workbook.addWorksheet("Summary");
  summary.columns = [
    { header: "Account ID", width: 20 },
    { header: "Region", width: 15 },
    { header: "Rule ID", width: 20 },
    { header: "Check Name", width: 40 },
    { header: "Severity", width: 12 },
    { header: "Status", width: 15 },
    { header: "Failed Checks", width: 20 },
  ];

  findings.forEach((f) => {
    summary.addRow([
      accountDetails?.[0]?.account_id || "N/A",
      f.region,
      f.id,
      f.check_name,
      f.severity_level,
      f.status,
      f.failed_checks,
    ]);
  });

  summary.eachRow((row, i) =>
    row.eachCell((cell) => {
      cell.font = i === 1 ? getFont("header") : getFont("data");
      cell.alignment = getAlignment();
      cell.border = getBorderStyle();
      if (i === 1) cell.fill = getFill("FFCCE5FF");
    })
  );

  // === 2) Group by Region ===
  const regionMap = {};
  findings.forEach((f) => {
    if (!regionMap[f.region]) regionMap[f.region] = [];
    regionMap[f.region].push(f);
  });

  const excludedResourceColumns = [
    "last_updated",
    "arn",
    "region",
    "home_region",
    "account_id",
    "resource_type",
    "details",
  ];
  // === 3) Region Sheets ===
  for (const [region, regionFindings] of Object.entries(regionMap)) {
    const sheet = workbook.addWorksheet(region);
    let currentRow = 1;

    for (const f of regionFindings) {
      const resources = f.fullData?.resources_affected || [];
      if (resources.length > 0) {
        const severityColor = getSeverityFill(f.severity_level);

        // 1. Heading row (Check Name merged)
        sheet.mergeCells(`A${currentRow}:C${currentRow}`);
        const heading = sheet.getCell(`A${currentRow}`);
        heading.value = f.check_name;
        heading.font = { bold: true, size: 14 };
        heading.alignment = getAlignment();
        heading.fill = severityColor;
        currentRow++;

        // 2. Summary rows
        const summaryRows = [
          ["Severity", f.severity_level],
          ["Failed Checks", f.failed_checks],
        ];
        summaryRows.forEach(([label, value]) => {
          const row = sheet.getRow(currentRow);
          row.getCell(1).value = label;
          row.getCell(2).value = value;
          row.eachCell((c) => {
            c.border = getBorderStyle();
            c.alignment = getAlignment();
          });
          currentRow++;
        });

        // 3. Resource Table
        // figure out columns only for this check
        const allKeys = {};
        resources.forEach((res) => {
          Object.keys(res).forEach((key) => {
            if (
              excludedResourceColumns.some((ex) =>
                key.toLowerCase().includes(ex)
              )
            )
              return;

            if (Array.isArray(res[key]) && typeof res[key][0] === "object") {
              if (!allKeys[key]) allKeys[key] = new Set();
              res[key].forEach((obj) =>
                Object.keys(obj).forEach((sub) => allKeys[key].add(sub))
              );
            } else {
              if (!allKeys[key]) allKeys[key] = new Set();
              allKeys[key].add(null);
            }
          });
        });

        // 2-row header like FindingsTable
        const headerRow1 = sheet.getRow(currentRow);
        const headerRow2 = sheet.getRow(currentRow + 1);
        let colIndex = 1;

        for (const [key, subKeys] of Object.entries(allKeys)) {
          if (subKeys.has(null)) {
            sheet.mergeCells(currentRow, colIndex, currentRow + 1, colIndex);
            const cell = headerRow1.getCell(colIndex);
            cell.value = key;
            cell.font = getFont("resource-header");
            cell.alignment = getAlignment();
            cell.fill = getHeaderFill();
            cell.border = getBorderStyle();
            colIndex++;
          } else {
            const subArr = Array.from(subKeys);
            sheet.mergeCells(
              currentRow,
              colIndex,
              currentRow,
              colIndex + subArr.length - 1
            );
            const parentCell = headerRow1.getCell(colIndex);
            parentCell.value = key;
            parentCell.font = getFont("resource-header");
            parentCell.alignment = getAlignment();
            parentCell.fill = getHeaderFill();
            parentCell.border = getBorderStyle();

            subArr.forEach((sub) => {
              const subCell = headerRow2.getCell(colIndex);
              subCell.value = sub;
              subCell.font = getFont("resource-header");
              subCell.alignment = getAlignment();
              subCell.fill = getHeaderFill();
              subCell.border = getBorderStyle();
              colIndex++;
            });
          }
        }

        currentRow += 2;

        // Fill resources
        resources.forEach((res) => {
          const row = sheet.getRow(currentRow);
          let ci = 1;
          for (const [key, subKeys] of Object.entries(allKeys)) {
            if (subKeys.has(null)) {
              row.getCell(ci).value = res[key] ?? "-";
              ci++;
            } else {
              for (const sub of subKeys) {
                row.getCell(ci).value =
                  (res[key] || []).map((obj) => obj[sub]).join(", ") || "-";
                ci++;
              }
            }
          }
          row.eachCell((c) => {
            c.fill = severityColor;
            c.border = getBorderStyle();
            c.alignment = getAlignment();
          });
          currentRow++;
        });
        currentRow += 2; // space between checks
      }
    }
  }
  workbook.eachSheet((sheet) => {
    sheet.columns.forEach((col) => {
      let maxLength = 10;
      col.eachCell({ includeEmpty: true }, (cell) => {
        const val = cell.value ? cell.value.toString() : "";
        maxLength = Math.max(maxLength, val.length + 2);
      });
      col.width = maxLength > 30 ? 30 : maxLength; // cap width at 60 for readability
    });
  });

  // === Save ===
  const buffer = await workbook.xlsx.writeBuffer();
  const blob = new Blob([buffer], {
    type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  });
  saveAs(blob, `${accountDetails?.account_id || "cis"}_cis-findings.xlsx`);
  notifySuccess("Exported CIS Findings to Excel!");
}
