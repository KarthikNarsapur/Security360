// utils/frameworkUtils.js
// Shared helpers used across all framework dashboards (RBI, SEBI, PCIDSS, OWASP)
// Mirrors the pattern from Utils.js used in CisSummary

// ─── Severity ─────────────────────────────────────────────────────────────────

export const getSeverityColor = (severity) => {
  const map = {
    Critical: "bg-red-100 text-red-700 border-red-200",
    High: "bg-orange-100 text-orange-700 border-orange-200",
    Medium: "bg-yellow-100 text-yellow-700 border-yellow-200",
    Low: "bg-blue-100 text-blue-700 border-blue-200",
    Unknown: "bg-gray-100 text-gray-600 border-gray-200",
  };
  return map[severity] || map.Unknown;
};

export const getSeverityBarColor = (severity) => {
  const map = {
    Critical: "#DC2626",
    High: "#EA580C",
    Medium: "#D97706",
    Low: "#2563EB",
  };
  return map[severity] || "#9CA3AF";
};

// ─── Data Builders ─────────────────────────────────────────────────────────────

/**
 * Build flat table rows from framework results array (RBI, SEBI, PCIDSS format).
 * results = array of check result dicts
 */
export const buildTableData = (results = []) => {
  return results.map((rule, index) => {
    const scanned = rule.additional_info?.total_scanned ?? 0;
    const affected = rule.additional_info?.affected ?? 0;
    const result = rule.result || (scanned === 0 && affected === 0 ? "NOT_APPLICABLE" : affected > 0 ? "FAIL" : "PASS");
    return {
      key: `${rule.control_id || index}-${index}`,
      id: rule.control_id || `check-${index}`,
      check_name: rule.check_name || "Unknown",
      service: rule.service || "",
      severity_level: rule.severity_level || "Unknown",
      severity_score: rule.severity_score || 0,
      affected,
      total_scanned: scanned,
      failed_checks: result === "NOT_APPLICABLE" ? "No resources found" : `${affected} out of ${scanned}`,
      result,
      framework: rule.framework || "",
      control_id: rule.control_id || "",
      region: "global",
      fullData: rule,
    };
  });
};

/**
 * Build flat table rows from regional format (array of {region, data: []}).
 * Used when scan results are split by region.
 */
export const buildTableDataFromRegions = (regionResults = []) => {
  const rows = [];
  for (const regionData of regionResults) {
    const region = regionData?.region || "global";
    const data = regionData?.data || [];
    const items = Array.isArray(data) ? data : Object.values(data);
    items.forEach((rule, index) => {
      const scanned = rule?.additional_info?.total_scanned ?? 0;
      const affected = rule?.additional_info?.affected ?? 0;
      const result = rule?.result || (scanned === 0 && affected === 0 ? "NOT_APPLICABLE" : affected > 0 ? "FAIL" : "PASS");
      rows.push({
        key: `${rule?.control_id || index}-${region}-${index}`,
        id: rule?.control_id || `check-${index}`,
        check_name: rule?.check_name || "Unknown",
        service: rule?.service || "",
        severity_level: rule?.severity_level || "Unknown",
        severity_score: rule?.severity_score || 0,
        affected,
        total_scanned: scanned,
        failed_checks: result === "NOT_APPLICABLE" ? "No resources found" : `${affected} out of ${scanned}`,
        result,
        region,
        framework: rule?.framework || "",
        control_id: rule?.control_id || "",
        fullData: rule,
      });
    });
  }
  return rows;
};

/**
 * Build OWASP table rows from website scan results.
 * all_results = [{url, data: [...checks], scan_meta_data}]
 */
export const buildTableDataFromWebsite = (allResults = []) => {
  const rows = [];
  for (const siteResult of allResults) {
    const url = siteResult?.url || "";
    const items = siteResult?.data || [];
    items.forEach((rule, index) => {
      const scanned = rule?.additional_info?.total_scanned ?? 0;
      const affected = rule?.additional_info?.affected ?? 0;
      const result = rule?.result || (scanned === 0 && affected === 0 ? "NOT_APPLICABLE" : affected > 0 ? "FAIL" : "PASS");
      rows.push({
        key: `${rule?.control_id || index}-${url}-${index}`,
        id: rule?.control_id || `check-${index}`,
        check_name: rule?.check_name || "Unknown",
        service: rule?.service || "",
        severity_level: rule?.severity_level || "Unknown",
        severity_score: rule?.severity_score || 0,
        affected,
        total_scanned: scanned,
        failed_checks: result === "NOT_APPLICABLE" ? "No resources found" : `${affected} out of ${scanned}`,
        result,
        region: url, // reuse region column for URL
        framework: rule?.framework || "",
        control_id: rule?.control_id || "",
        fullData: rule,
      });
    });
  }
  return rows;
};

/**
 * Compute summary card data from flat table rows.
 */
export const computeDashboardMeta = (tableData = []) => {
  let totalScanned = 0;
  let totalAffected = 0;
  const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };

  for (const row of tableData) {
    totalScanned += row.total_scanned || 0;
    totalAffected += row.affected || 0;
    if (severityCounts.hasOwnProperty(row.severity_level)) {
      severityCounts[row.severity_level] += row.affected || 0;
    }
  }

  const securityScore =
    totalScanned > 0
      ? Math.round(((totalScanned - totalAffected) / totalScanned) * 100)
      : 0;

  return { totalScanned, totalAffected, securityScore, severityCounts };
};

// ─── Filtering ────────────────────────────────────────────────────────────────

export const getFilterOptions = (tableData = []) => ({
  services: [
    ...new Set(tableData.map((r) => r.service).filter(Boolean)),
  ].sort(),
  severities: [
    ...new Set(tableData.map((r) => r.severity_level).filter(Boolean)),
  ],
  regions: [...new Set(tableData.map((r) => r.region).filter(Boolean))].sort(),
});

export const applyFilters = (tableData = [], filters = {}) => {
  const { services = [], severities = [], regions = [] } = filters;
  return tableData.filter((row) => {
    if (services.length > 0 && !services.includes(row.service)) return false;
    if (severities.length > 0 && !severities.includes(row.severity_level))
      return false;
    if (regions.length > 0 && !regions.includes(row.region)) return false;
    return true;
  });
};

// ─── Export ───────────────────────────────────────────────────────────────────

export const downloadJSON = (data, filename) => {
  const safe = data.map(({ fullData, ...rest }) => rest);
  const blob = new Blob([JSON.stringify(safe, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
};

export const downloadCSV = (data, filename) => {
  if (!data.length) return;
  const keys = Object.keys(data[0]).filter((k) => k !== "fullData");
  const rows = data.map((row) =>
    keys.map((k) => JSON.stringify(row[k] ?? "")).join(","),
  );
  const csv = [keys.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
};

// ─── Chart helpers ────────────────────────────────────────────────────────────

export const buildDoughnutData = (securityScore) => ({
  datasets: [
    {
      data: [securityScore, 100 - securityScore],
      backgroundColor: [
        securityScore >= 80
          ? "#10B981"
          : securityScore >= 60
            ? "#F59E0B"
            : "#EF4444",
        "#E5E7EB",
      ],
      borderWidth: 0,
    },
  ],
});

export const buildBarData = (severityCounts) => ({
  labels: ["Critical", "High", "Medium", "Low"],
  datasets: [
    {
      data: [
        severityCounts.Critical,
        severityCounts.High,
        severityCounts.Medium,
        severityCounts.Low,
      ],
      backgroundColor: ["#DC2626", "#EA580C", "#D97706", "#2563EB"],
      borderRadius: 4,
    },
  ],
});

export const DOUGHNUT_OPTIONS = {
  responsive: true,
  maintainAspectRatio: false,
  circumference: 180,
  rotation: 270,
  cutout: "75%",
  plugins: { legend: { display: false }, tooltip: { enabled: false } },
};

export const BAR_OPTIONS = {
  responsive: true,
  maintainAspectRatio: false,
  indexAxis: "y",
  plugins: { legend: { display: false } },
  scales: {
    x: { beginAtZero: true, ticks: { stepSize: 1 } },
    y: { grid: { display: false } },
  },
};

// ─── Framework config ─────────────────────────────────────────────────────────

export const FRAMEWORK_CONFIG = {
  rbi: {
    label: "RBI CSF",
    fullName: "RBI Cyber Security Framework",
    description: "Reserve Bank of India Cyber Security Framework 2023",
    gradient: "from-indigo-600 to-purple-600",
    apiEndpoint: "/api/rbi-scan",
    reportType: "rbi",
    scanLabel: "Run RBI Scan",
    inputType: "aws", // aws | website
  },
  sebi: {
    label: "SEBI CSCRF",
    fullName: "SEBI Cyber Security & Cyber Resilience Framework",
    description: "SEBI CSCRF 2024 — 128 compliance checks for regulated entities",
    gradient: "from-violet-600 to-indigo-600",
    apiEndpoint: "/api/sebi-scan",
    reportType: "sebi",
    scanLabel: "Run SEBI Scan",
    inputType: "aws",
  },
  pcidss: {
    label: "PCI-DSS v4.0",
    fullName: "Payment Card Industry Data Security Standard",
    description: "PCI-DSS v4.0 — mandatory for all card payment environments",
    gradient: "from-blue-600 to-indigo-600",
    apiEndpoint: "/api/pcidss-scan",
    reportType: "pcidss",
    scanLabel: "Run PCI-DSS Scan",
    inputType: "aws",
  },
  owasp: {
    label: "OWASP Top 10",
    fullName: "OWASP Top 10 Web Application Security",
    description: "OWASP Top 10 2021 — web application security scanning",
    gradient: "from-emerald-600 to-teal-600",
    apiEndpoint: "/api/website-scan/owasp",
    reportType: "owasp",
    scanLabel: "Run Website Scan",
    inputType: "website", // takes URL list instead of AWS accounts
  },

  // ─── Compliance frameworks (cloud-agnostic) ─────────────────────────────────
  gdpr: {
    label: "GDPR",
    fullName: "General Data Protection Regulation",
    description: "EU data protection and privacy regulation",
    gradient: "from-blue-600 to-cyan-600",
    apiEndpoint: "/api/compliance-report",
    reportType: "gdpr",
    scanLabel: "Run GDPR Scan",
    inputType: "aws",
  },
  hipaa: {
    label: "HIPAA",
    fullName: "Health Insurance Portability and Accountability Act",
    description: "US healthcare data protection standard",
    gradient: "from-emerald-600 to-teal-600",
    apiEndpoint: "/api/compliance-report",
    reportType: "hipaa",
    scanLabel: "Run HIPAA Scan",
    inputType: "aws",
  },
  soc2: {
    label: "SOC 2",
    fullName: "Service Organization Control 2",
    description: "Enterprise security, availability, and confidentiality",
    gradient: "from-violet-600 to-purple-600",
    apiEndpoint: "/api/compliance-report",
    reportType: "soc2",
    scanLabel: "Run SOC 2 Scan",
    inputType: "aws",
  },
  fedramp: {
    label: "FedRAMP",
    fullName: "Federal Risk and Authorization Management Program",
    description: "US government cloud security authorization",
    gradient: "from-red-600 to-rose-600",
    apiEndpoint: "/api/compliance-report",
    reportType: "fedramp",
    scanLabel: "Run FedRAMP Scan",
    inputType: "aws",
  },
  nist: {
    label: "NIST CSF",
    fullName: "NIST Cybersecurity Framework",
    description: "Risk-based cybersecurity framework",
    gradient: "from-indigo-600 to-blue-700",
    apiEndpoint: "/api/compliance-report",
    reportType: "nist",
    scanLabel: "Run NIST Scan",
    inputType: "aws",
  },
  nist80053: {
    label: "NIST SP 800-53",
    fullName: "NIST Special Publication 800-53",
    description: "Security and privacy controls for federal systems",
    gradient: "from-indigo-700 to-purple-700",
    apiEndpoint: "/api/compliance-report",
    reportType: "nist80053",
    scanLabel: "Run NIST 800-53 Scan",
    inputType: "aws",
  },
  iso27001: {
    label: "ISO/IEC 27001",
    fullName: "ISO/IEC 27001 Information Security",
    description: "International information security management standard",
    gradient: "from-teal-600 to-cyan-700",
    apiEndpoint: "/api/compliance-report",
    reportType: "iso27001",
    scanLabel: "Run ISO 27001 Scan",
    inputType: "aws",
  },
  iso27018: {
    label: "ISO/IEC 27018",
    fullName: "ISO/IEC 27018 Cloud Privacy",
    description: "Protection of personal data in public clouds",
    gradient: "from-cyan-600 to-blue-600",
    apiEndpoint: "/api/compliance-report",
    reportType: "iso27018",
    scanLabel: "Run ISO 27018 Scan",
    inputType: "aws",
  },
  wafr: {
    label: "AWS Well-Architected",
    fullName: "AWS Well-Architected Framework",
    description: "Cloud best practices across 6 pillars",
    gradient: "from-orange-500 to-amber-600",
    apiEndpoint: "/api/compliance-report",
    reportType: "wafr",
    scanLabel: "Run WAFR Scan",
    inputType: "aws",
  },
  "cis-compliance": {
    label: "CIS Benchmark",
    fullName: "CIS AWS Foundations Benchmark",
    description: "Security baseline configuration standards",
    gradient: "from-slate-600 to-gray-700",
    apiEndpoint: "/api/compliance-report",
    reportType: "cis",
    scanLabel: "Run CIS Scan",
    inputType: "aws",
  },
  dpdp: {
    label: "DPDP Act",
    fullName: "Digital Personal Data Protection Act",
    description: "India's data protection law for personal data",
    gradient: "from-orange-500 to-green-600",
    apiEndpoint: "/api/compliance-report",
    reportType: "dpdp",
    scanLabel: "Run DPDP Scan",
    inputType: "aws",
  },
  ndhm: {
    label: "NDHM",
    fullName: "National Digital Health Mission Guidelines",
    description: "India's digital health data protection standards",
    gradient: "from-emerald-500 to-green-600",
    apiEndpoint: "/api/compliance-report",
    reportType: "ndhm",
    scanLabel: "Run NDHM Scan",
    inputType: "aws",
  },
  ehr: {
    label: "EHR Standards",
    fullName: "Electronic Health Records Standards (India)",
    description: "MoHFW standards for electronic health records in India",
    gradient: "from-teal-500 to-emerald-600",
    apiEndpoint: "/api/compliance-report",
    reportType: "ehr",
    scanLabel: "Run EHR Scan",
    inputType: "aws",
  },
};
