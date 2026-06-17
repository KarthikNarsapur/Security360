// utils/complianceConfig.js
// Central config for cloud-agnostic Compliance & Industry dashboards.
// Single source of truth for schemas, framework configs, industry mappings, and helpers.

// ─── Severity ─────────────────────────────────────────────────────────────────

export const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

export const normalizeSeverity = (raw) => {
  const map = { critical: "Critical", high: "High", medium: "Medium", low: "Low", none: "None" };
  return map[(raw || "").toLowerCase()] || "Low";
};

export const sortBySeverity = (findings) =>
  [...findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
  );

// ─── Source Mapping ───────────────────────────────────────────────────────────

const SOURCE_MAP = {
  // AWS
  s3: "s3",
  ec2: "ec2",
  iam: "iam",
  rds: "rds",
  guardduty: "guardduty",
  cloudtrail: "cloudtrail",
  config: "config",
  inspector: "inspector",
  securityhub: "securityhub",
  waf: "waf",
  kms: "kms",
  ebs: "ebs",
  vpc: "vpc",
  lambda: "lambda",
  dynamodb: "dynamodb",
  ssm: "ssm",
  "secrets manager": "secrets_manager",
  secretsmanager: "secrets_manager",
  // Azure
  "blob storage": "azure_blob",
  "azure sql": "azure_sql",
  "cosmos db": "azure_cosmos",
  "key vault": "azure_keyvault",
  "virtual machine": "azure_vm",
  "network security group": "azure_nsg",
  // GCP
  "cloud storage": "gcp_storage",
  "compute engine": "gcp_compute",
  "cloud sql": "gcp_sql",
  bigquery: "gcp_bigquery",
};

const deriveSource = (service) => {
  if (!service) return "unknown";
  const key = service.toLowerCase().trim();
  return SOURCE_MAP[key] || key.replace(/[\s/]+/g, "_");
};

// ─── Compliance Framework Config ──────────────────────────────────────────────

export const COMPLIANCE_FRAMEWORKS = {
  gdpr: {
    key: "gdpr",
    label: "GDPR",
    fullName: "General Data Protection Regulation",
    description: "EU data protection and privacy regulation",
    icon: "🛡",
    gradient: "from-blue-600 to-cyan-600",
    reportType: "gdpr",
    simpleExplanation: "Protects the personal data of people in the European Union. If your business collects names, emails, or any personal info from EU citizens, this applies to you.",
    whoNeedsIt: "Any business handling EU customer data",
    keyFocus: "Data privacy, consent, right to be forgotten",
  },
  pcidss: {
    key: "pcidss",
    label: "PCI DSS",
    fullName: "Payment Card Industry Data Security Standard",
    description: "Mandatory for all card payment environments",
    icon: "💳",
    gradient: "from-blue-600 to-indigo-600",
    reportType: "pcidss",
    simpleExplanation: "Keeps credit card data safe. If your business accepts, processes, or stores credit card payments, you must follow these rules.",
    whoNeedsIt: "Any business that handles credit card payments",
    keyFocus: "Payment data encryption, access control, network security",
  },
  hipaa: {
    key: "hipaa",
    label: "HIPAA",
    fullName: "Health Insurance Portability and Accountability Act",
    description: "US healthcare data protection standard",
    icon: "🏥",
    gradient: "from-emerald-600 to-teal-600",
    reportType: "hipaa",
    simpleExplanation: "Protects patient health information in the United States. Hospitals, clinics, insurance companies, and their tech partners must follow these rules.",
    whoNeedsIt: "Healthcare providers, insurers, and their business partners",
    keyFocus: "Patient data privacy, secure health records, breach notification",
  },
  soc2: {
    key: "soc2",
    label: "SOC 2",
    fullName: "Service Organization Control 2",
    description: "Enterprise security, availability, and confidentiality",
    icon: "🏢",
    gradient: "from-violet-600 to-purple-600",
    reportType: "soc2",
    simpleExplanation: "Proves your company handles customer data responsibly. Enterprise clients often require this before signing contracts with SaaS or cloud service providers.",
    whoNeedsIt: "SaaS companies, cloud providers, any B2B service handling customer data",
    keyFocus: "Security, availability, processing integrity, confidentiality, privacy",
  },
  fedramp: {
    key: "fedramp",
    label: "FedRAMP",
    fullName: "Federal Risk and Authorization Management Program",
    description: "US government cloud security authorization",
    icon: "🏛",
    gradient: "from-red-600 to-rose-600",
    reportType: "fedramp",
    simpleExplanation: "Required for any cloud service used by the US federal government. It ensures cloud products meet strict security standards before government agencies can use them.",
    whoNeedsIt: "Cloud providers selling to US government agencies",
    keyFocus: "Government-grade security, continuous monitoring, risk assessment",
  },
  wafr: {
    key: "wafr",
    label: "AWS Well-Architected",
    fullName: "AWS Well-Architected Framework",
    description: "Cloud best practices across 6 pillars",
    icon: "☁️",
    gradient: "from-orange-500 to-amber-600",
    reportType: "wafr",
    simpleExplanation: "A set of best practices from AWS to help you build secure, reliable, and cost-effective cloud systems. Think of it as a health check for your cloud setup.",
    whoNeedsIt: "Any team running workloads on AWS",
    keyFocus: "Security, reliability, performance, cost optimization, sustainability",
  },
  cis: {
    key: "cis",
    label: "CIS Benchmark",
    fullName: "CIS AWS Foundations Benchmark",
    description: "Security baseline configuration standards",
    icon: "🔒",
    gradient: "from-slate-600 to-gray-700",
    reportType: "cis",
    simpleExplanation: "A checklist of security settings that every cloud account should have. Created by security experts worldwide, it covers the basics that prevent most common attacks.",
    whoNeedsIt: "Any organization using cloud services",
    keyFocus: "Account security, logging, monitoring, networking defaults",
  },
  nist: {
    key: "nist",
    label: "NIST CSF",
    fullName: "NIST Cybersecurity Framework",
    description: "Risk-based cybersecurity framework",
    icon: "📋",
    gradient: "from-indigo-600 to-blue-700",
    reportType: "nist",
    simpleExplanation: "A widely-used framework that helps organizations understand, manage, and reduce cybersecurity risk. It organizes security into five simple steps: Identify, Protect, Detect, Respond, Recover.",
    whoNeedsIt: "Organizations of any size looking to improve their security posture",
    keyFocus: "Risk management, incident response, security governance",
  },
  nist80053: {
    key: "nist80053",
    label: "NIST SP 800-53",
    fullName: "NIST Special Publication 800-53",
    description: "Security and privacy controls for federal systems",
    icon: "📜",
    gradient: "from-indigo-700 to-purple-700",
    reportType: "nist80053",
    simpleExplanation: "A comprehensive catalog of security controls required for US federal information systems. It is the most detailed security standard used by government agencies.",
    whoNeedsIt: "Federal agencies and contractors handling government data",
    keyFocus: "Access control, audit, incident response, system protection",
  },
  iso27001: {
    key: "iso27001",
    label: "ISO/IEC 27001",
    fullName: "ISO/IEC 27001 Information Security",
    description: "International information security management standard",
    icon: "🌐",
    gradient: "from-teal-600 to-cyan-700",
    reportType: "iso27001",
    simpleExplanation: "The international gold standard for information security management. Getting certified shows your customers and partners that you take security seriously at every level of your organization.",
    whoNeedsIt: "Organizations seeking international security certification",
    keyFocus: "Security management system, risk assessment, continuous improvement",
  },
  iso27018: {
    key: "iso27018",
    label: "ISO/IEC 27018",
    fullName: "ISO/IEC 27018 Cloud Privacy",
    description: "Protection of personal data in public clouds",
    icon: "🔐",
    gradient: "from-cyan-600 to-blue-600",
    reportType: "iso27018",
    simpleExplanation: "Extends ISO 27001 specifically for cloud providers handling personal data. It ensures cloud services protect your customers' private information properly.",
    whoNeedsIt: "Cloud service providers processing personal data",
    keyFocus: "Cloud privacy, data processing transparency, customer data protection",
  },

  // ─── Indian Frameworks ────────────────────────────────────────────────────
  dpdp: {
    key: "dpdp",
    label: "DPDP Act",
    fullName: "Digital Personal Data Protection Act",
    description: "India's data protection law for personal data",
    icon: "🇮🇳",
    gradient: "from-orange-500 to-green-600",
    reportType: "dpdp",
    simpleExplanation: "India's landmark data protection law that governs how businesses collect, store, and process personal data of Indian citizens. Similar to GDPR but tailored for India, it gives individuals rights over their data and imposes obligations on organizations handling it.",
    whoNeedsIt: "Any organization processing personal data of Indian citizens",
    keyFocus: "Consent management, data principal rights, data fiduciary obligations, breach notification",
  },
  rbi: {
    key: "rbi",
    label: "RBI CSF",
    fullName: "RBI Cyber Security Framework",
    description: "Reserve Bank of India cybersecurity guidelines for banks",
    icon: "🏦",
    gradient: "from-indigo-600 to-purple-600",
    reportType: "rbi",
    simpleExplanation: "Mandatory cybersecurity framework issued by the Reserve Bank of India for all banks and financial institutions. It requires continuous surveillance, IT governance, and incident response capabilities to protect India's banking infrastructure from cyber threats.",
    whoNeedsIt: "Banks, NBFCs, and financial institutions regulated by RBI",
    keyFocus: "IT governance, cyber resilience, SOC operations, incident response, audit trails",
  },
  sebi: {
    key: "sebi",
    label: "SEBI CSCRF",
    fullName: "SEBI Cyber Security & Cyber Resilience Framework",
    description: "SEBI CSCRF 2024 — 128 checks across Governance, Protect, Detect, Respond, Recover & Data Localization",
    icon: "📈",
    gradient: "from-violet-600 to-indigo-600",
    reportType: "sebi",
    simpleExplanation: "Cybersecurity and Cyber Resilience Framework mandated by SEBI (Circular SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113) for all regulated entities. Covers 6 cybersecurity functions — Governance, Identify, Protect, Detect, Respond, Recover — plus India data localization requirements and enhanced assessments including Ransomware Readiness and Cyber Resilience Scoring.",
    whoNeedsIt: "Stock exchanges, depositories, brokers, mutual funds, portfolio managers, and all SEBI-regulated entities",
    keyFocus: "IAM & access control, data encryption, network segmentation, SOC monitoring, backup & DR, India data residency, cyber resilience scoring",
  },

  // ─── Healthcare-Specific Frameworks ───────────────────────────────────────
  ndhm: {
    key: "ndhm",
    label: "NDHM",
    fullName: "National Digital Health Mission Guidelines",
    description: "India's digital health data protection standards",
    icon: "🏥",
    gradient: "from-emerald-500 to-green-600",
    reportType: "ndhm",
    simpleExplanation: "India's National Digital Health Mission (Ayushman Bharat Digital Mission) sets standards for how health data is created, stored, and shared digitally. It establishes the Health ID system and ensures interoperability across hospitals, labs, and pharmacies while protecting patient privacy.",
    whoNeedsIt: "Hospitals, clinics, health-tech platforms, and labs operating in India",
    keyFocus: "Health ID, consent-based data sharing, interoperability, patient privacy",
  },
  ehr: {
    key: "ehr",
    label: "EHR Standards",
    fullName: "Electronic Health Records Standards (India)",
    description: "MoHFW standards for electronic health records in India",
    icon: "📋",
    gradient: "from-teal-500 to-emerald-600",
    reportType: "ehr",
    simpleExplanation: "Standards issued by India's Ministry of Health & Family Welfare for maintaining Electronic Health Records. They define how patient medical records should be digitized, stored securely, and made accessible to authorized healthcare providers while maintaining confidentiality.",
    whoNeedsIt: "Hospitals, clinics, and health IT vendors managing patient records in India",
    keyFocus: "Record standardization, secure storage, access control, data portability, audit logging",
  },
};

// ─── Industry Config ──────────────────────────────────────────────────────────

export const INDUSTRY_CONFIG = {
  healthcare: {
    label: "Healthcare",
    icon: "🏥",
    description: "Compliance frameworks for healthcare organizations",
    gradient: "from-emerald-600 to-teal-600",
    frameworks: {
      mandatory: ["hipaa", "dpdp", "ndhm", "ehr"],
      recommended: ["nist", "iso27001", "iso27018", "rbi"],
      optional: ["cis", "sebi"],
    },
  },
  finance: {
    label: "Finance",
    icon: "💳",
    description: "Compliance frameworks for financial services",
    gradient: "from-blue-600 to-indigo-600",
    frameworks: {
      mandatory: ["pcidss", "soc2", "rbi", "sebi"],
      recommended: ["nist", "iso27001", "dpdp"],
      optional: ["cis"],
    },
  },
  saas: {
    label: "SaaS",
    icon: "☁️",
    description: "Compliance frameworks for SaaS platforms",
    gradient: "from-violet-600 to-purple-600",
    frameworks: {
      mandatory: ["soc2", "gdpr"],
      recommended: ["iso27001", "nist"],
      optional: ["cis", "wafr"],
    },
  },
  government: {
    label: "Government",
    icon: "🏛",
    description: "Compliance frameworks for government agencies",
    gradient: "from-red-600 to-rose-600",
    frameworks: {
      mandatory: ["fedramp", "nist80053"],
      recommended: ["nist", "cis"],
      optional: ["iso27001"],
    },
  },
  ecommerce: {
    label: "E-commerce",
    icon: "🛒",
    description: "Compliance frameworks for e-commerce platforms",
    gradient: "from-orange-500 to-amber-600",
    frameworks: {
      mandatory: ["pcidss", "gdpr"],
      recommended: ["soc2", "iso27001"],
      optional: ["cis"],
    },
  },
};

// ─── Cloud Account Keys ───────────────────────────────────────────────────────

export const CLOUD_ACCOUNT_KEYS = {
  aws: "account_details",
  azure: "azure_account_details",
  gcp: "gcp_account_details",
};

// ─── Normalize Findings ───────────────────────────────────────────────────────

export const normalizeFindings = (rawResults = [], cloud) => {
  if (!Array.isArray(rawResults)) return [];

  return rawResults
    .map((item, index) => {
      const frameworks = (item.frameworks || []).map((f) => (f || "").toLowerCase());
      const severity = normalizeSeverity(item.severity_level || item.severity);
      return {
        id: item.control_id || item.id || `${cloud}-check-${index}`,
        cloud,
        source: deriveSource(item.service),
        service: item.service || "",
        resource: item.resource || "",
        region: item.region || "global",
        severity,
        frameworks,
        frameworkSet: new Set(frameworks),
        check_name: item.check_name || "Unknown",
        description: item.description || item.problem_statement || "",
        remediation: item.remediation || item.recommendation || "",
        affected: item.additional_info?.affected ?? item.affected ?? 0,
        total_scanned: item.additional_info?.total_scanned ?? item.total_scanned ?? 0,
        severity_score: item.severity_score || 0,
        fullData: item,
      };
    })
    .filter((f) => f.severity !== "None" && f.severity_score > 0);
};

// ─── Merge Multi-Cloud Findings ───────────────────────────────────────────────

export const mergeMultiCloudFindings = (awsResult, azureResult, gcpResult) => {
  const clouds = { aws: awsResult, azure: azureResult, gcp: gcpResult };
  const allFindings = [];
  const cloudStatuses = {};

  for (const [cloud, result] of Object.entries(clouds)) {
    // null = cloud was not selected by user — skip entirely
    if (result === null) {
      cloudStatuses[cloud] = {
        status: "skipped",
        lastScanned: null,
        error: null,
      };
      continue;
    }

    if (result.status === "error") {
      cloudStatuses[cloud] = {
        status: "error",
        lastScanned: null,
        error: result.error || "Failed to load",
      };
      continue;
    }

    const findings = result.findings || [];
    cloudStatuses[cloud] = {
      status: findings.length > 0 ? "ok" : "empty",
      lastScanned: result.lastScanned || null,
      error: null,
    };
    allFindings.push(...findings);
  }

  return {
    findings: sortBySeverity(allFindings),
    cloudStatuses,
  };
};

// ─── Filters ──────────────────────────────────────────────────────────────────

export const filterByCloud = (findings, cloudKey) => {
  if (!cloudKey || cloudKey === "all") return findings;
  return findings.filter((f) => f.cloud === cloudKey);
};

export const filterByFramework = (findings, frameworkKey) => {
  if (!frameworkKey) return findings;
  return findings.filter((f) => f.frameworkSet.has(frameworkKey));
};
