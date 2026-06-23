import { useEffect, useState } from "react";
import { Button, Alert } from "antd";
import { Play, Clock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import Cookies from "js-cookie";

import AccountDropdown from "../UI/DropDown/AccountDropdown";
import RegionDropdown from "../UI/DropDown/RegionDropdown";
import Spinner from "../UI/Spinner";
import { LoadingSkeletonCisDashboardS3Fetch } from "../LoadingSkeleton";
import {
  NoDataAvailableMessageComponent,
  GetSampleReportNote,
  fetchUserDetails,
} from "../Utils";
import { notifyError, notifySuccess, notifyInfo } from "../Notification";

import ScanCharts from "../Framework/shared/ScanCharts";
import SummaryCards from "../Framework/shared/SummaryCards";
import FindingsTable from "../Framework/shared/FindingsTable";
import FindingDrawer from "../Framework/shared/FindingDrawer";
import { computeDashboardMeta } from "../../utils/frameworkUtils";
import {
  COMPLIANCE_FRAMEWORKS,
  CLOUD_ACCOUNT_KEYS,
  normalizeFindings,
  sortBySeverity,
} from "../../utils/complianceConfig";

// Frameworks that have a dedicated scan endpoint
const SCAN_ENDPOINTS = {
  dpdp: "/api/dpdp-scan",
  rbi: "/api/rbi-scan",
  sebi: "/api/sebi-scan",
  pcidss: "/api/pcidss-scan",
  gdpr: "/api/gdpr-scan",
  hipaa: "/api/hipaa-scan",
  soc2: "/api/soc2-scan",
  fedramp: "/api/fedramp-scan",
  wafr: "/api/wafr-scan",
  cis: "/api/cis-scan",
  nist: "/api/nist-scan",
  nist80053: "/api/nist80053-scan",
  iso27001: "/api/iso27001-scan",
  iso27018: "/api/iso27018-scan",
  iso42001: "/api/iso42001-scan",
  owasp: "/api/owasp-scan",
  ndhm: "/api/ndhm-scan",
  ehr: "/api/ehr-scan",
  "azure-waf": "/api/azure-waf-scan",
  "gcp-caf": "/api/gcp-caf-scan",
};

const ComplianceDashboard = ({
  frameworkKey,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) => {
  const config = COMPLIANCE_FRAMEWORKS[frameworkKey];
  const navigate = useNavigate();
  const backendUrl = process.env.REACT_APP_BACKEND_URL;

  // ── Account selection ─────────────────────────────────────────────────────
  const [awsAccount, setAwsAccount] = useState(undefined);

  // ── Scan controls ───────────────────────────────────────────────────────────
  const [scanAccounts, setScanAccounts] = useState([]);
  const [scanRegions, setScanRegions] = useState([]);
  const [scanning, setScanning] = useState(false);
  const hasScanEndpoint = !!SCAN_ENDPOINTS[frameworkKey];

  // ── Scan progress ───────────────────────────────────────────────────────────
  const [scanProgress, setScanProgress] = useState({ percent: 0, message: "" });
  const [scanComplete, setScanComplete] = useState(false);
  const wsRef = { current: null };

  // ── Data state ──────────────────────────────────────────────────────────────
  const [allFindings, setAllFindings] = useState([]);
  const [cloudStatuses, setCloudStatuses] = useState({});
  const [loading, setLoading] = useState(false);
  const [isSampleReport, setIsSampleReport] = useState(false);
  const [isReportAvailable, setIsReportAvailable] = useState(false);

  // ── Drawer ──────────────────────────────────────────────────────────────────
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [cardFilter, setCardFilter] = useState("failed");
  const [hiddenFindings, setHiddenFindings] = useState(() => {
    const saved = localStorage.getItem(`hidden_compliance_${frameworkKey}`);
    return saved ? JSON.parse(saved) : [];
  });

  // ── Account lists from localStorage ─────────────────────────────────────────
  const awsAccounts = JSON.parse(localStorage.getItem(CLOUD_ACCOUNT_KEYS.aws) || "[]");

  useEffect(() => {
    const getUserData = async () => {
      const result = await fetchUserDetails({ navigate });
      if (result.status === "ok") {
        setUserName(result.userName);
        setFullName(result.fullName);
        setAccountDetails(result.accountDetails);
        setEksAccountDetails(result.eksAccountDetails);
      }
    };
    getUserData();
  }, []);

  useEffect(() => {
    localStorage.setItem(
      `hidden_compliance_${frameworkKey}`,
      JSON.stringify(hiddenFindings)
    );
  }, [hiddenFindings, frameworkKey]);

  // ── Reset state when switching frameworks ───────────────────────────────────
  useEffect(() => {
    setAllFindings([]);
    setCloudStatuses({});
    setIsReportAvailable(false);
    setIsSampleReport(false);
    setAwsAccount(undefined);
    setScanComplete(false);
    setScanProgress({ percent: 0, message: "" });
    setCardFilter("failed");
    setHiddenFindings(() => {
      const saved = localStorage.getItem(`hidden_compliance_${frameworkKey}`);
      return saved ? JSON.parse(saved) : [];
    });
  }, [frameworkKey]);

  // ── Fetch report for AWS ──────────────────────────────────────────────────────
  const fetchAwsReport = async (accountId, isSample = false) => {
    try {
      const parsedAccount = isSample ? {} : JSON.parse(accountId || "{}");
      const payload = {
        account_id: parsedAccount.account_id || "",
        username: localStorage.getItem("username"),
        type: config.reportType,
        is_sample: isSample,
        cloud: "aws",
      };

      const response = await fetch(`${backendUrl}/api/get-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const apiResponse = await response.json();

      if (apiResponse?.status === "ok") {
        const report = apiResponse.data;
        const results = Array.isArray(report?.results)
          ? report.results.flatMap((r) =>
              Array.isArray(r.data) ? r.data : r.data ? Object.values(r.data) : [r]
            )
          : [];
        return {
          status: "ok",
          findings: normalizeFindings(results, "aws"),
          lastScanned: report?.timestamp || new Date().toISOString(),
          error: null,
        };
      }
      return { status: "error", findings: [], lastScanned: null, error: apiResponse?.error_message || "Failed" };
    } catch (err) {
      return { status: "error", findings: [], lastScanned: null, error: err.message };
    }
  };

  // ── Load report ─────────────────────────────────────────────────────────────
  const loadReports = async (isSample = false) => {
    setLoading(true);
    setIsSampleReport(isSample);

    const result = await fetchAwsReport(isSample ? "" : awsAccount, isSample);

    const cloudStatuses = {};
    if (result.status === "error") {
      cloudStatuses.aws = { status: "error", lastScanned: null, error: result.error || "Failed to load" };
    } else {
      cloudStatuses.aws = {
        status: result.findings.length > 0 ? "ok" : "empty",
        lastScanned: result.lastScanned || null,
        error: null,
      };
    }

    setAllFindings(sortBySeverity(result.findings || []));
    setCloudStatuses(cloudStatuses);
    setIsReportAvailable(true);
    setLoading(false);
  };

  const handleViewReports = () => {
    if (!awsAccount) {
      notifyError("Please select an AWS account");
      return;
    }
    loadReports(false);
  };

  // ── Run compliance scan (AWS only for now) ──────────────────────────────────
  const handleRunScan = async () => {
    if (!hasScanEndpoint) return;

    const access_token = Cookies.get("access_token");
    const username = localStorage.getItem("username") || "";

    if (!access_token || !username) {
      notifyInfo("Session expired, login again..");
      navigate("/login");
      return;
    }

    const parsedAwsAccounts = (scanAccounts || []).map((a) => { try { return JSON.parse(a); } catch { return null; } }).filter(Boolean);

    if (!parsedAwsAccounts.length) {
      notifyError("Please select at least one AWS account");
      return;
    }
    if (!scanRegions?.length) {
      notifyError("Please select at least one AWS region");
      return;
    }

    setScanning(true);
    setScanComplete(false);
    setScanProgress({ percent: 0, message: "Connecting..." });

    // Use WebSocket for real-time progress
    const wsProtocol = backendUrl.startsWith("https") ? "wss" : "ws";
    const wsHost = backendUrl.replace(/^https?:\/\//, "");
    const wsUrl = `${wsProtocol}://${wsHost}/ws/scan/${frameworkKey}`;

    const scanPayload = {
      accounts: parsedAwsAccounts,
      regions: scanRegions,
      username,
    };

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;
    let scanResult = null;

    const wsPromise = new Promise((resolve, reject) => {
      ws.onopen = () => {
        ws.send(JSON.stringify(scanPayload));
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setScanProgress({ percent: data.percent || 0, message: data.message || "" });
          if (data.status === "complete" || data.status === "error") {
            scanResult = data.result || data;
            resolve(data);
          }
        } catch (e) {
          // ignore parse errors
        }
      };

      ws.onerror = (err) => {
        reject(new Error("WebSocket connection failed"));
      };

      ws.onclose = () => {
        // Only reject if we never got a result
        setTimeout(() => {
          if (!scanResult) {
            reject(new Error("Connection closed unexpectedly"));
          }
        }, 1000);
      };

      // Timeout after 15 minutes
      setTimeout(() => {
        if (!scanResult) reject(new Error("Scan timed out after 15 minutes"));
      }, 900000);
    });

    try {
      const wsResult = await wsPromise;

      if (wsResult?.status === "error") {
        notifyError(`AWS: ${wsResult?.message || wsResult?.result?.error_message || "Scan failed"}`);
      } else {
        const result = scanResult || wsResult?.result;
        if (result?.notifications) {
          result.notifications.success?.forEach((msg) => notifySuccess(`AWS: ${msg}`));
          result.notifications.error?.forEach((msg) => notifyError(`AWS: ${msg}`));
        } else if (result?.status === "ok") {
          notifySuccess("AWS: Scan completed successfully");
        }
      }

      setScanAccounts([]);
      setScanRegions([]);
    } catch (err) {
      notifyError("Scan failed: " + err.message);
    } finally {
      try { ws.close(); } catch (e) { /* ignore */ }
      wsRef.current = null;
      setScanning(false);
      setScanComplete(true);
      setScanProgress({ percent: 100, message: "Scan complete!" });
    }
  };

  const handleCancelScan = () => {
    if (wsRef.current) {
      try { wsRef.current.close(); } catch (e) { /* ignore */ }
      wsRef.current = null;
    }
    setScanning(false);
    setScanProgress({ percent: 0, message: "" });
    setScanComplete(false);
    notifyInfo("Scan cancelled");
  };

  const handleViewLatestReport = () => {
    setScanComplete(false);
    loadReports(false);
  };

  // ── Derived data ────────────────────────────────────────────────────────────
  const allCloudFindings = sortBySeverity(allFindings);
  const filteredFindings = allCloudFindings.filter((f) => {
    if (cardFilter === "passed") return f.affected === 0;
    if (cardFilter === "failed") return f.affected > 0;
    if (cardFilter === "critical") return f.affected > 0 && f.severity === "Critical";
    return true; // "all"
  });

  const tableData = filteredFindings.map((f, i) => ({
    key: `${f.id}-${f.cloud}-${f.region}-${i}`,
    id: f.id,
    cloud: f.cloud,
    source: f.source,
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

  const dashboardMeta = computeDashboardMeta(
    allCloudFindings.map((f) => ({
      total_scanned: f.total_scanned,
      affected: f.affected,
      severity_level: f.severity,
    }))
  );

  const handleHideFinding = (e, findingId) => {
    e.stopPropagation();
    setHiddenFindings((prev) => [...prev, findingId]);
  };

  const allCloudsFailed = cloudStatuses.aws?.status === "error";

  if (!config) return <div className="p-12 text-red-500">Unknown framework: {frameworkKey}</div>;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="p-6 pl-12">
        <div className="max-w-7xl mx-auto">
          {/* ── Header ─────────────────────────────────────────────────────── */}
          <div className="mb-8">
            <div className="mt-2 flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-indigo-700 bg-clip-text text-transparent">
                  {config.fullName}
                </h1>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                  {config.description}
                </p>
              </div>
            </div>

            {/* ── Brief explanation ─────────────────────────────────────────── */}
            <div className="mt-4 bg-white/60 dark:bg-slate-800/60 backdrop-blur-lg rounded-xl p-4 border border-indigo-100 dark:border-slate-700">
              <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                {config.simpleExplanation}
              </p>
              <div className="flex flex-wrap gap-6 mt-3 text-xs text-slate-500 dark:text-slate-400">
                <div>
                  <span className="font-semibold text-slate-700 dark:text-slate-300">Who needs it: </span>
                  {config.whoNeedsIt}
                </div>
                <div>
                  <span className="font-semibold text-slate-700 dark:text-slate-300">Key focus: </span>
                  {config.keyFocus}
                </div>
              </div>
            </div>

            <div className="mt-6 border-t border-gray-200 dark:border-gray-700" />

            {/* ── Run Scan Section (only for frameworks with scan endpoints) ── */}
            {hasScanEndpoint && !scanning && (
              <div className="mt-6 bg-white/60 dark:bg-slate-800/60 backdrop-blur-lg rounded-xl p-4 border border-indigo-100 dark:border-slate-700">
                <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">Run {config.label} Scan</h3>
                <div className="flex flex-wrap items-end gap-4">
                  <div className="w-48">
                    <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 block">AWS Accounts</label>
                    <AccountDropdown
                      onAccountChange={setScanAccounts}
                      selectedAccounts={scanAccounts}
                      accountOptions={awsAccounts}
                      placeholder={awsAccounts.length > 0 ? "Select AWS accounts" : "No AWS accounts"}
                      disabled={scanning || loading}
                    />
                  </div>
                  <div className="w-48">
                    <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 block">AWS Regions</label>
                    <RegionDropdown
                      onRegionChange={setScanRegions}
                      selectedRegions={scanRegions}
                      disabled={scanning || loading}
                    />
                  </div>
                  <Button
                    type="primary"
                    icon={<Play className="w-4 h-4" />}
                    onClick={handleRunScan}
                    disabled={scanning || loading}
                    className="!bg-gradient-to-r from-indigo-600 to-indigo-700 border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                  >
                    Run {config.label} Scan
                  </Button>
                </div>
              </div>
            )}

            {scanning && (
              <div className="mt-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 border border-indigo-100 dark:border-slate-700 p-12 text-center">
                <div className="max-w-md mx-auto">
                  <p className="text-lg font-semibold text-slate-700 dark:text-slate-200 mb-2">
                    Running {config.label} scan...
                  </p>
                  <p className="text-sm text-slate-500 dark:text-slate-400 mb-4 font-mono">
                    {scanProgress.message || "Initializing..."}
                  </p>
                  {/* Progress bar */}
                  <div className="w-full bg-gray-200 dark:bg-slate-700 rounded-full h-3 overflow-hidden">
                    <div
                      className="h-3 rounded-full transition-all duration-500 ease-out"
                      style={{
                        width: `${scanProgress.percent}%`,
                        background: scanProgress.percent >= 96
                          ? "linear-gradient(90deg, #10b981, #34d399)"
                          : "linear-gradient(90deg, #6366f1, #818cf8)",
                      }}
                    />
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-2 font-mono">
                    {scanProgress.percent}%
                  </p>
                  <Button
                    onClick={handleCancelScan}
                    className="mt-4"
                    danger
                    size="small"
                  >
                    Cancel Scan
                  </Button>
                </div>
              </div>
            )}


            {/* ── View Reports Section ──────────────────────────────────────── */}
            {!scanning && (
              <>
                <div className="mt-6 border-t border-gray-200 dark:border-gray-700" />

            {/* ── Account selectors ───────────────────────────────────── */}
            <div className="mt-6 flex flex-wrap items-center gap-4">
              <div className="w-52">
                <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 block">AWS Account</label>
                <AccountDropdown
                  onAccountChange={setAwsAccount}
                  selectedAccounts={awsAccount}
                  accountOptions={awsAccounts}
                  placeholder={awsAccounts.length > 0 ? "Select AWS account" : "No AWS accounts"}
                  mode="single"
                  disabled={loading}
                />
              </div>
              <div className="flex items-end gap-2 mt-4">
                <Button
                  type="primary"
                  icon={loading ? null : <Play className="w-4 h-4" />}
                  onClick={handleViewReports}
                  disabled={loading}
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                >
                  {loading ? <span>Loading... <Spinner /></span> : "View Reports"}
                </Button>
                <Button
                  type="primary"
                  icon={loading ? null : <Play className="w-4 h-4" />}
                  onClick={() => loadReports(true)}
                  disabled={loading && isSampleReport}
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                >
                  {loading && isSampleReport ? <span>Loading Sample... <Spinner /></span> : "View Sample Report"}
                </Button>
              </div>
            </div>
              </>
            )}
          </div>

          {/* ── Error banner ──────────────────────────────────────────────── */}
          {cloudStatuses.aws?.status === "error" && isReportAvailable && (
            <div className="mb-4">
              <Alert
                type="warning"
                showIcon
                className="mb-2"
                message={`Failed to load AWS findings: ${cloudStatuses.aws?.error || "Unknown error"}`}
              />
            </div>
          )}

          {/* ── Last scanned timestamp ─────────────────────────────────── */}
          {isReportAvailable && cloudStatuses.aws && cloudStatuses.aws.status !== "skipped" && (
            <div className="mt-4 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-indigo-100 dark:border-slate-700">
              <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-400">
                {cloudStatuses.aws.status === "error" ? (
                  <span className="w-2 h-2 rounded-full bg-red-500" />
                ) : (
                  <Clock className="w-4 h-4 text-indigo-600" />
                )}
                <span className="font-medium">AWS:</span>
                <span className="text-slate-900 dark:text-white">
                  {cloudStatuses.aws.status === "error"
                    ? "Failed"
                    : cloudStatuses.aws.lastScanned
                      ? new Date(cloudStatuses.aws.lastScanned.replace("Z", "")).toLocaleString("en-GB", { hour12: true })
                      : "No data"}
                </span>
              </div>
            </div>
          )}

          {/* ── Body ───────────────────────────────────────────────────────── */}
          {loading ? (
            <div className="mt-6"><LoadingSkeletonCisDashboardS3Fetch /></div>
          ) : !isReportAvailable ? (
            <div className="mt-6">
              <NoDataAvailableMessageComponent
                messages={[
                  "No data available",
                  `Select an AWS account and click 'View Reports' to see ${config.label} findings.`,
                ]}
              />
            </div>
          ) : allCloudsFailed ? (
            <div className="mt-6">
              <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 border border-red-200 dark:border-red-800 p-12 text-center">
                <div className="text-4xl mb-4">⚠️</div>
                <p className="text-lg font-medium text-red-600 dark:text-red-400">
                  Failed to load findings from AWS.
                </p>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-2">
                  {hasScanEndpoint
                    ? `The backend may not have ${config.label} scan data yet. Run a scan first, or try the Sample Report.`
                    : `No ${config.label} report data available for this account. Try the Sample Report to preview the dashboard.`}
                </p>
              </div>
            </div>
          ) : filteredFindings.length === 0 ? (
            <div className="mt-6">
              <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 border border-indigo-100 dark:border-slate-700 p-12 text-center">
                <div className="text-4xl mb-4">✅</div>
                <p className="text-lg font-medium text-slate-700 dark:text-slate-300">
                  No {config.label} violations found.
                </p>
              </div>
            </div>
          ) : (
            <div className="mt-6">
              {isSampleReport && <GetSampleReportNote />}
              <ScanCharts meta={dashboardMeta} />
              <SummaryCards meta={dashboardMeta} onCardClick={(filter) => {
                if (filter === "passed") setCardFilter("passed");
                else if (filter === "failed") setCardFilter("failed");
                else if (filter === "critical") setCardFilter("critical");
                else setCardFilter("all");
                document.getElementById("findings-table")?.scrollIntoView({ behavior: "smooth" });
              }} />
              <div id="findings-table">
              <FindingsTable
                tableData={tableData}
                frameworkKey={frameworkKey}
                showCloudColumn={true}
                allFindings={allCloudFindings.map((f, i) => ({
                  key: `${f.id}-${f.cloud}-${f.region}-${i}`,
                  id: f.id,
                  control_id: f.id,
                  cloud: f.cloud,
                  source: f.source,
                  check_name: f.check_name,
                  service: f.service,
                  severity_level: f.severity,
                  severity_score: f.severity_score,
                  affected: f.affected,
                  total_scanned: f.total_scanned,
                  region: f.region,
                  description: f.description,
                  fullData: f.fullData,
                }))}
                onRowClick={(record) => {
                  setSelectedFinding(record);
                  setDrawerVisible(true);
                }}
                hiddenFindings={hiddenFindings}
                onHideFinding={handleHideFinding}
              />
              </div>
              <FindingDrawer
                open={drawerVisible}
                onClose={() => setDrawerVisible(false)}
                finding={selectedFinding}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ComplianceDashboard;
