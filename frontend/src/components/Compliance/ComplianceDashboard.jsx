import { useEffect, useState } from "react";
import { Button, Alert } from "antd";
import { Play, User, Clock } from "lucide-react";
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
import { notifyError, notifySuccess, notifyInfo, notifyRedirectToContact } from "../Notification";

import ScanCharts from "../Framework/shared/ScanCharts";
import SummaryCards from "../Framework/shared/SummaryCards";
import FindingsTable from "../Framework/shared/FindingsTable";
import FindingDrawer from "../Framework/shared/FindingDrawer";
import CloudFilter from "./CloudFilter";

import { computeDashboardMeta } from "../../utils/frameworkUtils";
import {
  COMPLIANCE_FRAMEWORKS,
  CLOUD_ACCOUNT_KEYS,
  normalizeFindings,
  mergeMultiCloudFindings,
  filterByCloud,
  sortBySeverity,
} from "../../utils/complianceConfig";

// Frameworks that have a dedicated scan endpoint
const SCAN_ENDPOINTS = {
  dpdp: "/api/dpdp-scan",
  rbi: "/api/rbi-scan",
  sebi: "/api/sebi-scan",
  pcidss: "/api/pcidss-scan",
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

  // ── Cloud filter ────────────────────────────────────────────────────────────
  const [selectedCloud, setSelectedCloud] = useState("all");

  // ── Account selection per cloud ─────────────────────────────────────────────
  const [awsAccount, setAwsAccount] = useState(undefined);
  const [azureAccount, setAzureAccount] = useState(undefined);
  const [gcpAccount, setGcpAccount] = useState(undefined);

  // ── Scan controls ───────────────────────────────────────────────────────────
  const [scanAccounts, setScanAccounts] = useState([]);
  const [scanAzureAccounts, setScanAzureAccounts] = useState([]);
  const [scanGcpAccounts, setScanGcpAccounts] = useState([]);
  const [scanRegions, setScanRegions] = useState([]);
  const [scanning, setScanning] = useState(false);
  const hasScanEndpoint = !!SCAN_ENDPOINTS[frameworkKey];

  // ── Data state ──────────────────────────────────────────────────────────────
  const [allFindings, setAllFindings] = useState([]);
  const [cloudStatuses, setCloudStatuses] = useState({});
  const [loading, setLoading] = useState(false);
  const [isSampleReport, setIsSampleReport] = useState(false);
  const [isReportAvailable, setIsReportAvailable] = useState(false);

  // ── Drawer ──────────────────────────────────────────────────────────────────
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [hiddenFindings, setHiddenFindings] = useState(() => {
    const saved = localStorage.getItem(`hidden_compliance_${frameworkKey}`);
    return saved ? JSON.parse(saved) : [];
  });

  // ── Account lists from localStorage ─────────────────────────────────────────
  const awsAccounts = JSON.parse(localStorage.getItem(CLOUD_ACCOUNT_KEYS.aws) || "[]");
  const azureAccounts = JSON.parse(localStorage.getItem(CLOUD_ACCOUNT_KEYS.azure) || "[]");
  const gcpAccounts = JSON.parse(localStorage.getItem(CLOUD_ACCOUNT_KEYS.gcp) || "[]");

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

  // ── Fetch report for a single cloud ─────────────────────────────────────────
  const fetchCloudReport = async (cloud, accountId, isSample = false) => {
    try {
      const parsedAccount = isSample ? {} : JSON.parse(accountId || "{}");
      const payload = {
        account_id: parsedAccount.account_id || "",
        username: localStorage.getItem("username"),
        type: config.reportType,
        is_sample: isSample,
        cloud,
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
          findings: normalizeFindings(results, cloud),
          lastScanned: report?.timestamp || new Date().toISOString(),
          error: null,
        };
      }
      return { status: "error", findings: [], lastScanned: null, error: apiResponse?.error_message || "Failed" };
    } catch (err) {
      return { status: "error", findings: [], lastScanned: null, error: err.message };
    }
  };

  // ── Load reports from all clouds ────────────────────────────────────────────
  const loadReports = async (isSample = false) => {
    setLoading(true);
    setIsSampleReport(isSample);

    // Only fetch clouds that have an account selected (or all for sample)
    const cloudConfigs = [
      { cloud: "aws", account: awsAccount },
      { cloud: "azure", account: azureAccount },
      { cloud: "gcp", account: gcpAccount },
    ];

    const promises = cloudConfigs.map(({ cloud, account }) => {
      if (isSample || account) {
        return fetchCloudReport(cloud, isSample ? "" : account, isSample);
      }
      // Cloud not selected — return null (skip it)
      return Promise.resolve(null);
    });

    const results = await Promise.allSettled(promises);

    const unwrap = (r) => {
      if (r.status !== "fulfilled") return { status: "error", findings: [], lastScanned: null, error: "Request failed" };
      return r.value; // null means cloud was not selected
    };

    const merged = mergeMultiCloudFindings(unwrap(results[0]), unwrap(results[1]), unwrap(results[2]));

    setAllFindings(merged.findings);
    setCloudStatuses(merged.cloudStatuses);
    setIsReportAvailable(true);
    setLoading(false);
  };

  const handleViewReports = () => {
    if (!awsAccount && !azureAccount && !gcpAccount) {
      notifyError("Select at least one account from any cloud");
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
    const parsedAzureAccounts = (scanAzureAccounts || []).map((a) => { try { return JSON.parse(a); } catch { return null; } }).filter(Boolean);
    const parsedGcpAccounts = (scanGcpAccounts || []).map((a) => { try { return JSON.parse(a); } catch { return null; } }).filter(Boolean);

    if (!parsedAwsAccounts.length && !parsedAzureAccounts.length && !parsedGcpAccounts.length) {
      notifyError("Select at least one account from any cloud");
      return;
    }
    if (parsedAwsAccounts.length > 0 && !scanRegions?.length) {
      notifyError("Please select at least one region for AWS scan");
      return;
    }

    setScanning(true);
    const scanEndpoint = SCAN_ENDPOINTS[frameworkKey];
    const scanPromises = [];

    // AWS scan
    if (parsedAwsAccounts.length > 0) {
      scanPromises.push(
        fetch(`${backendUrl}${scanEndpoint}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ accounts: parsedAwsAccounts, regions: scanRegions, username }),
        }).then((r) => r.json()).then((r) => ({ cloud: "AWS", ...r })).catch((e) => ({ cloud: "AWS", status: "error", error_message: e.message }))
      );
    }

    // Azure scan
    if (parsedAzureAccounts.length > 0) {
      scanPromises.push(
        fetch(`${backendUrl}${scanEndpoint}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ accounts: parsedAzureAccounts, regions: ["global"], username, cloud: "azure" }),
        }).then((r) => r.json()).then((r) => ({ cloud: "Azure", ...r })).catch((e) => ({ cloud: "Azure", status: "error", error_message: e.message }))
      );
    }

    // GCP scan
    if (parsedGcpAccounts.length > 0) {
      scanPromises.push(
        fetch(`${backendUrl}${scanEndpoint}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ accounts: parsedGcpAccounts, regions: ["global"], username, cloud: "gcp" }),
        }).then((r) => r.json()).then((r) => ({ cloud: "GCP", ...r })).catch((e) => ({ cloud: "GCP", status: "error", error_message: e.message }))
      );
    }

    try {
      const results = await Promise.all(scanPromises);
      for (const result of results) {
        if (result?.status === "ok") {
          result.notifications?.success?.forEach((msg) => notifySuccess(`${result.cloud}: ${msg}`));
          result.notifications?.error?.forEach((msg) => notifyError(`${result.cloud}: ${msg}`));
        } else {
          notifyError(`${result.cloud}: ${result?.error_message || "Scan failed"}`);
          if (result?.fail_type === "contact_us") notifyRedirectToContact(navigate, 5);
        }
      }
      setScanAccounts([]);
      setScanAzureAccounts([]);
      setScanGcpAccounts([]);
      setScanRegions([]);
    } catch (err) {
      notifyError("Scan failed: " + err.message);
    } finally {
      setScanning(false);
    }
  };

  // ── Derived data ────────────────────────────────────────────────────────────
  const filteredFindings = sortBySeverity(filterByCloud(allFindings, selectedCloud));

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

  const dashboardMeta = computeDashboardMeta(tableData);

  const errorClouds = Object.entries(cloudStatuses)
    .filter(([, s]) => s.status === "error")
    .map(([cloud]) => cloud);

  const activeClouds = Object.entries(cloudStatuses)
    .filter(([, s]) => s.status !== "skipped");

  const handleHideFinding = (e, findingId) => {
    e.stopPropagation();
    setHiddenFindings((prev) => [...prev, findingId]);
  };

  const allCloudsFailed = activeClouds.length > 0 && activeClouds.every(([, s]) => s.status === "error");
  const someCloudsFailed = errorClouds.length > 0 && !allCloudsFailed;

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
                    <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 block">Azure Subscriptions</label>
                    <AccountDropdown
                      onAccountChange={setScanAzureAccounts}
                      selectedAccounts={scanAzureAccounts}
                      accountOptions={azureAccounts}
                      placeholder={azureAccounts.length > 0 ? "Select Azure subscriptions" : "No Azure subscriptions"}
                      disabled={scanning || loading}
                    />
                  </div>
                  <div className="w-48">
                    <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 block">GCP Projects</label>
                    <AccountDropdown
                      onAccountChange={setScanGcpAccounts}
                      selectedAccounts={scanGcpAccounts}
                      accountOptions={gcpAccounts}
                      placeholder={gcpAccounts.length > 0 ? "Select GCP projects" : "No GCP projects"}
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
                <Spinner />
                <p className="text-lg font-medium text-slate-700 dark:text-slate-300 mt-4">
                  Running {config.label} scan...
                </p>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                  This might take a few minutes depending on the number of resources.
                </p>
              </div>
            )}

            {/* ── View Reports Section ──────────────────────────────────────── */}
            {!scanning && (
              <>
                <div className="mt-6 border-t border-gray-200 dark:border-gray-700" />

            {/* ── Account selectors per cloud ───────────────────────────────── */}
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
              <div className="w-52">
                <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 block">Azure Subscription</label>
                <AccountDropdown
                  onAccountChange={setAzureAccount}
                  selectedAccounts={azureAccount}
                  accountOptions={azureAccounts}
                  placeholder={azureAccounts.length > 0 ? "Select Azure subscription" : "No Azure subscriptions"}
                  mode="single"
                  disabled={loading}
                />
              </div>
              <div className="w-52">
                <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 block">GCP Project</label>
                <AccountDropdown
                  onAccountChange={setGcpAccount}
                  selectedAccounts={gcpAccount}
                  accountOptions={gcpAccounts}
                  placeholder={gcpAccounts.length > 0 ? "Select GCP project" : "No GCP projects"}
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

          {/* ── Error banners ──────────────────────────────────────────────── */}
          {errorClouds.length > 0 && isReportAvailable && (
            <div className="mb-4">
              {errorClouds.map((cloud) => (
                <Alert
                  key={cloud}
                  type="warning"
                  showIcon
                  className="mb-2"
                  message={`Failed to load ${cloud.toUpperCase()} findings: ${cloudStatuses[cloud]?.error || "Unknown error"}`}
                />
              ))}
            </div>
          )}

          {/* ── Cloud filter ───────────────────────────────────────────────── */}
          {isReportAvailable && (
            <CloudFilter
              selectedCloud={selectedCloud}
              onCloudChange={setSelectedCloud}
              cloudStatuses={cloudStatuses}
            />
          )}

          {/* ── Per-cloud timestamps ───────────────────────────────────────── */}
          {isReportAvailable && (
            <div className="mt-4 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-indigo-100 dark:border-slate-700">
              <div className="flex flex-wrap items-center gap-6 text-sm text-slate-600 dark:text-slate-400">
                {Object.entries(cloudStatuses)
                  .filter(([, status]) => status.status !== "skipped")
                  .map(([cloud, status]) => (
                  <div key={cloud} className="flex items-center gap-2">
                    {status.status === "error" ? (
                      <span className="w-2 h-2 rounded-full bg-red-500" />
                    ) : (
                      <Clock className="w-4 h-4 text-indigo-600" />
                    )}
                    <span className="font-medium">{cloud.toUpperCase()}:</span>
                    <span className="text-slate-900 dark:text-white">
                      {status.status === "error"
                        ? "Failed"
                        : status.lastScanned
                          ? new Date(status.lastScanned.replace("Z", "")).toLocaleString("en-GB", { hour12: true })
                          : "No data"}
                    </span>
                  </div>
                ))}
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
                  `Select accounts and click 'View Reports' to see ${config.label} findings across all clouds.`,
                ]}
              />
            </div>
          ) : allCloudsFailed ? (
            <div className="mt-6">
              <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 border border-red-200 dark:border-red-800 p-12 text-center">
                <div className="text-4xl mb-4">⚠️</div>
                <p className="text-lg font-medium text-red-600 dark:text-red-400">
                  Failed to load findings from all clouds.
                </p>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-2">
                  The backend may not have {config.label} scan data yet. Run scans from the cloud-specific pages first, or try the Sample Report.
                </p>
              </div>
            </div>
          ) : filteredFindings.length === 0 ? (
            <div className="mt-6">
              <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 border border-indigo-100 dark:border-slate-700 p-12 text-center">
                <div className="text-4xl mb-4">✅</div>
                <p className="text-lg font-medium text-slate-700 dark:text-slate-300">
                  {someCloudsFailed
                    ? `Could not load findings from ${errorClouds.map((c) => c.toUpperCase()).join(", ")}. Other clouds show no ${config.label} violations.`
                    : `No ${config.label} violations found across selected clouds.`}
                </p>
              </div>
            </div>
          ) : (
            <div className="mt-6">
              {isSampleReport && <GetSampleReportNote />}
              <ScanCharts meta={dashboardMeta} />
              <SummaryCards meta={dashboardMeta} />
              <FindingsTable
                tableData={tableData}
                frameworkKey={frameworkKey}
                showCloudColumn={true}
                onRowClick={(record) => {
                  setSelectedFinding(record);
                  setDrawerVisible(true);
                }}
                hiddenFindings={hiddenFindings}
                onHideFinding={handleHideFinding}
              />
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
