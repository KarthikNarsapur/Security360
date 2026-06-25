// components/Framework/shared/FrameworkDashboard.jsx
//
// Generic dashboard for all AWS-based compliance frameworks (RBI, SEBI, PCI-DSS).
// Pass frameworkKey and it handles scan, report fetch, charts, table, drawer.
//
// Props:
//   frameworkKey        — "rbi" | "sebi" | "pcidss"
//   accountDetails      — from parent (for dropdowns)
//   setUserName / setFullName / setAccountDetails / setEksAccountDetails — from parent

import { useEffect, useState } from "react";
import { Button } from "antd";
import { Play, User, Clock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import Cookies from "js-cookie";

import AccountDropdown from "../../UI/DropDown/AccountDropdown";
import RegionDropdown from "../../UI/DropDown/RegionDropdown";
import Spinner from "../../UI/Spinner";
import {
  LoadingSkeletonCisDashboardS3Fetch,
} from "../../LoadingSkeleton";
import {
  NoDataAvailableMessageComponent,
  GetSampleReportNote,
  fetchUserDetails,
  getPaginationConfig,
} from "../../Utils";
import {
  notifyError,
  notifyInfo,
  notifySuccess,
  notifyRedirectToContact,
} from "../../Notification";

import ScanCharts from "./ScanCharts";
import SummaryCards from "./SummaryCards";
import FindingsTable from "./FindingsTable";
import FindingDrawer from "./FindingDrawer";

import {
  buildTableData,
  computeDashboardMeta,
  FRAMEWORK_CONFIG,
} from "../../../utils/frameworkUtils";

const FrameworkDashboard = ({
  frameworkKey,
  accountDetails,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) => {
  const config = FRAMEWORK_CONFIG[frameworkKey];
  const navigate = useNavigate();

  // ── scan controls ───────────────────────────────────────────────────────────
  const [selectedRegions, setSelectedRegions] = useState([]);
  const [selectedAccounts, setSelectedAccounts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [socket, setSocket] = useState(null);

  // ── report controls ─────────────────────────────────────────────────────────
  const [selectedReportAccount, setSelectedReportAccount] = useState([]);
  const [s3FetchLoading, setS3FetchLoading] = useState(false);
  const [isSampleReport, setIsSampleReport] = useState(false);
  const [isReportAvailable, setIsReportAvailable] = useState(false);
  const [meta, setMeta] = useState(null);

  // ── data ────────────────────────────────────────────────────────────────────
  const [tableData, setTableData] = useState([]);
  const [dashboardMeta, setDashboardMeta] = useState(null);
  const [hiddenFindings, setHiddenFindings] = useState(() => {
    const saved = localStorage.getItem(`hidden_${frameworkKey}_rules`);
    return saved ? JSON.parse(saved) : [];
  });

  // ── drawer ──────────────────────────────────────────────────────────────────
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [drawerVisible, setDrawerVisible] = useState(false);

  const infra_accounts = JSON.parse(
    localStorage.getItem("account_details") || "[]",
  );
  const backendUrl = process.env.REACT_APP_BACKEND_URL;

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
      `hidden_${frameworkKey}_rules`,
      JSON.stringify(hiddenFindings),
    );
  }, [hiddenFindings]);

  useEffect(
    () => () => {
      if (socket) socket.close();
    },
    [socket],
  );

  // ── process scan results into dashboard state ───────────────────────────────
  const processScanResults = (results) => {
    const rows = buildTableData(results);
    setTableData(rows);
    setDashboardMeta(computeDashboardMeta(rows));
  };

  // ── fetch report from S3 ────────────────────────────────────────────────────
  const handleReportAccountChange = async (accounts, isSample = false) => {
    const previousValue = selectedReportAccount;
    setIsSampleReport(isSample);

    if (!isSample) {
      setSelectedReportAccount(accounts);
      if (!accounts || accounts.length === 0) {
        notifyError("Select at least one account to view report");
        return;
      }
    }

    try {
      const parsedAccount = isSample ? {} : JSON.parse(accounts || "{}");
      const payload = {
        account_id: parsedAccount.account_id || "",
        username: localStorage.getItem("username"),
        type: config.reportType,
        is_sample: isSample,
      };

      setS3FetchLoading(true);
      const response = await fetch(`${backendUrl}/api/get-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const apiResponse = await response.json();

      if (apiResponse?.status === "ok") {
        isSample && setSelectedReportAccount(undefined);
        const report = apiResponse.data;
        setMeta({
          account_id: report?.account_id || "",
          timestamp: report?.timestamp || "",
        });
        setIsReportAvailable(true);
        // Results may be flat array or wrapped in {region, data} — handle both
        const results = Array.isArray(report.results)
          ? report.results.flatMap((r) =>
              Array.isArray(r.data)
                ? r.data
                : r.data
                  ? Object.values(r.data)
                  : [r],
            )
          : [];
        processScanResults(results);
      } else {
        notifyError(apiResponse?.error_message || "Failed to get report");
        setSelectedReportAccount(previousValue);
        setIsSampleReport(false);
      }
    } catch (err) {
      console.error("Failed to get report:", err);
      notifyError("Failed to get report");
      setSelectedReportAccount(previousValue);
      setIsSampleReport(false);
    } finally {
      setS3FetchLoading(false);
    }
  };

  // ── scan progress message ────────────────────────────────────────────────────
  const [progressMessage, setProgressMessage] = useState("");

  // ── run scan ─────────────────────────────────────────────────────────────────
  const handleScanClick = async () => {
    const access_token = Cookies.get("access_token");
    const parsedAccounts = (selectedAccounts || [])
      .map((acc) => {
        try {
          return JSON.parse(acc);
        } catch {
          return null;
        }
      })
      .filter(Boolean);

    const payload = {
      accounts: parsedAccounts,
      regions: selectedRegions,
      username: localStorage.getItem("username") || "",
    };

    if (!access_token || !payload.username) {
      notifyInfo("Session expired, login again..");
      navigate("/login");
      return;
    }
    if (!payload.regions?.length) {
      notifyError("Please select at least one region");
      return;
    }
    if (!payload.accounts?.length) {
      notifyError("Please select at least one account");
      return;
    }

    try {
      const wsProtocol = backendUrl.startsWith("https") ? "wss" : "ws";
      const wsHost = backendUrl.replace(/^https?:\/\//, "");
      const wsURL = `${wsProtocol}://${wsHost}/ws/scan/${frameworkKey}`;
      const ws = new WebSocket(wsURL);
      setSocket(ws);

      ws.onopen = () => {
        setLoading(true);
        setProgress(0);
        setProgressMessage("Connecting...");
        ws.send(JSON.stringify(payload));
      };
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.percent !== undefined) setProgress(data.percent);
          if (data.message) setProgressMessage(data.message);
          if (data.status === "complete") {
            ws.close();
            setLoading(false);
            setSocket(null);
            setSelectedRegions([]);
            setSelectedAccounts([]);
            const result = data.result;
            if (result?.notifications) {
              result.notifications.success?.forEach((msg) => notifySuccess(msg));
              result.notifications.error?.forEach((msg) => notifyError(msg));
            } else {
              notifySuccess(`${config.label} scan completed successfully`);
            }
          } else if (data.status === "error") {
            ws.close();
            setLoading(false);
            setSocket(null);
            setProgress(0);
            notifyError(data.message || `Error in ${config.label} scan`);
          }
        } catch (e) { /* ignore parse errors */ }
      };
      ws.onclose = () => setSocket(null);
      ws.onerror = () => {
        notifyError("Failed to connect to progress server.");
        setLoading(false);
        setProgress(0);
      };
    } catch (err) {
      console.error("WebSocket error:", err);
    }
  };

  const stopScan = () => {
    if (socket) {
      socket.close();
      setLoading(false);
      setProgress(0);
    }
  };

  const handleHideFinding = (e, findingId) => {
    e.stopPropagation();
    setHiddenFindings((prev) => [...prev, findingId]);
    notifySuccess("Finding hidden successfully");
  };

  if (loading) return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="p-6 pl-12">
        <div className="max-w-7xl mx-auto">
          <div className="mb-8">
            <h1 className={`text-3xl font-bold bg-gradient-to-r ${config.gradient} bg-clip-text text-transparent`}>
              {config.fullName}
            </h1>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{config.description}</p>
          </div>
          <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 border border-indigo-100 dark:border-slate-700 p-12 text-center">
            <div className="max-w-md mx-auto">
              <div className="relative inline-flex items-center justify-center w-16 h-16 mb-4">
                <div className={`absolute inset-0 rounded-full bg-gradient-to-r ${config.gradient} animate-spin`}>
                  <div className="absolute inset-1 rounded-full bg-white dark:bg-slate-900"></div>
                </div>
                <Play className="w-6 h-6 text-indigo-600 z-10" />
              </div>
              <p className="text-lg font-semibold text-slate-700 dark:text-slate-200 mb-2">
                Running {config.label} Compliance Scan...
              </p>
              <p className="text-sm text-slate-500 dark:text-slate-400 mb-4 font-mono min-h-[20px]">
                {progressMessage || "Initializing..."}
              </p>
              {/* Progress bar */}
              <div className="w-full bg-gray-200 dark:bg-slate-700 rounded-full h-3 overflow-hidden">
                <div
                  className="h-3 rounded-full transition-all duration-500 ease-out"
                  style={{
                    width: `${progress}%`,
                    background: progress >= 96
                      ? "linear-gradient(90deg, #10b981, #34d399)"
                      : `linear-gradient(90deg, #6366f1, #818cf8)`,
                  }}
                />
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-2 font-mono">
                {progress}%
              </p>
              <button
                onClick={stopScan}
                className="mt-4 px-4 py-1.5 text-sm text-red-600 border border-red-300 rounded-lg hover:bg-red-50 transition"
              >
                Cancel Scan
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="p-6 pl-12">
        <div className="max-w-7xl mx-auto">
          {/* ── Header ─────────────────────────────────────────────────────── */}
          <div className="mb-8">
            <div className="mt-2 flex items-center justify-between">
              <div>
                <h1
                  className={`text-3xl font-bold bg-gradient-to-r ${config.gradient} bg-clip-text text-transparent`}
                >
                  {config.fullName}
                </h1>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                  {config.description}
                </p>
              </div>
              {/* Scan controls */}
              <div className="flex items-center gap-4">
                <div className="w-60">
                  <AccountDropdown
                    onAccountChange={setSelectedAccounts}
                    selectedAccounts={selectedAccounts}
                    accountOptions={infra_accounts}
                    disabled={loading || s3FetchLoading}
                  />
                </div>
                <div className="w-60">
                  <RegionDropdown
                    onRegionChange={setSelectedRegions}
                    selectedRegions={selectedRegions}
                    disabled={loading || s3FetchLoading}
                  />
                </div>
                <Button
                  type="primary"
                  icon={<Play className="w-4 h-4" />}
                  onClick={handleScanClick}
                  className={`!bg-gradient-to-r ${config.gradient} border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105`}
                >
                  {config.scanLabel}
                </Button>
              </div>
            </div>

            <div className="mt-6 border-t border-gray-200 dark:border-gray-700" />

            {/* View report for account */}
            <div className="mt-6 flex items-center gap-4">
              <span className="text-sm font-medium text-slate-600 dark:text-slate-400">
                View Report for Account:
              </span>
              <div className="w-60">
                <AccountDropdown
                  onAccountChange={handleReportAccountChange}
                  selectedAccounts={selectedReportAccount}
                  accountOptions={infra_accounts}
                  placeholder="Select account to view report"
                  mode="single"
                  disabled={loading || s3FetchLoading}
                />
              </div>
              <Button
                type="primary"
                icon={
                  s3FetchLoading && !isSampleReport ? null : (
                    <Play className="w-4 h-4" />
                  )
                }
                onClick={() => handleReportAccountChange("", true)}
                disabled={isSampleReport && s3FetchLoading}
                className={`!bg-gradient-to-r ${config.gradient} border-0 font-semibold px-6 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 disabled:opacity-70 disabled:text-white`}
              >
                {s3FetchLoading && isSampleReport ? (
                  <span>
                    Loading Sample Report &nbsp;
                    <Spinner />
                  </span>
                ) : (
                  <span>View Sample Report</span>
                )}
              </Button>
            </div>

            {/* Metadata bar */}
            {meta && (
              <div className="mt-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-indigo-100 dark:border-slate-700">
                <div className="flex items-center gap-6 text-sm text-slate-600 dark:text-slate-400">
                  <div className="flex items-center gap-2">
                    <User className="w-4 h-4 text-indigo-600" />
                    <span className="font-medium">Account ID:</span>
                    <span className="font-mono text-slate-900 dark:text-white">
                      {meta.account_id}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4 text-indigo-600" />
                    <span className="font-medium">Last Scanned:</span>
                    <span className="text-slate-900 dark:text-white">
                      {meta.timestamp
                        ? new Date(
                            meta.timestamp.replace("Z", ""),
                          ).toLocaleString("en-GB", { hour12: true })
                        : "N/A"}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* ── Body ───────────────────────────────────────────────────────── */}
          {s3FetchLoading ? (
            <LoadingSkeletonCisDashboardS3Fetch />
          ) : !isReportAvailable ? (
            <NoDataAvailableMessageComponent
              messages={[
                "No data available",
                `Run a ${config.label} scan to retrieve security findings for your AWS account.`,
              ]}
            />
          ) : (
            <div>
              {isSampleReport && <GetSampleReportNote />}

              <ScanCharts meta={dashboardMeta} />
              <SummaryCards meta={dashboardMeta} />

              <FindingsTable
                tableData={tableData}
                frameworkKey={frameworkKey}
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

export default FrameworkDashboard;
