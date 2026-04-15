import { useEffect, useState } from "react";
import { Button } from "antd";
import Cookies from "js-cookie";
import OverviewCard from "./UI/OverviewCard";
import TopThreatsCard from "./UI/TopThreatsCard";
import PieChartSeverity from "./UI/PieChartSeverity";
import BarChartFindings from "./UI/BarChartFindings";
import {
  notifyError,
  notifyInfo,
  notifyRedirectToContact,
  notifySuccess,
} from "./Notification";
import { LoadingSkeletonSummaryPage } from "./LoadingSkeleton";
import Spinner from "./UI/Spinner";
import { Shield, Play, User, Clock } from "lucide-react";
import RegionDropdown from "./UI/DropDown/RegionDropdown";
import { useNavigate } from "react-router-dom";
import {
  fetchUserDetails,
  GetSampleReportNote,
  NoDataAvailableMessageComponent,
} from "./Utils";
import AccountDropdown from "./UI/DropDown/AccountDropdown";

const SummaryComponent = ({
  setSelectedMenu,
  results,
  setResults,
  meta,
  setMeta,
  isReportAvailable,
  setIsReportAvailable,
  accountDetails,
  prevReportAvailable,
  setPrevReportAvailable,
  securityServicesScanResults,
  setSecurityServicesScanResults,
  globalServicesScanResults,
  setGlobalServicesScanResults,
  modal,
  darkMode,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
  isSummaryScanSampleReport,
  setIsSummaryScanSampleReport,
  isSampleReport,
  setIsSampleReport
}) => {
  const [loading, setLoading] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [collapsed, setCollapsed] = useState(false);
  const [isfetched, setIsFetched] = useState(false);
  const [isBarExpanded, setIsBarExpanded] = useState(false);
  const [selectedRegions, setSelectedRegions] = useState([]);
  const [selectedAccounts, setSelectedAccounts] = useState([]);
  const [selectedReportAccount, setSelectedReportAccount] = useState([]); //for report account
  const navigate = useNavigate();

  useEffect(() => {
    const getUserData = async () => {
      const result = await fetchUserDetails({ navigate });
      if (result.status == "ok") {
        setUserName(result.userName);
        setFullName(result.fullName);
        setAccountDetails(result.accountDetails);
        setEksAccountDetails(result.eksAccountDetails);
      }
    };
    getUserData();
  }, []);
  const infra_accounts =
    JSON.parse(localStorage.getItem("account_details") || "[]") || [];
  const username = localStorage.getItem("username") || "";

  const runScan = async () => {
    const backend_url = process.env.REACT_APP_BACKEND_URL;

    const access_token = Cookies.get("access_token");
    // console.log("selectedAccounts before parsing:", selectedAccounts);
    const parsedAccounts = (selectedAccounts || [])
      .map((acc) => {
        try {
          return JSON.parse(acc);
        } catch (e) {
          console.error("Invalid account JSON:", acc);
          return null;
        }
      })
      .filter(Boolean);

    const payload = {
      // access_token: access_token,
      accounts: parsedAccounts || [],
      regions: selectedRegions || [],
      username: localStorage.getItem("username") || "",
    };

    if (!access_token || !payload.username) {
      notifyInfo("Session expired, login again..");
      navigate("/login");
    }
    if (!payload.regions || payload.regions.length === 0) {
      notifyError("Please select at least one region");
      return;
    }
    if (!payload.accounts || payload.accounts.length === 0) {
      notifyError("Please select at least one account");
      return;
    }

    try {
      setLoading(true);
      const response = await fetch(`${backend_url}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json();
      if (result?.status === "ok") {
        setSelectedRegions([]);
        setSelectedAccounts([]);
        if (Array.isArray(result.notifications?.success)) {
          // console.log(
          //   "result.notifications.success: ",
          //   result.notifications.success
          // );
          result.notifications.success.forEach((msg) => {
            notifySuccess(msg);
          });
        }

        // Loop through error messages
        if (Array.isArray(result.notifications?.error)) {
          // console.log(
          //   "result.notifications.error: ",
          //   result.notifications.error
          // );
          result.notifications.error.forEach((msg) => {
            notifyError(msg);
          });
        }
      } else {
        notifyError(result?.error_message || "scan failed");
        if (result?.fail_type || "" === "contact_us") {
          notifyRedirectToContact(navigate, 5);
        }
      }
    } catch (err) {
      console.log("Scan failed due to: ", err);
    } finally {
      setLoading(false);
    }
  };

  // to handle report account change
  const handleReportAccountChange = async (accounts, isSample = false) => {
    const previousValue = selectedReportAccount;
    setIsSampleReport(isSample);

    if (!isSample) {
      setSelectedReportAccount(accounts);
      if (!accounts || accounts.length == 0) {
        notifyError("Select at least one account to view report");
        return;
      }
    }

    const backend_url = process.env.REACT_APP_BACKEND_URL;
    // console.log("accounts: ", accounts);

    try {
      const parsedAccount = isSample ? {} : JSON.parse(accounts || "{}");
      const payload = {
        account_id: parsedAccount.account_id || "",
        username: localStorage.getItem("username"),
        type: "summary",
        is_sample: isSample,
      };

      setLoading(true);
      setIsSummaryScanSampleReport(isSample);

      // Call backend API to get report for selected account
      const response = await fetch(`${backend_url}/api/get-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const apiResponse = await response.json();

      if (apiResponse?.status === "ok") {
        isSample && setSelectedReportAccount();
        const report = apiResponse.data;

        if (!report || report.length === 0) {
          setMeta({});
          setIsReportAvailable(false);
          setResults([]);
          return;
        }

        setMeta({
          account_id: report.account_id,
          account_name: report.account_name,
          timestamp: report.timestamp,
          regions: report.regions,
          scanned_meta_data: report.scanned_meta_data,
        });
        setSecurityServicesScanResults(
          report.security_services_scanned_data || {}
        );
        setGlobalServicesScanResults(report.global_services_scan_results || {});
        setIsReportAvailable(true);

        const formatted = [
          // regional results
          ...(report.results || [])
            .flatMap((regionData) => {
              const region = regionData.region;
              const findings = Object.entries(regionData.data).map(
                ([key, value]) => ({
                  ...value,
                  type: key,
                  region,
                  account_id: report.account_id || "",
                })
              );
              return findings;
            })
            .filter((item) => item.total_scanned !== 0),

          // global services results
          ...Object.entries(report.global_services_scan_results || {}).map(
            ([key, value]) => ({
              ...value,
              type: key,
              region: "global",
              account_id: report.account_id || "",
            })
          ),
        ];

        setResults(formatted);
      } else {
        notifyError(apiResponse?.error_message || "Failed to get report");
        setSelectedReportAccount(previousValue);
        setIsSummaryScanSampleReport(false);
      }
    } catch (err) {
      console.error("Failed to get report:", err);
      notifyError("Failed to get report");
      setSelectedReportAccount(previousValue);
      setIsSummaryScanSampleReport(false);
    } finally {
      setLoading(false);
    }
  };

  const handleRegionChange = (regions) => {
    setSelectedRegions(regions);
  };

  const handleAccountChange = (accounts) => {
    setSelectedAccounts(accounts);
  };

  return (
    <div className="p-6 pl-12">
      <div className="mb-8">
        <div className="mt-2 flex items-center justify-between">
          <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent flex items-center gap-3">
            {/* <Shield className="w-8 h-8 text-indigo-600" /> */}
            Cloud Security Dashboard
          </h1>

          <div className="flex items-center gap-4">
            <div className="w-60">
              <AccountDropdown
                onAccountChange={handleAccountChange}
                selectedAccounts={selectedAccounts}
                accountOptions={infra_accounts}
                disabled={loading}
              />
            </div>
            <div className="w-60">
              <RegionDropdown
                onRegionChange={handleRegionChange}
                selectedRegions={selectedRegions}
                disabled={loading}
              />
            </div>
            <Button
              type="primary"
              icon={loading ? null : <Play className="w-4 h-4" />}
              onClick={() => runScan()}
              className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
            >
              {loading ? (
                <span>
                  Running Scan&nbsp;&nbsp;
                  <Spinner />
                </span>
              ) : (
                <span>Run Scan</span>
              )}
            </Button>
          </div>
        </div>

        {/* Horizontal line after dropdowns and run scan button */}
        <div className="mt-6 border-t border-gray-200 dark:border-gray-700"></div>

        {/* dropdown for selecting account to view report */}
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
              disabled={loading}
            />
          </div>

          {/* Sample data button */}
          <Button
            type="primary"
            icon={loading ? null : <Play className="w-4 h-4" />}
            onClick={() => handleReportAccountChange("", true)} // "" for accounts
            disabled={isSummaryScanSampleReport && loading}
            className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 font-semibold px-6 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 disabled:opacity-70 disabled:text-white"
          >
            {loading && isSummaryScanSampleReport ? (
              <span>
                Loading Sample Report&nbsp;&nbsp;
                <Spinner />
              </span>
            ) : (
              <span>View Sample Report</span>
            )}
          </Button>
        </div>

        {/* Metadata */}
        {(meta?.timestamp || meta?.account_id) && (
          <div className="mt-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-indigo-100 dark:border-slate-700">
            <div className="flex items-center gap-6 text-sm text-slate-600 dark:text-slate-400">
              <div className="flex items-center gap-2">
                <User className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                <span className="font-medium">Account ID:</span>
                <span className="font-mono text-slate-900 dark:text-white">
                  {loading ? "Loading..." : meta?.account_id || "Not available"}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                <span className="font-medium">Last Scanned:</span>
                <span className="text-slate-900 dark:text-white">
                  {loading
                    ? "Loading..."
                    : new Date(meta.timestamp.replace("Z", "")).toLocaleString(
                      "en-GB",
                      {
                        hour12: true,
                      }
                    ) || "Not available"}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
      {loading && <LoadingSkeletonSummaryPage />}
      {!loading && (
        <div>
          {results.length ? (
            <div>
              {isSummaryScanSampleReport && <GetSampleReportNote />}
              <div className="mb-6">
                <OverviewCard
                  findings={results}
                  setSelectedMenu={setSelectedMenu}
                />
              </div>

              {/* <div className="grid grid-cols-1 gap-0 mt-6">
            <TopThreatsCard findings={findings} />
          </div> */}

              <div className="mt-6">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                  <div className="w-full">
                    <TopThreatsCard
                      findings={results}
                      modal={modal}
                      darkMode={darkMode}
                    />
                  </div>
                  <div className="w-full">
                    <PieChartSeverity findings={results} />
                  </div>
                </div>
                <div className="w-full">
                  <BarChartFindings
                    findings={results}
                    isBarExpanded={isBarExpanded}
                    setIsBarExpanded={setIsBarExpanded}
                  />
                </div>
              </div>
            </div>
          ) : (
            <NoDataAvailableMessageComponent
              messages={[
                "No data available.",
                "Select accounts and regions, then click 'Run Scan' to scan your AWS accounts.",
                "If no accounts appear in the dropdown, please add them from the Home page of Infra Scan.",
              ]}
            />
          )}
        </div>
      )}
    </div>
  );
};

export default SummaryComponent;
