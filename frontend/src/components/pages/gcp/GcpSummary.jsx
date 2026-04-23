import { useEffect, useState } from "react";
import { Button } from "antd";
import Cookies from "js-cookie";
import OverviewCard from "../../UI/OverviewCard";
import TopThreatsCard from "../../UI/TopThreatsCard";
import PieChartSeverity from "../../UI/PieChartSeverity";
import BarChartFindings from "../../UI/BarChartFindings";
import {
  notifyError,
  notifyInfo,
  notifyRedirectToContact,
  notifySuccess,
} from "../../Notification";
import { LoadingSkeletonSummaryPage } from "../../LoadingSkeleton";
import Spinner from "../../UI/Spinner";
import { Play, User, Clock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import {
  fetchUserDetails,
  GetSampleReportNote,
  NoDataAvailableMessageComponent,
} from "../../Utils";
import AccountDropdown from "../../UI/DropDown/AccountDropdown";

const GcpSummary = ({
  results,
  setResults,
  meta,
  setMeta,
  accountDetails,
  modal,
  darkMode,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) => {
  const [loading, setLoading] = useState(false);
  const [isBarExpanded, setIsBarExpanded] = useState(false);
  const [selectedProjects, setSelectedProjects] = useState([]);
  const [selectedReportAccount, setSelectedReportAccount] = useState([]);
  const [isSummaryScanSampleReport, setIsSummaryScanSampleReport] =
    useState(false);
  const [isSampleReport, setIsSampleReport] = useState(false);
  const navigate = useNavigate();

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

  const infra_accounts =
    JSON.parse(localStorage.getItem("gcp_account_details") || "[]") || [];

  const runScan = async () => {
    const backend_url = process.env.REACT_APP_BACKEND_URL;
    const access_token = Cookies.get("access_token");
    const parsedProjects = (selectedProjects || [])
      .map((proj) => {
        try { return JSON.parse(proj); }
        catch (e) { return null; }
      })
      .filter(Boolean);

    const payload = {
      accounts: parsedProjects || [],
      username: localStorage.getItem("username") || "",
      cloud: "gcp",
    };

    if (!access_token || !payload.username) {
      notifyInfo("Session expired, login again..");
      navigate("/login");
      return;
    }
    if (!payload.accounts || payload.accounts.length === 0) {
      notifyError("Please select at least one project");
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
        setSelectedProjects([]);
        if (Array.isArray(result.notifications?.success))
          result.notifications.success.forEach((msg) => notifySuccess(msg));
        if (Array.isArray(result.notifications?.error))
          result.notifications.error.forEach((msg) => notifyError(msg));
      } else {
        notifyError(result?.error_message || "Scan failed");
        if (result?.fail_type === "contact_us") notifyRedirectToContact(navigate, 5);
      }
    } catch (err) {
      console.error("Scan failed:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleReportAccountChange = async (accounts, isSample = false) => {
    const previousValue = selectedReportAccount;
    setIsSampleReport(isSample);
    if (!isSample) {
      setSelectedReportAccount(accounts);
      if (!accounts || accounts.length === 0) {
        notifyError("Select at least one project to view report");
        return;
      }
    }
    const backend_url = process.env.REACT_APP_BACKEND_URL;
    try {
      const parsedAccount = isSample ? {} : JSON.parse(accounts || "{}");
      const payload = {
        account_id: parsedAccount.account_id || "",
        username: localStorage.getItem("username"),
        type: "summary",
        is_sample: isSample,
        cloud: "gcp",
      };
      setLoading(true);
      setIsSummaryScanSampleReport(isSample);
      const response = await fetch(`${backend_url}/api/get-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const apiResponse = await response.json();
      if (apiResponse?.status === "ok") {
        isSample && setSelectedReportAccount();
        const report = apiResponse.data;
        if (!report || report.length === 0) { setMeta({}); setResults([]); return; }
        setMeta({
          account_id: report.account_id || report.project_id,
          account_name: report.account_name || report.project_name,
          timestamp: report.timestamp,
          regions: report.regions,
          scanned_meta_data: report.scanned_meta_data,
        });
        const formatted = [
          ...(report.results || [])
            .flatMap((regionData) => {
              const region = regionData.region;
              return Object.entries(regionData.data).map(([key, value]) => ({
                ...value, type: key, region,
                account_id: report.account_id || report.project_id || "",
              }));
            })
            .filter((item) => item.total_scanned !== 0),
          ...Object.entries(report.global_services_scan_results || {}).map(
            ([key, value]) => ({
              ...value, type: key, region: "global",
              account_id: report.account_id || report.project_id || "",
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

  const handleProjectChange = (projects) => {
    setSelectedProjects(projects);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 p-6 pl-12">
      <div className="mb-8">
        <div className="mt-2 flex items-center justify-between">
          <h2 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent flex items-center gap-3">
            GCP Security Dashboard
          </h2>
          <div className="flex items-center gap-4">
            <div className="w-60">
              <AccountDropdown
                onAccountChange={handleProjectChange}
                selectedAccounts={selectedProjects}
                accountOptions={infra_accounts}
                placeholder="Select GCP projects"
                disabled={loading}
              />
            </div>
            <Button
              type="primary"
              icon={loading ? null : <Play className="w-4 h-4" />}
              onClick={() => runScan()}
              className="!bg-gradient-to-r from-blue-600 to-indigo-700 hover:from-blue-700 hover:to-indigo-800 border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
            >
              {loading ? (<span>Running Scan&nbsp;&nbsp;<Spinner /></span>) : (<span>Run Scan</span>)}
            </Button>
          </div>
        </div>
        <div className="mt-6 border-t border-gray-200 dark:border-gray-700"></div>
        <div className="mt-6 flex items-center gap-4">
          <span className="text-sm font-medium text-slate-600 dark:text-slate-400">View Report for Project:</span>
          <div className="w-60">
            <AccountDropdown
              onAccountChange={handleReportAccountChange}
              selectedAccounts={selectedReportAccount}
              accountOptions={infra_accounts}
              placeholder="Select project to view report"
              mode="single"
              disabled={loading}
            />
          </div>
          <Button
            type="primary"
            icon={loading ? null : <Play className="w-4 h-4" />}
            onClick={() => handleReportAccountChange("", true)}
            disabled={isSummaryScanSampleReport && loading}
            className="!bg-gradient-to-r from-blue-600 to-indigo-700 hover:from-blue-700 hover:to-indigo-800 border-0 font-semibold px-6 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 disabled:opacity-70 disabled:text-white"
          >
            {loading && isSummaryScanSampleReport ? (<span>Loading Sample Report&nbsp;&nbsp;<Spinner /></span>) : (<span>View Sample Report</span>)}
          </Button>
        </div>
        {(meta?.timestamp || meta?.account_id) && (
          <div className="mt-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-indigo-100 dark:border-slate-700">
            <div className="flex items-center gap-6 text-sm text-slate-600 dark:text-slate-400">
              <div className="flex items-center gap-2">
                <User className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                <span className="font-medium">Project ID:</span>
                <span className="font-mono text-slate-900 dark:text-white">
                  {loading ? "Loading..." : meta?.account_id || "Not available"}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                <span className="font-medium">Last Scanned:</span>
                <span className="text-slate-900 dark:text-white">
                  {loading ? "Loading..." : new Date(meta.timestamp.replace("Z", "")).toLocaleString("en-GB", { hour12: true }) || "Not available"}
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
              <div className="mb-6"><OverviewCard findings={results} cloud="gcp" /></div>
              <div className="mt-6">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                  <div className="w-full"><TopThreatsCard findings={results} modal={modal} darkMode={darkMode} /></div>
                  <div className="w-full"><PieChartSeverity findings={results} /></div>
                </div>
                <div className="w-full"><BarChartFindings findings={results} isBarExpanded={isBarExpanded} setIsBarExpanded={setIsBarExpanded} /></div>
              </div>
            </div>
          ) : (
            <NoDataAvailableMessageComponent
              messages={["No data available.", "Select projects, then click 'Run Scan' to scan your GCP projects.", "If no projects appear in the dropdown, please add them from the Home page."]}
            />
          )}
        </div>
      )}
    </div>
  );
};

export default GcpSummary;
