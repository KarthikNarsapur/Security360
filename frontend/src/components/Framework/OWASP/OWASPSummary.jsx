// components/Framework/OWASP/OWASPSummary.jsx
//
// OWASP Top 10 website scanner dashboard.
// Different from AWS frameworks — takes URL list instead of AWS accounts/regions.

import { useEffect, useState } from "react";
import { Button, Input, Tag } from "antd";
import { Play, Plus, X, Globe, Clock, CloudCog } from "lucide-react";
import { useNavigate } from "react-router-dom";
import Cookies from "js-cookie";

import Spinner from "../../UI/Spinner";
import {
  LoadingSkeletonCisDashboard,
  LoadingSkeletonCisDashboardS3Fetch,
} from "../../LoadingSkeleton";
import {
  NoDataAvailableMessageComponent,
  GetSampleReportNote,
  fetchUserDetails,
} from "../../Utils";
import { notifyError, notifyInfo, notifySuccess } from "../../Notification";

import ScanCharts from "../shared/ScanCharts";
import SummaryCards from "../shared/SummaryCards";
import FindingsTable from "../shared/FindingsTable";
import FindingDrawer from "../shared/FindingDrawer";

import {
  buildTableDataFromWebsite,
  computeDashboardMeta,
  FRAMEWORK_CONFIG,
} from "../../../utils/frameworkUtils";

const OWASPSummary = ({
  accountDetails,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) => {
  const config = FRAMEWORK_CONFIG.owasp;
  const navigate = useNavigate();
  const backendUrl = process.env.REACT_APP_BACKEND_URL;
  const [totalSitesScanned, setTotalSiteScanned] = useState(0);

  // ── URL input state ─────────────────────────────────────────────────────────
  const [urlInput, setUrlInput] = useState("");
  const [urlList, setUrlList] = useState([]);

  // ── scan state ──────────────────────────────────────────────────────────────
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [socket, setSocket] = useState(null);
  const [scanTime, setScanTime] = useState(null);

  // ── report state ────────────────────────────────────────────────────────────
  const [s3FetchLoading, setS3FetchLoading] = useState(false);
  const [isSampleReport, setIsSampleReport] = useState(false);
  const [isReportAvailable, setIsReportAvailable] = useState(false);

  // ── data ────────────────────────────────────────────────────────────────────
  const [tableData, setTableData] = useState([]);
  const [dashboardMeta, setDashboardMeta] = useState(null);
  const [hiddenFindings, setHiddenFindings] = useState(() => {
    const saved = localStorage.getItem("hidden_owasp_rules");
    return saved ? JSON.parse(saved) : [];
  });

  // ── drawer ──────────────────────────────────────────────────────────────────
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [drawerVisible, setDrawerVisible] = useState(false);

  useEffect(() => {
    const getUserData = async () => {
      const result = await fetchUserDetails({ navigate });
      console.log("OWASP dashboard user data: ", result);
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
    localStorage.setItem("hidden_owasp_rules", JSON.stringify(hiddenFindings));
  }, [hiddenFindings]);

  const processResults = (allResults) => {
    const rows = buildTableDataFromWebsite(allResults);
    setTableData(rows);
    setDashboardMeta(computeDashboardMeta(rows));
  };

  // ── Add / remove URLs ───────────────────────────────────────────────────────
  const isValidUrl = (url) => {
    const pattern = /^(https?:\/\/|www\.)[^\s$.?#].[^\s]*$/i;
    return pattern.test(url);
  };
  const addUrl = () => {
    const trimmed = urlInput.trim();
    if (!trimmed) return;
    if (!isValidUrl(trimmed)) {
      notifyError("Please enter a valid URL");
      return;
    }
    if (urlList.includes(trimmed)) {
      notifyError("URL already added");
      return;
    }
    setUrlList((prev) => [...prev, trimmed]);
    setUrlInput("");
  };

  const removeUrl = (url) =>
    setUrlList((prev) => prev.filter((u) => u !== url));

  const handleUrlKeyDown = (e) => {
    if (e.key === "Enter") addUrl();
  };

  // ── Run scan ─────────────────────────────────────────────────────────────────
  const handleScanClick = async () => {
    const access_token = Cookies.get("access_token");
    if (!access_token) {
      notifyInfo("Session expired, login again..");
      navigate("/login");
      return;
    }
    if (urlList.length === 0) {
      notifyError("Please add at least one website URL");
      return;
    }

    setLoading(true);

    const payload = {
      username: localStorage.getItem("username") || "parth",
      websites: urlList,
      framework: "owasp",
    };

    try {
      const response = await fetch(`${backendUrl}${config.apiEndpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json();

      if (result?.status === "ok") {
        setScanTime(new Date().toISOString());
        setIsReportAvailable(true);
        setTotalSiteScanned(urlList.length);
        setUrlList([]);

        // Inline results returned directly from API (OWASP doesn't use S3 report flow)
        if (result.results) processResults(result.results);

        result.notifications?.success?.forEach((msg) => notifySuccess(msg));
        result.notifications?.error?.forEach((msg) => notifyError(msg));
      } else {
        setLoading(false);
        setProgress(0);
        notifyError(result?.error_message || "Error in OWASP scan");
      }
    } catch (err) {
      notifyError("Failed to start scan: " + err.message);
      setLoading(false);
      setProgress(0);
    } finally {
      setLoading(false);
    }
  };

  // ── Sample report ───────────────────────────────────────────────────────────
  const handleSampleReport = async () => {
    setIsSampleReport(true);
    setS3FetchLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/get-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          account_id: "",
          username: localStorage.getItem("username"),
          type: "owasp",
          is_sample: true,
        }),
      });
      const apiResponse = await response.json();
      if (apiResponse?.status === "ok") {
        const report = apiResponse.data;
        const results = report.results || [];
        setScanTime(report.timestamp || new Date().toISOString());
        setIsReportAvailable(true);
        processResults(results);
      } else {
        notifyError(
          apiResponse?.error_message || "Failed to load sample report",
        );
        setIsSampleReport(false);
      }
    } catch (err) {
      notifyError("Failed to load sample report");
      setIsSampleReport(false);
    } finally {
      setS3FetchLoading(false);
    }
  };

  const handleHideFinding = (e, findingId) => {
    e.stopPropagation();
    setHiddenFindings((prev) => [...prev, findingId]);
    notifySuccess("Finding hidden");
  };

  //   if (loading) return <LoadingSkeletonCisDashboard progress={progress} />;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="p-6 pl-12">
        <div className="max-w-7xl mx-auto">
          {/* ── Header ─────────────────────────────────────────────────────── */}
          <div className="mb-8">
            <div className="mt-2 flex items-center justify-between gap-4 flex-wrap">
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-emerald-600 to-teal-600 bg-clip-text text-transparent">
                  {config.fullName}
                </h1>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                  {config.description}
                </p>
              </div>
              <Button
                type="primary"
                icon={loading ? <Spinner /> : <Play className="w-4 h-4" />}
                onClick={handleScanClick}
                disabled={loading}
                className="!bg-gradient-to-r from-emerald-600 to-teal-600 border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
              >
                {loading ? "Scanning..." : "Run Website Scan"}
              </Button>
            </div>

            <div className="mt-6 border-t border-gray-200 dark:border-gray-700" />

            {/* URL input */}
            <div className="mt-6 space-y-3">
              <span className="text-sm font-medium text-slate-600 dark:text-slate-400">
                Enter website URLs to scan:
              </span>
              <div className="flex items-center gap-2">
                <Input
                  prefix={<Globe className="w-4 h-4 text-gray-400" />}
                  placeholder="https://example.com"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  onKeyDown={handleUrlKeyDown}
                  className="w-96 rounded-xl"
                />
                <Button
                  icon={<Plus className="w-4 h-4" />}
                  onClick={addUrl}
                  disabled={loading}
                  className="!bg-gradient-to-r from-emerald-600 to-teal-600 text-white border-0 rounded-xl hover:scale-105 transition-all"
                >
                  Add URL
                </Button>
                <Button
                  onClick={handleSampleReport}
                  disabled={loading || s3FetchLoading}
                  className="!bg-gradient-to-r from-emerald-600 to-teal-600 text-white border-0 rounded-xl hover:scale-105 transition-all disabled:opacity-70"
                >
                  {s3FetchLoading && isSampleReport ? (
                    <span>
                      Loading Sample &nbsp;
                      <Spinner />
                    </span>
                  ) : (
                    "View Sample Report"
                  )}
                </Button>
              </div>

              {/* URL tags */}
              {urlList.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {urlList.map((url) => (
                    <Tag
                      key={url}
                      closable
                      onClose={() => removeUrl(url)}
                      className="bg-emerald-50 text-emerald-700 border-emerald-200 rounded-full px-3 py-1"
                      closeIcon={<X className="w-3 h-3" />}
                    >
                      <Globe className="w-3 h-3 inline mr-1" />
                      {url}
                    </Tag>
                  ))}
                </div>
              )}
            </div>

            {/* Scan metadata */}
            {scanTime && (
              <div className="mt-4 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-indigo-100 dark:border-slate-700">
                <div className="flex items-center gap-6 text-sm text-slate-600 dark:text-slate-400">
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4 text-emerald-600" />
                    <span className="font-medium">Last Scanned:</span>
                    <span className="text-slate-900 dark:text-white">
                      {new Date(scanTime).toLocaleString("en-GB", {
                        hour12: true,
                      })}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-emerald-600" />
                    <span className="font-medium">Sites Scanned:</span>
                    <span className="text-slate-900 dark:text-white">
                      {totalSitesScanned || "-"}
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
                "Add website URLs above and run a scan to check OWASP Top 10 compliance.",
              ]}
            />
          ) : (
            <div>
              {isSampleReport && <GetSampleReportNote />}

              <ScanCharts meta={dashboardMeta} />
              <SummaryCards meta={dashboardMeta} />

              <FindingsTable
                tableData={tableData}
                frameworkKey="owasp"
                onRowClick={(record) => {
                  setSelectedFinding(record);
                  setDrawerVisible(true);
                }}
                regionLabel="URL"
                hiddenFindings={hiddenFindings}
                onHideFinding={handleHideFinding}
              />

              <FindingDrawer
                open={drawerVisible}
                onClose={() => setDrawerVisible(false)}
                finding={selectedFinding}
                regionLabel="URL"
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default OWASPSummary;
