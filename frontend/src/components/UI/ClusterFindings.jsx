import { useState, useEffect } from "react";
import { Play } from "lucide-react";
import { Button, Select } from "antd";
import { notifyError, notifyInfo, notifySuccess } from "../Notification";
import Cookies from "js-cookie";
import { useNavigate } from "react-router-dom";
import { fetchUserDetails, GetSampleReportNote } from "../Utils";

const { Option } = Select;

const CustomDropdown = ({
  label,
  value,
  onChange,
  options,
  placeholder,
  disabled = false,
  loading = false,
}) => (
  <div className="flex flex-col flex-1 min-w-[200px]">
    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
      {label}
    </label>
    <Select
      value={value || undefined}
      onChange={onChange}
      placeholder={placeholder}
      className="w-full"
      size="large"
      disabled={disabled}
      loading={loading}
      showSearch
      allowClear
      filterOption={(input, option) =>
        (option?.children ?? "").toLowerCase().includes(input.toLowerCase())
      }
      style={{ minWidth: 200 }}
    >
      {options.map((option) => (
        <Option key={option.value} value={option.value}>
          {option.label}
        </Option>
      ))}
    </Select>
  </div>
);

const FileDisplay = ({ fileUrl, fileType, fileName }) => {
  if (!fileUrl) {
    return <div>No file selected</div>;
  }
  console.log(fileUrl, fileType, fileName);
  if (fileType === "pdf") {
    return (
      <div className="w-full">
        {/* Title and File Name with vertical line */}
        <div className="mb-4 flex items-center gap-4">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
            Security Report
          </h3>
          <div className="w-px h-6 bg-gray-300 dark:bg-gray-600" />
          {fileName && (
            <h3 className="text-lg font-semibold text-indigo-600 dark:text-indigo-400">
              {fileName}
            </h3>
          )}
        </div>
        <div className="w-full border rounded-lg bg-white">
          <iframe
            src={fileUrl}
            title="PDF Report"
            className="w-full h-[600px] border-0"
            style={{ overflow: "hidden" }}
          />
        </div>
      </div>
    );
  }
  return null;
};

const ClusterFindings = ({
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) => {
  const [accountId, setAccountId] = useState("");
  const [eksCluster, setEksCluster] = useState("");
  const [tool, setTool] = useState("");
  const [dateFolder, setDateFolder] = useState("");
  const [reportType, setReportType] = useState("");

  const [accounts, setAccounts] = useState([]);
  const [eksClusters, setEksClusters] = useState([]);
  const [dateFolders, setDateFolders] = useState([]);
  const [reports, setReports] = useState([]);

  const [loadingAccounts, setLoadingAccounts] = useState(false);
  const [loadingClusters, setLoadingClusters] = useState(false);
  const [loadingDateFolders, setLoadingDateFolders] = useState(false);
  const [loadingReports, setLoadingReports] = useState(false);
  const [loadingReport, setLoadingReport] = useState(false);

  const [fileUrl, setFileUrl] = useState("");
  const [fileType, setFileType] = useState("");

  const [sampleTool, setSampleTool] = useState("");
  const [lastValidSampleTool, setLastValidSampleTool] = useState("");
  const [loadingSampleReport, setLoadingSampleReport] = useState(false);
  const [isShowingSampleReport, setIsShowingSampleReport] = useState(false);

  const [folderStructure, setFolderStructure] = useState({});
  const [displayFileName, setDisplayFileName] = useState("");

  const username = localStorage.getItem("username");
  const backend_url = process.env.REACT_APP_BACKEND_URL;
  const navigate = useNavigate();

  const toolOptions = [
    { value: "kube-hunter", label: "Kubehunter" },
    { value: "kube-scape", label: "Kubescape" },
  ];

  const sampleToolOptions = [
    { value: "mitre", label: "MITRE" },
    { value: "nsa", label: "NSA" },
    { value: "kubehunter", label: "Kubehunter" },
  ];

  const getSampleToolLabel = (value) => {
    const option = sampleToolOptions.find((opt) => opt.value === value);
    return option ? option.label : value;
  };

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
    fetchAccountsAndStructure();
  }, []);

  const fetchAccountsAndStructure = async () => {
    setLoadingAccounts(true);
    if (!username) {
      notifyError("Please login first");
      navigate("/login");
      return;
    }
    try {
      const response = await fetch(`${backend_url}/api/get-eks-accounts`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });
      const data = await response.json();
      if (data.status === "ok" && data.response) {
        setFolderStructure(data.response);
        const accountOptions = Object.keys(data.response).map((acc) => ({
          value: acc,
          label: acc,
        }));
        setAccounts(accountOptions);
        if (accountOptions.length > 0) {
          setAccountId(accountOptions[0].value);
        }
      } else {
        notifyError("Failed to load accounts");
      }
    } catch (error) {
      console.error("Error fetching accounts:", error);
      notifyError("Error loading accounts");
    } finally {
      setLoadingAccounts(false);
    }
  };

  useEffect(() => {
    if (accountId && folderStructure[accountId]) {
      setLoadingClusters(true);
      const clusters = Object.keys(folderStructure[accountId]).map((c) => ({
        value: c,
        label: c,
      }));
      setEksClusters(clusters);
      setLoadingClusters(false);
    } else {
      setEksClusters([]);
    }
    resetAfterAccountChange();
  }, [accountId]);

  useEffect(() => {
    if (accountId && eksCluster && tool) {
      setLoadingDateFolders(true);
      const toolDates = folderStructure[accountId]?.[eksCluster]?.[tool] || {};
      const dateOptions = Object.keys(toolDates).map((d) => ({
        value: d,
        label: d,
      }));
      setDateFolders(dateOptions);
      setLoadingDateFolders(false);
    } else {
      setDateFolders([]);
    }
    resetAfterClusterOrToolChange();
  }, [tool]);

  useEffect(() => {
    if (accountId && eksCluster && tool && dateFolder) {
      setLoadingReports(true);
      const reportsArr =
        folderStructure[accountId]?.[eksCluster]?.[tool]?.[dateFolder] || [];
      const reportOptions = reportsArr.map((name) => ({
        value: name,
        label: name.replace(".pdf", ""),
      }));
      setReports(reportOptions);
      setLoadingReports(false);
    } else {
      setReports([]);
    }
    resetAfterDateChange();
  }, [dateFolder]);

  const resetAfterAccountChange = () => {
    setEksCluster("");
    setTool("");
    setDateFolder("");
    setReportType("");
    setDateFolders([]);
    setReports([]);
    // setFileUrl("");
    // setFileType("");
  };

  const resetAfterClusterOrToolChange = () => {
    setDateFolder("");
    setReportType("");
    setReports([]);
    // setFileUrl("");
    // setFileType("");
  };

  const resetAfterDateChange = () => {
    setReportType("");
    // setFileUrl("");
    // setFileType("");
  };

  const handleAccountChange = (value) => {
    setAccountId(value);
  };

  const handleClusterChange = (value) => {
    setEksCluster(value);
    setTool("");
    setDateFolder("");
    setReportType("");
    setDateFolders([]);
    setReports([]);
    // setFileUrl("");
    // setFileType("");
  };

  const handleToolChange = (value) => {
    setTool(value);
  };

  const handleDateFolderChange = (value) => {
    setDateFolder(value);
  };

  const handleReportChange = (value) => {
    setReportType(value);
    // setFileUrl("");
    // setFileType("");
  };

  const handleGetReport = async () => {
    if (!accountId || !eksCluster || !tool || !dateFolder || !reportType) {
      notifyError("Please select all options before getting the report");
      return;
    }
    setLoadingReport(true);
    try {
      const payload = {
        username,
        account: accountId,
        cluster: eksCluster,
        report_type: tool,
        date: dateFolder,
        pdf_name: reportType,
      };
      const res = await fetch(`${backend_url}/api/get-report-pdf`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      if (data.status === "ok") {
        const check = await fetch(data.pdfUrl);
        if (check.ok) {
          setFileUrl(data.pdfUrl);
          setFileType("pdf");
          setDisplayFileName(reportType);
          notifySuccess("Report loaded successfully");
          setIsShowingSampleReport(false);
          setSampleTool();
        } else {
          notifyError("Error fetching report");
        }
      } else {
        notifyError(data.error_message || "Error fetching report");
      }
    } catch (err) {
      console.error("Error getting report:", err);
      notifyError("Error loading report");
    } finally {
      setLoadingReport(false);
    }
  };

  const handleGetSampleReport = async () => {
    if (!sampleTool) {
      notifyError("Please select a tool for sample report");
      return;
    }

    setLoadingSampleReport(true);
    try {
      const sampleReportUrls = {
        mitre: process.env.REACT_APP_SAMPLE_MITRE_URL,
        nsa: process.env.REACT_APP_SAMPLE_NSA_URL,
        kubehunter: process.env.REACT_APP_SAMPLE_KUBEHUNTER_URL,
      };

      const s3_pdf_url = sampleReportUrls[sampleTool];
      if (!s3_pdf_url) {
        notifyError("Sample report not available for selected tool");
        return;
      }

      const check = await fetch(s3_pdf_url);

      if (check.ok) {
        setFileUrl(s3_pdf_url);
        setFileType("pdf");
        setLastValidSampleTool(sampleTool);
        setDisplayFileName(`${getSampleToolLabel(sampleTool)} Sample Report`);
        notifySuccess("Sample report loaded successfully");
        setIsShowingSampleReport(true);
      } else {
        setSampleTool(lastValidSampleTool);
        notifyError("Sample report not available for selected tool");
      }
    } catch (err) {
      setSampleTool(lastValidSampleTool);
      console.error("Error getting sample report:", err);
      notifyError("Error loading sample report");
    } finally {
      setLoadingSampleReport(false);
    }
  };

  const isGetReportEnabled =
    accountId && eksCluster && tool && dateFolder && reportType;

  return (
    <div className="p-6 pl-12 bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 min-h-screen">
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
            Cluster Security Reports
          </h1>
        </div>
      </div>

      <div className="mb-6">
        <div className="bg-white/95 dark:bg-slate-900/95 backdrop-blur-lg rounded-2xl shadow-2xl shadow-slate-900/20 border border-slate-200 dark:border-slate-700 p-6">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">
            Select Report Parameters
          </h3>

          {/* account id dropdown */}
          <div className="flex items-end gap-4 flex-wrap">
            <CustomDropdown
              label="Account ID"
              value={accountId}
              onChange={handleAccountChange}
              options={accounts}
              placeholder="Select account..."
              loading={loadingAccounts}
            />

            {/* clusters dropdown */}
            <CustomDropdown
              label="EKS Cluster"
              value={eksCluster}
              onChange={handleClusterChange}
              options={eksClusters}
              placeholder={
                accountId ? "Select cluster..." : "Select account first"
              }
              disabled={!accountId}
              loading={loadingClusters}
            />

            {/* tool dropdown */}
            <CustomDropdown
              label="Security Tool"
              value={tool}
              onChange={handleToolChange}
              options={toolOptions}
              placeholder={
                eksCluster ? "Select tool..." : "Select cluster first"
              }
              disabled={!eksCluster}
            />

            {/* date folder dropdown */}
            <CustomDropdown
              label="Date Folder"
              value={dateFolder}
              onChange={handleDateFolderChange}
              options={dateFolders}
              placeholder={tool ? "Select date..." : "Select tool first"}
              disabled={!tool}
              loading={loadingDateFolders}
            />

            {/* reports dropdown */}
            <CustomDropdown
              label="Available Reports"
              value={reportType}
              onChange={handleReportChange}
              options={reports}
              placeholder={
                dateFolder ? "Select report..." : "Select date first"
              }
              disabled={!dateFolder}
              loading={loadingReports}
            />

            {/* get report button */}
            <div className="flex-shrink-0">
              <Button
                type="primary"
                size="large"
                loading={loadingReport}
                onClick={handleGetReport}
                disabled={!isGetReportEnabled}
                className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 font-semibold px-4 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 disabled:opacity-70 disabled:text-white"
                icon={!loadingReport && <Play className="w-4 h-4" />}
              >
                {loadingReport ? "Loading..." : "Get Report"}
              </Button>
            </div>
            <div className="mb-6 border-t border-gray-200 dark:border-gray-700"></div>

            {/* Vertical line separator */}
            <div className="w-px h-12 bg-gray-300 dark:bg-gray-600 mx-2" />

            {/* sample tool dropdown */}
            <div className="flex items-end gap-4 flex-wrap">
              <CustomDropdown
                label="Sample Tool"
                value={sampleTool}
                onChange={setSampleTool}
                options={sampleToolOptions}
                placeholder="Select sample tool..."
              />

              {/* get sample report button */}
              <div className="flex-shrink-0">
                <Button
                  type="primary"
                  size="large"
                  loading={loadingSampleReport}
                  onClick={handleGetSampleReport}
                  disabled={!sampleTool}
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 font-semibold px-4 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 disabled:opacity-70 disabled:text-white"
                  icon={!loadingSampleReport && <Play className="w-4 h-4" />}
                >
                  {loadingSampleReport ? "Loading..." : "Get Sample Report"}
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {isShowingSampleReport && <GetSampleReportNote />}

      <div className="bg-white/95 dark:bg-slate-900/95 backdrop-blur-lg rounded-2xl shadow-2xl shadow-slate-900/20 border border-slate-200 dark:border-slate-700 p-6">
        <FileDisplay
          fileUrl={fileUrl}
          fileType={fileType}
          fileName={displayFileName}
        />
      </div>
    </div>
  );
};

export default ClusterFindings;
