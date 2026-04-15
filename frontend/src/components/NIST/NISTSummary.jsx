import { useEffect, useState } from "react";
import { Doughnut, Bar } from "react-chartjs-2";
import {
  Table,
  Tag,
  Drawer,
  Checkbox,
  Button,
  Dropdown,
  Space,
  message,
  Divider,
  Popconfirm,
  theme,
} from "antd";
import {
  FilterOutlined,
  DownloadOutlined,
  EyeInvisibleOutlined,
} from "@ant-design/icons";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
} from "chart.js";
import {
  Shield,
  CheckCircle,
  XCircle,
  AlertTriangle,
  HelpCircle,
  X,
  Calendar,
  MapPin,
  Server,
  Database,
  Eye,
  ChevronRight,
  ChevronDown,
  Play,
  User,
  Clock,
  Square,
} from "lucide-react";
import {
  ISOSummarySkeleton,
  LoadingSkeletonCisDashboard,
  LoadingSkeletonCisDashboardS3Fetch,
} from "../LoadingSkeleton";
import { NISTSummarySkeleton } from "../LoadingSkeleton";
import RegionDropdown from "../UI/DropDown/RegionDropdown";
import {
  notifyError,
  notifyInfo,
  notifyRedirectToContact,
  notifySuccess,
} from "../Notification";
import {
  getStatusColor,
  getStatusIcon,
  getSeverityColor,
  getSeverityIcon,
  NoDataAvailableMessageComponent,
  fetchUserDetails,
  GetSampleReportNote,
  getPaginationConfig,
} from "../Utils";
import { useNavigate } from "react-router-dom";
import Cookies from "js-cookie";
import AccountDropdown from "../UI/DropDown/AccountDropdown";
import Spinner from "../UI/Spinner";
// import exportNISTFindingsToExcel from "./ExportNISTFindingsToExcel";

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement
);

const JsonRenderer = ({ data, level = 0 }) => {
  const [expandedKeys, setExpandedKeys] = useState(new Set());

  const toggleExpanded = (key) => {
    const newExpanded = new Set(expandedKeys);
    if (newExpanded.has(key)) {
      newExpanded.delete(key);
    } else {
      newExpanded.add(key);
    }
    setExpandedKeys(newExpanded);
  };

  const renderValue = (key, value, currentLevel) => {
    const uniqueKey = `${currentLevel}-${key}`;

    if (value === null || value === undefined) {
      return <span className="text-gray-400 italic">null</span>;
    }

    if (typeof value === "boolean") {
      return (
        <span
          className={`font-medium ${value ? "text-green-600" : "text-red-600"}`}
        >
          {value.toString()}
        </span>
      );
    }

    if (typeof value === "number") {
      return <span className="text-blue-600 font-medium">{value}</span>;
    }

    if (typeof value === "string") {
      // date
      if (value.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)) {
        return (
          <span className="text-purple-600">
            {new Date(value).toLocaleString()}
          </span>
        );
      }
      // ARN
      if (value.startsWith("arn:aws:")) {
        return (
          <span className="text-indigo-600 font-mono text-sm break-all">
            {value}
          </span>
        );
      }
      // IP or CIDR
      if (value.match(/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/)) {
        return <span className="text-orange-600 font-mono">{value}</span>;
      }
      return <span className="text-gray-700">{value}</span>;
    }

    if (Array.isArray(value)) {
      if (value.length === 0) {
        return <span className="text-gray-400 italic">[]</span>;
      }

      const isExpanded = expandedKeys.has(uniqueKey);
      return (
        <div>
          <button
            onClick={() => toggleExpanded(uniqueKey)}
            className="flex items-center text-sm text-blue-600 hover:text-blue-800 font-medium"
          >
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 mr-1" />
            ) : (
              <ChevronRight className="w-4 h-4 mr-1" />
            )}
            Array ({value.length} items)
          </button>
          {isExpanded && (
            <div className="ml-4 mt-2 space-y-2">
              {value.map((item, index) => (
                <div key={index} className="border-l-2 border-gray-200 pl-3">
                  <div className="text-sm font-medium text-gray-500 mb-1">
                    [{index}]
                  </div>
                  <JsonRenderer data={item} level={currentLevel + 1} />
                </div>
              ))}
            </div>
          )}
        </div>
      );
    }

    if (typeof value === "object") {
      const keys = Object.keys(value);
      if (keys.length === 0) {
        return <span className="text-gray-400 italic">{"{}"}</span>;
      }

      const isExpanded = expandedKeys.has(uniqueKey);
      return (
        <div>
          <button
            onClick={() => toggleExpanded(uniqueKey)}
            className="flex items-center text-sm text-blue-600 hover:text-blue-800 font-medium"
          >
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 mr-1" />
            ) : (
              <ChevronRight className="w-4 h-4 mr-1" />
            )}
            Object ({keys.length} properties)
          </button>
          {isExpanded && (
            <div className="ml-4 mt-2">
              <JsonRenderer data={value} level={currentLevel + 1} />
            </div>
          )}
        </div>
      );
    }

    return <span className="text-gray-700">{String(value)}</span>;
  };

  if ((!data || typeof data !== "object") && !loading) {
    return <div className="text-gray-500 italic">No data available</div>;
  }

  return (
    <div className="space-y-3">
      {Object.entries(data).map(([key, value]) => (
        <div
          key={key}
          className={`${level > 0 ? "border-l-2 border-gray-100 pl-4" : ""}`}
        >
          <div className="flex items-start gap-3">
            <div className="min-w-0 flex-1">
              <div className="text-sm font-medium text-gray-900 mb-1">
                {key
                  .replace(/_/g, " ")
                  .replace(/\b\w/g, (l) => l.toUpperCase())}
              </div>
              <div className="text-sm">{renderValue(key, value, level)}</div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

// Filter dropdown component

const DropdownFilter = ({ label, options, selected, onChange }) => {
  const handleCheckboxChange = (value, checked) => {
    const newSelected = checked
      ? [...selected, value]
      : selected.filter((v) => v !== value);

    onChange(newSelected);
  };

  return (
    <Dropdown
      trigger={["click"]}
      dropdownRender={() => (
        <div
          style={{
            padding: 12,
            background: "#fff",
            borderRadius: 8,
            boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
            display: "flex",
            flexDirection: "column",
            maxHeight: 160,
            overflowY: "auto",
          }}
        >
          {options.map((opt) => (
            <Checkbox
              key={opt}
              checked={selected.includes(opt)}
              onChange={(e) => handleCheckboxChange(opt, e.target.checked)}
              style={{ marginBottom: 8 }}
            >
              {opt}
            </Checkbox>
          ))}
        </div>
      )}
    >
      <Button icon={<FilterOutlined />} className="mr-2">
        {label}
      </Button>
    </Dropdown>
  );
};

const downloadFile = (filename, content, type) => {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
};

const convertToCSV = (data) => {
  if (data.length === 0) return "";
  const keys = Object.keys(data[0]);
  const rows = data.map((row) =>
    keys.map((k) => JSON.stringify(row[k] ?? "")).join(",")
  );
  return [keys.join(","), ...rows].join("\n");
};

const NISTSummary = ({
  accountDetails,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) => {
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [selectedRegions, setSelectedRegions] = useState([]);
  const [selectedAccounts, setSelectedAccounts] = useState([]);
  const [meta, setMeta] = useState();
  const [prevReportAvailable, setPrevReportAvailable] = useState();
  const [isReportAvailable, setIsReportAvailable] = useState();
  const [NISTRules, setNISTRules] = useState(null);
  const [loading, setLoading] = useState(false);
  const [s3FetchLoading, setS3FetchLoading] = useState(false);
  const [error, setError] = useState(null);
  const [dashboardData, setDashboardData] = useState(null);
  const [progress, setProgress] = useState(0);
  const [socket, setSocket] = useState(null);
  const [selectedFilterRegions, setSelectedFilterRegions] = useState([]);
  const [selectedStatuses, setSelectedStatuses] = useState([]);
  const [selectedSeverities, setSelectedSeverities] = useState([]);
  const [selectedReportAccount, setSelectedReportAccount] = useState([]); //for report account
  const [isNISTSampleReport, setIsNISTSampleReport] = useState(false);
  const [pageSize, setPageSize] = useState(10);


  const { token } = theme.useToken();
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

  const [hiddenNISTFindings, setHiddenNISTFindings] = useState(() => {
    const saved = localStorage.getItem("hiddenNISTRules");
    return saved ? JSON.parse(saved) : [];
  });

  useEffect(() => {
    localStorage.setItem("hiddenNISTRules", JSON.stringify(hiddenNISTFindings));
  }, [hiddenNISTFindings]);

  const handleHideNISTFinding = (e, findingId) => {
    // console.log("first: ", e, findingId);
    e.stopPropagation();
    setHiddenNISTFindings((prev) => [...prev, findingId]);
    notifySuccess("Finding hidden successfully");
  };

  useEffect(() => {
    return () => {
      if (socket) {
        socket.close();
      }
    };
  }, [socket]);

  const handleRegionChange = (regions) => {
    setSelectedRegions(regions);
  };

  const handleAccountChange = (accounts) => {
    setSelectedAccounts(accounts);
  };

  const handleReportAccountChange = async (accounts, isSample = false) => {
    const previousValue = selectedReportAccount;
    setIsNISTSampleReport(isSample);

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
        type: "NIST42001",
        is_sample: isSample,
      };
      setS3FetchLoading(true);
      setIsNISTSampleReport(isSample);

      // Call backend API to get report for selected account
      const response = await fetch(`${backend_url}/api/get-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const apiResponse = await response.json();

      if (apiResponse?.status === "ok") {
        console.log("api reponse: ", apiResponse)
        isSample && setSelectedReportAccount();

        const report = apiResponse.data;
        const NISTScannedDataAllRegions = report.results;

        setMeta({
          account_id: report?.account_id || "",
          timestamp: report?.timestamp || "",
        });
        // setReport(data.results);
        setIsReportAvailable(true);
        setNISTRules(NISTScannedDataAllRegions);
        processDashboardData(NISTScannedDataAllRegions);
      } else {
        notifyError(apiResponse?.error_message || "Failed to get report");
        setSelectedReportAccount(previousValue);
        setIsNISTSampleReport(false);
      }
    } catch (err) {
      console.error("Failed to get report:", err);
      notifyError("Failed to get report");
      setSelectedReportAccount(previousValue);
      setIsNISTSampleReport(false);
    } finally {
      setS3FetchLoading(false);
    }
  };

  const handleScanClick = async () => {
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
      // const webSocketURL = `${process.env.REACT_APP_WEBSOCKET_URL}/NIST-progress`;
      // const ws = new WebSocket(webSocketURL);
      // setSocket(ws);

      // ws.onopen = () => {
      //   console.log("WebSocket connected");
      //   // console.log("loading: ", loading);
      //   setLoading(true);
      //   setSelectedRegions([]);
      //   setProgress(0);
      //   sendBackendRequest();
      // };

      // ws.onmessage = (event) => {
      //   const data = JSON.parse(event.data);
      //   // console.log("in websocket data: ", data);
      //   if (data.progress !== undefined) {
      //     setProgress(data.progress);
      //   }
      //   if (data.status === "completed") {
      //     ws.close();
      //     setLoading(false);
      //     setSocket(null);
      //     // // Fetch the results
      //     // const result = response.json();
      //     // if (result?.status === "ok") {
      //     //   const filename = result?.filename;
      //     //   fetchFromS3(filename);
      //     // }
      //   }
      //   if (data.status === "error") {
      //     ws.close();
      //     setLoading(false);
      //     setSocket(null);
      //     setProgress(0);
      //   }
      // };

      // ws.onclose = () => {
      //   console.log("closing websocket");
      //   setSocket(null);
      // };

      // ws.onerror = (error) => {
      //   console.error("WebSocket error:", error);
      //   notifyError("Failed to connect to the progress server.");
      //   setLoading(false);
      // };

      const sendBackendRequest = async () => {
        setLoading(true);
        try {
          const response = await fetch(`${backend_url}/api/NIST-scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });

          const result = await response.json();
          if (result?.status === "ok") {
            // fetch from s3
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
            // if (ws.readyState === WebSocket.OPEN) {
            //   ws.close();
            // }
            setLoading(false);
            setProgress(0);
            notifyError(result?.error_message || "Error in NIST rules scan");
            console.log("Error in NIST rules scan", result);
            if (result?.fail_type || "" === "contact_us") {
              notifyRedirectToContact(navigate, 5);
            }
          }
        } catch (err) {
          console.error("Backend request failed:", err);
          notifyError("Failed to start scan: " + err.message);
          // if (ws.readyState === WebSocket.OPEN) {
          //   ws.close();
          // }
          setLoading(false);
          setProgress(0);
        }
        finally {
          setLoading(false);
        }

      };
      sendBackendRequest();
    } catch (err) {
      console.log("Failed to load report: " + err.message);
    } finally {
      // setLoading(false);
      // setIsFetched(false);
    }
  };

  const stopScan = () => {
    if (socket) {
      socket.close();
      setLoading(false);
      setProgress(0);
    }
  };

  const processDashboardData = (data) => {
    let totalScanned = 0;
    let totalAffected = 0;
    let passed = 0;
    let failed = 0;
    let not_available = 0
    let unknown = 0;

    const severityCounts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Info: 0
    };

    const tableData = [];

    for (const regionData of data) {
      const currentRegion = regionData?.region || "";
      const regionScannedData = regionData?.data || {};
      Object.entries(regionScannedData).forEach(([key, rule]) => {
        const uniqueKey = `${key}-${currentRegion}`;

        if (!rule) {
          unknown++;
          tableData.push({
            key: uniqueKey,
            id: key,
            check_name: "Unknown",
            severity_level: "Unknown",
            status: "unknown",
            failed_checks: "Unknown",
            total_scanned: 0,
            affected: 0,
            fullData: null,
            region: currentRegion,
          });
          return;
        }

        const scanned = rule.additional_info?.total_scanned || 0;
        const affected = rule.additional_info?.affected || 0;

        totalScanned += scanned;
        totalAffected += affected;

        const status = rule?.status || "unknown";
        console.log("unique key: ", uniqueKey, "and status: ", status)
        if (status === "passed") {
          passed++;
        } else if (status === "failed") {
          failed++;
        } else if (status === "not_available") {
          not_available++;
        } else {
          unknown++;
        }

        if (
          rule.severity_level &&
          severityCounts.hasOwnProperty(rule.severity_level)
        ) {
          severityCounts[rule.severity_level] =
            severityCounts[rule.severity_level] +
            rule?.additional_info?.affected || 0;
        }
        tableData.push({
          key: uniqueKey,
          id: rule.id,
          check_name: rule.check_name,
          severity_level: rule.severity_level,
          status,
          failed_checks: `${affected} out of ${scanned}`,
          total_scanned: scanned,
          affected,
          fullData: rule,
          region: currentRegion,
        });
      });
    }
    const securityScore =
      totalScanned > 0
        ? Math.round(((totalScanned - totalAffected) / totalScanned) * 100)
        : 0;

    setDashboardData({
      securityScore,
      totalScanned,
      totalAffected,
      passed,
      failed,
      unknown,
      severityCounts,
      tableData,
    });
    // debug
  };

  const handleRowClick = (record) => {
    setSelectedFinding(record);
    setDrawerVisible(true);
  };

  const getFilterOptions = () => {
    if (!dashboardData?.tableData)
      return { regions: [], statuses: [], severities: [] };

    const regions = [
      ...new Set(dashboardData?.tableData.map((item) => item.region)),
    ].filter(Boolean);

    const statuses = [
      ...new Set(dashboardData?.tableData.map((item) => item.status)),
    ].filter(Boolean);

    const severities = [
      ...new Set(dashboardData?.tableData.map((item) => item.severity_level)),
    ].filter(Boolean);

    return { regions, statuses, severities };
  };

  const getFilteredTableData = () => {
    if (!dashboardData?.tableData) return [];

    return dashboardData?.tableData.filter((item) => {
      const regionMatch =
        selectedFilterRegions.length === 0 ||
        selectedFilterRegions.includes(item.region);

      const statusMatch =
        selectedStatuses.length === 0 || selectedStatuses.includes(item.status);

      const severityMatch =
        selectedSeverities.length === 0 ||
        selectedSeverities.includes(item.severity_level);

      const hiddenMatch = !hiddenNISTFindings.includes(item.id + item.region);

      return regionMatch && statusMatch && severityMatch && hiddenMatch;
    });
  };

  const exportToJSON = () => {
    const filteredData = getFilteredTableData();
    const json = JSON.stringify(filteredData, null, 2);
    downloadFile(
      `${accountDetails?.[0]?.account_id || ""}_NIST-findings.json`,
      json,
      "application/json"
    );
    notifySuccess("Exported to JSON!");
  };

  const exportToCSV = () => {
    const filteredData = getFilteredTableData();
    const csv = convertToCSV(filteredData);
    downloadFile(
      `${accountDetails?.[0]?.account_id || ""}_NIST-findings.csv`,
      csv,
      "text/csv"
    );
    notifySuccess("Exported to CSV!");
  };

  const clearAllFilters = () => {
    setSelectedFilterRegions([]);
    setSelectedStatuses([]);
    setSelectedSeverities([]);
  };

  // Chart
  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    circumference: 180,
    rotation: 270,
    cutout: "75%",
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        enabled: false,
      },
    },
  };

  const doughnutData = {
    datasets: [
      {
        data: dashboardData
          ? [dashboardData?.securityScore, 100 - dashboardData?.securityScore]
          : [0, 100],
        backgroundColor: [
          dashboardData?.securityScore >= 80
            ? "#10B981"
            : dashboardData?.securityScore >= 60
              ? "#F59E0B"
              : "#EF4444",
          "#E5E7EB",
        ],
        borderWidth: 0,
      },
    ],
  };

  const barData = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [
      {
        data: dashboardData
          ? [
            dashboardData.severityCounts.Critical,
            dashboardData.severityCounts.High,
            dashboardData.severityCounts.Medium,
            dashboardData.severityCounts.Low,
          ]
          : [0, 0, 0, 0],
        backgroundColor: ["#DC2626", "#EA580C", "#D97706", "#2563EB"],
        borderRadius: 4,
      },
    ],
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: "y",
    plugins: {
      legend: {
        display: false,
      },
    },
    scales: {
      x: {
        beginAtZero: true,
        ticks: {
          stepSize: 1,
        },
      },
      y: {
        grid: {
          display: false,
        },
      },
    },
  };

  const columns = [
    {
      title: "Status",
      dataIndex: "status",
      key: "status",
      sorter: (a, b) => a.status.localeCompare(b.status),
      render: (status) => (
        <div className="flex items-center gap-2">
          <Tag className={getStatusColor(status)}>
            {status === "partially_failed"
              ? "Partially Failed"
              : status.charAt(0).toUpperCase() + status.slice(1)}
          </Tag>
        </div>
      ),
    },
    {
      title: "Severity Level",
      dataIndex: "severity_level",
      key: "severity_level",
      sorter: (a, b) => a.severity_level.localeCompare(b.severity_level),
      render: (severity) => (
        <Tag className={getSeverityColor(severity)}>{severity}</Tag>
      ),
    },
    {
      title: "Region",
      dataIndex: "region",
      key: "region",
      sorter: (a, b) => a.region.localeCompare(b.region),
    },
    {
      title: "ID",
      dataIndex: "id",
      key: "id",
      sorter: (a, b) => a.id.localeCompare(b.id),
      render: (id) => <span className="font-mono text-sm">{id}</span>,
    },
    {
      title: "Check Name",
      dataIndex: "check_name",
      key: "check_name",
      sorter: (a, b) => a.check_name.localeCompare(b.check_name),
    },
    {
      title: "Failed Checks",
      dataIndex: "failed_checks",
      key: "failed_checks",
      render: (text, record) => (
        <span
          className={
            record.affected > 0 ? "text-red-600 font-medium" : "text-green-600"
          }
        >
          {text}
        </span>
      ),
    },
    {
      title: "Action",
      key: "action",
      render: (_, record) => (
        <Popconfirm
          title="Are you sure you want to hide this finding?"
          onConfirm={(e) => handleHideNISTFinding(e, record.id + record.region)}
          okText="Yes"
          cancelText="No"
          onCancel={(e) => e.stopPropagation()}
        >
          <Button
            icon={<EyeInvisibleOutlined />}
            size="small"
            onClick={(e) => e.stopPropagation()}
          >
            Hide
          </Button>
        </Popconfirm>
      ),
    },
  ];


  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
        <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-red-500/10 p-8 border border-red-100 dark:border-red-800">
          <div className="text-red-600 dark:text-red-400 text-center">
            <XCircle className="w-12 h-12 mx-auto mb-4" />
            <h2 className="text-xl font-semibold mb-2">
              Error Loading Dashboard
            </h2>
            <p>{error}</p>
          </div>
        </div>
      </div>
    );
  }

  const filterOptions = getFilterOptions();
  const filteredTableData = getFilteredTableData();

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="p-6 pl-12">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="mb-8">
            <div className="mt-2 flex items-center justify-between">
              <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent flex items-center gap-3">
                {/* <Shield className="w-8 h-8 text-indigo-600" /> */}
                NIST Benchmark Dashboard
              </h1>

              {/* Scan Controls */}
              <div className="flex items-center gap-4">
                <div className="w-60">
                  <AccountDropdown
                    onAccountChange={handleAccountChange}
                    selectedAccounts={selectedAccounts}
                    accountOptions={infra_accounts}
                    disabled={loading || s3FetchLoading}
                  />
                </div>
                <div className="w-60">
                  <RegionDropdown
                    onRegionChange={handleRegionChange}
                    selectedRegions={selectedRegions}
                    disabled={loading || s3FetchLoading}
                  />
                </div>
                <Button
                  type="primary"
                  icon={<Play className="w-4 h-4" />}
                  onClick={handleScanClick}
                  disabled={loading}
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                >
                  Run Scan
                </Button>
              </div>
            </div>

            {/* Horizontal line after dropdowns and run scan button */}
            <div className="mt-6 border-t border-gray-200 dark:border-gray-700"></div>
            {loading ? (
              <div className="mt-6">
                <ISOSummarySkeleton />
              </div>
            ) : (
              <>
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
                      disabled={loading || s3FetchLoading}
                    />
                  </div>
                  {/* Sample data button */}
                  <Button
                    type="primary"
                    icon={s3FetchLoading ? null : <Play className="w-4 h-4" />}
                    onClick={() => handleReportAccountChange("", true)} // "" for accounts
                    disabled={isNISTSampleReport}
                    className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 font-semibold px-6 rounded-xl rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 disabled:opacity-70 disabled:text-white"
                  >
                    {s3FetchLoading && isNISTSampleReport ? (
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
                {meta && (
                  <div className="mt-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-indigo-100 dark:border-slate-700">
                    <div className="flex items-center gap-6 text-sm text-slate-600 dark:text-slate-400">
                      <div className="flex items-center gap-2">
                        <User className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                        <span className="font-medium">Account ID:</span>
                        <span className="font-mono text-slate-900 dark:text-white">
                          {meta.account_id}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Clock className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                        <span className="font-medium">Last Scanned:</span>
                        <span className="text-slate-900 dark:text-white">
                          {meta.timestamp
                            ? new Date(
                              meta.timestamp.replace("Z", "")
                            ).toLocaleString("en-GB", {
                              hour12: true,
                            })
                            : "N/A"}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>

          {loading ? null : s3FetchLoading ? (
            <LoadingSkeletonCisDashboardS3Fetch />
          ) : !isReportAvailable ? (
            <div>
              <NoDataAvailableMessageComponent
                messages={[
                  "No data available",
                  "Run a scan to retrieve security findings for your AWS account.",
                ]}
              />
            </div>
          ) : (
            <div>
              {isNISTSampleReport && <GetSampleReportNote />}
              {/* Top Row - Charts */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                {/* Security Score Chart */}
                <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700">
                  <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
                    Security Score
                  </h2>
                  <div className="relative h-64">
                    <Doughnut data={doughnutData} options={doughnutOptions} />
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="text-center">
                        <div className="text-4xl font-bold text-slate-900 dark:text-white">
                          {dashboardData?.securityScore}%
                        </div>
                        <div className="text-sm text-slate-500 dark:text-slate-400">
                          Security Score
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="mt-4 text-center text-sm text-slate-600 dark:text-slate-400">
                    {dashboardData?.totalScanned - dashboardData?.totalAffected}{" "}
                    of {dashboardData?.totalScanned} checks passed
                  </div>
                </div>

                {/* Severity Distribution */}
                <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700">
                  <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
                    Findings by Severity
                  </h2>
                  <div className="h-64">
                    <Bar data={barData} options={barOptions} />
                  </div>
                </div>
              </div>
              {/* Overview Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 transition-all duration-200 hover:scale-105">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-slate-600 dark:text-slate-400">
                        Passed
                      </p>
                      <p className="text-4xl font-bold text-green-600">
                        {dashboardData?.passed}
                      </p>
                    </div>
                    <CheckCircle className="w-8 h-8 text-green-500" />
                  </div>
                </div>

                <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 transition-all duration-200 hover:scale-105">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-slate-600 dark:text-slate-400">
                        Failed
                      </p>
                      <p className="text-4xl font-bold text-red-600">
                        {dashboardData?.failed}
                      </p>
                    </div>
                    <XCircle className="w-8 h-8 text-red-500" />
                  </div>
                </div>

                <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 transition-all duration-200 hover:scale-105">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-slate-600 dark:text-slate-400">
                        Unknown
                      </p>
                      <p className="text-4xl font-bold text-slate-600 dark:text-slate-400">
                        {dashboardData?.unknown}
                      </p>
                    </div>
                    <HelpCircle className="w-8 h-8 text-slate-500" />
                  </div>
                </div>

                <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 transition-all duration-200 hover:scale-105">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-slate-600 dark:text-slate-400">
                        Total Affected
                      </p>
                      <p className="text-4xl font-bold text-orange-600">
                        {dashboardData?.totalAffected}
                      </p>
                    </div>
                    <AlertTriangle className="w-8 h-8 text-orange-500" />
                  </div>
                </div>
              </div>
              {/* Findings Table */}
              <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 border border-indigo-100 dark:border-slate-700">
                <div className="p-6 border-b border-indigo-100 dark:border-slate-700">
                  <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
                    Security Findings
                  </h2>
                </div>
                <div className="p-6">
                  {/* Filter and Export Controls */}

                  <div className="mb-4">
                    {/* <Space wrap className="mb-2"> */}
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <DropdownFilter
                          label="Region"
                          options={filterOptions.regions}
                          selected={selectedFilterRegions}
                          onChange={setSelectedFilterRegions}
                        />

                        <DropdownFilter
                          label="Status"
                          options={filterOptions.statuses}
                          selected={selectedStatuses}
                          onChange={setSelectedStatuses}
                        />

                        <DropdownFilter
                          label="Severity"
                          options={filterOptions.severities}
                          selected={selectedSeverities}
                          onChange={setSelectedSeverities}
                        />

                        <Button danger onClick={clearAllFilters}>
                          Clear All
                        </Button>
                        {/* </Space> */}
                      </div>

                      <div className="flex items-center gap-2">
                        <Button
                          icon={<DownloadOutlined />}
                          className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                          onClick={exportToJSON}
                        >
                          Export to JSON
                        </Button>
                        <Button
                          icon={<DownloadOutlined />}
                          className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                        // onClick={() =>
                        //   exportNISTFindingsToExcel(
                        //     filteredTableData,
                        //     accountDetails
                        //   )
                        // }
                        >
                          Export to Excel
                        </Button>
                      </div>
                    </div>

                    {/* Active Filters Display */}

                    {/* <div className="mt-2 text-sm text-gray-700"> */}
                    <div className="text-sm text-gray-700">
                      {(selectedFilterRegions.length > 0 ||
                        selectedStatuses.length > 0 ||
                        selectedSeverities.length > 0) && (
                          <span>
                            {selectedFilterRegions.length > 0 && (
                              <span>
                                <strong>Regions:</strong>{" "}
                                {selectedFilterRegions.join(", ")} |{" "}
                              </span>
                            )}

                            {selectedStatuses.length > 0 && (
                              <span>
                                <strong>Statuses:</strong>{" "}
                                {selectedStatuses.join(", ")} |{" "}
                              </span>
                            )}

                            {selectedSeverities.length > 0 && (
                              <span>
                                <strong>Severities:</strong>{" "}
                                {selectedSeverities.join(", ")}
                              </span>
                            )}
                          </span>
                        )}
                    </div>
                  </div>

                  <Divider />
                  <Table
                    columns={columns}
                    // dataSource={dashboardData.tableData}
                    dataSource={filteredTableData}
                    onRow={(record) => ({
                      onClick: () => handleRowClick(record),
                      className:
                        "cursor-pointer hover:bg-indigo-50 dark:hover:bg-slate-800 transition-colors",
                    })}
                    pagination={getPaginationConfig(pageSize, setPageSize)}
                    className="w-full"
                  />
                </div>
              </div>

              {/* Detailed Finding Drawer */}
              <Drawer
                title={
                  selectedFinding && (
                    <div className="flex items-center justify-between p-6 border-b bg-white sticky top-0 z-10">
                      <div className="flex items-center gap-3">
                        <div>
                          <h2 className="text-xl font-semibold text-gray-900">
                            {selectedFinding.check_name}
                          </h2>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="font-mono text-sm text-gray-600">
                              {selectedFinding.id}
                            </span>
                            <Tag
                              className={getSeverityColor(
                                selectedFinding.severity_level
                              )}
                            >
                              {selectedFinding.severity_level}
                            </Tag>
                            <Tag
                              className={getStatusColor(selectedFinding.status)}
                            >
                              {selectedFinding.status === "partially_failed"
                                ? "Partially Failed"
                                : selectedFinding.status
                                  .charAt(0)
                                  .toUpperCase() +
                                selectedFinding.status.slice(1)}
                            </Tag>
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={() => setDrawerVisible(false)}
                        className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                      >
                        <X className="w-5 h-5" />
                      </button>
                    </div>
                  )
                }
                placement="right"
                width={600}
                closable={false}
                onClose={() => setDrawerVisible(false)}
                open={drawerVisible}
                className="finding-drawer"
                styles={{
                  body: { padding: 0 },
                  wrapper: {
                    borderLeft: `2px solid ${token.drawerBorderColor}`,
                  },
                }}
              >
                {selectedFinding && (
                  <div className="h-full flex flex-col">
                    {/* Content */}
                    <div className="flex-1 overflow-y-auto">
                      {selectedFinding.fullData ? (
                        <div className="p-6 space-y-8">
                          {/* Overview Section */}
                          <div className="bg-gray-50 rounded-lg p-6">
                            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                              <Shield className="w-5 h-5" />
                              Overview
                            </h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                              <div>
                                <label className="text-sm font-medium text-gray-600">
                                  Problem Statement
                                </label>
                                <p className="text-gray-900 mt-1">
                                  {selectedFinding.fullData.problem_statement}
                                </p>
                              </div>
                              <div>
                                <label className="text-sm font-medium text-gray-600">
                                  Severity Score
                                </label>
                                <p className="text-gray-900 mt-1 font-semibold">
                                  {selectedFinding.fullData.severity_score}/100
                                </p>
                              </div>
                              <div>
                                <label className="text-sm font-medium text-gray-600">
                                  Total Scanned
                                </label>
                                <p className="text-gray-900 mt-1">
                                  {selectedFinding.total_scanned}
                                </p>
                              </div>
                              <div>
                                <label className="text-sm font-medium text-gray-600">
                                  Affected Resources
                                </label>
                                <p className="mt-1 font-semibold text-red-600">
                                  {selectedFinding.affected}
                                </p>
                              </div>
                              {selectedFinding.fullData.last_updated && (
                                <div className="md:col-span-2">
                                  <label className="text-sm font-medium text-gray-600 flex items-center gap-1">
                                    <Calendar className="w-4 h-4" />
                                    Last Updated
                                  </label>
                                  <p className="text-gray-900 mt-1">
                                    {new Date(
                                      selectedFinding.fullData.last_updated
                                    ).toLocaleString()}
                                  </p>
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Affected Resources */}
                          {selectedFinding.fullData.resources_affected &&
                            selectedFinding.fullData.resources_affected.length >
                            0 && (
                              <div>
                                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                                  <Server className="w-5 h-5 text-red-500" />
                                  Affected Resources (
                                  {
                                    selectedFinding.fullData.resources_affected
                                      .length
                                  }
                                  )
                                </h3>
                                <div className="space-y-4">
                                  {selectedFinding.fullData.resources_affected.map(
                                    (resource, index) => (
                                      <div
                                        key={index}
                                        className="bg-red-50 border border-red-200 rounded-lg p-6"
                                      >
                                        <div className="flex items-start justify-between mb-4">
                                          <div>
                                            <h4 className="font-semibold text-red-900 flex items-center gap-2">
                                              <Database className="w-4 h-4" />
                                              {resource.resource_id}
                                            </h4>
                                            {resource.region && (
                                              <p className="text-sm text-red-700 flex items-center gap-1 mt-1">
                                                <MapPin className="w-3 h-3" />
                                                {resource.region}
                                              </p>
                                            )}
                                          </div>
                                          {resource.issue && (
                                            <Tag color="red" className="ml-2">
                                              {resource.issue}
                                            </Tag>
                                          )}
                                        </div>

                                        <div className="border-t border-red-200 pt-4">
                                          <h5 className="font-medium text-red-900 mb-3">
                                            Resource Details
                                          </h5>
                                          <JsonRenderer data={resource} />
                                        </div>
                                      </div>
                                    )
                                  )}
                                </div>
                              </div>
                            )}

                          {/* Recommendation Section */}
                          {selectedFinding.fullData.recommendation && (
                            <div>
                              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                                <CheckCircle className="w-5 h-5 text-green-500" />
                                Recommendation
                              </h3>
                              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                                <p className="text-green-800">
                                  {selectedFinding.fullData.recommendation}
                                </p>
                              </div>
                            </div>
                          )}

                          {/* Remediation Steps */}
                          {selectedFinding.fullData.remediation_steps &&
                            selectedFinding.fullData.remediation_steps.length >
                            0 &&
                            selectedFinding.fullData.additional_info.affected >
                            0 && (
                              <div>
                                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                                  <AlertTriangle className="w-5 h-5 text-orange-500" />
                                  Remediation Steps
                                </h3>
                                <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                                  <ol className="space-y-2">
                                    {selectedFinding.fullData.remediation_steps.map(
                                      (step, index) => (
                                        <li
                                          key={index}
                                          className="text-orange-800 flex gap-3"
                                        >
                                          <span className="font-medium text-orange-600 min-w-[1.5rem]">
                                            {index + 1}.
                                          </span>
                                          <span>
                                            {step.replace(/^\d+\.\s*/, "")}
                                          </span>
                                        </li>
                                      )
                                    )}
                                  </ol>
                                </div>
                              </div>
                            )}

                          {/* Additional Information */}
                          {selectedFinding.fullData.additional_info && (
                            <div>
                              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                                <HelpCircle className="w-5 h-5 text-blue-500" />
                                Additional Information
                              </h3>
                              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                                <JsonRenderer
                                  data={
                                    selectedFinding.fullData.additional_info
                                  }
                                />
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="p-6">
                          <div className="text-center text-gray-500">
                            <HelpCircle className="w-12 h-12 mx-auto mb-4 text-gray-400" />
                            <p>
                              No detailed information available for this
                              finding.
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </Drawer>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default NISTSummary;
