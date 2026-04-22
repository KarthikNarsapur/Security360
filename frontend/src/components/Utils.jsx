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
import { LuNotebookPen } from "react-icons/lu";
import Cookies from "js-cookie";
import { useNavigate } from "react-router-dom";
import { useEffect } from "react";
import { notifyInfo } from "./Notification";

const getStatusColor = (status) => {
  const lowerStatus = status.toLowerCase();
  const baseClasses =
    "capitalize font-semibold px-3 py-1 rounded-full text-white text-sxl  border-0";

  switch (lowerStatus) {
    case "failed":
      return `${baseClasses} bg-gradient-to-r from-red-500 to-red-600`;
    case "passed":
      return `${baseClasses} bg-gradient-to-r from-green-500 to-green-600`;
    case "partially_failed":
      return `${baseClasses} bg-gradient-to-r from-orange-500 to-orange-600`;
    case "not_available":
      return `${baseClasses} bg-gradient-to-r from-gray-500 to-gray-600`;
    default:
      return `${baseClasses} bg-gradient-to-r from-slate-500 to-slate-600`;
  }
};

// Status display map
const statusLabelMap = {
  passed: "Compliant",
  failed: "Non-Compliant",
  not_available: "Not Applicable",
  unknown: "Unknown",
};

const statusValueMap = {
  Compliant: "passed",
  "Non-Compliant": "failed",
  "Not Applicable": "not_available",
  unknown: "Unknown",
};

const formatStatus = (status) => {
  return statusLabelMap[status] || "Unknown";
};

const getPaginationConfig = (pageSize, setPageSize) => ({
  pageSize,
  showSizeChanger: true,
  showQuickJumper: true,
  onChange: (_, size) => setPageSize(size),
  onShowSizeChange: (_, size) => setPageSize(size),
  showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} items`,
});

const getStatusIcon = (status) => {
  switch (status) {
    case "passed":
      return <CheckCircle className="w-4 h-4 text-green-500" />;
    case "failed":
      return <XCircle className="w-4 h-4 text-red-500" />;
    case "partially_failed":
      return <AlertTriangle className="w-4 h-4 text-orange-500" />;
    default:
      return <HelpCircle className="w-4 h-4 text-gray-500" />;
  }
};

const getSeverityColor = (severity) => {
  const baseClasses =
    "capitalize font-semibold px-3 py-1 rounded-full text-white text-sxl border-0";
  const lowerSeverity = severity.toLowerCase();

  switch (lowerSeverity) {
    case "critical":
      return `${baseClasses} bg-gradient-to-r from-[#7f0a0a] to-[#5c0000]`; // Dark Red
    case "high":
      return `${baseClasses} bg-gradient-to-r from-[#d51800] to-[#a31400]`; // Red
    case "medium":
      return `${baseClasses} bg-gradient-to-r from-[#ff8200] to-[#e56a00]`; // Orange
    case "low":
      return `${baseClasses} bg-gradient-to-r from-[#ffc300] to-[#e6ac00]`; // Yellow
    default:
      return `${baseClasses} bg-gradient-to-r from-slate-500 to-slate-600`; // Grey
  }
};

const getSeverityColorsBasicScan = (severity) => {
  const colorMap = {
    Critical: {
      background: "#7f0a0a",
      border: "#5c0000",
    },
    High: {
      background: "#d51800",
      border: "#a31400",
    },
    Medium: {
      background: "#ff8200",
      border: "#e56a00",
    },
    Low: {
      background: "#ffc300",
      border: "#e6ac00",
    },
  };

  return (
    colorMap[severity] || {
      background: "#64748b",
      border: "#475569",
    }
  );
};

const getSeverityColorBorder = (severity) => {
  const lowerSeverity = severity.toLowerCase();

  switch (lowerSeverity) {
    case "critical":
      return "red-900"; // Dark Red
    case "high":
      return "red-700"; // Red
    case "medium":
      return "orange-600"; // Orange
    case "low":
      return "yellow-500"; // Yellow
    default:
      return "slate-600"; // Grey fallback
  }
};

const getSeverityIcon = (severity) => {
  switch (severity) {
    case "Critical":
      return <XCircle className="w-5 h-5 text-red-500" />;
    case "High":
      return <AlertTriangle className="w-5 h-5 text-orange-500" />;
    case "Medium":
      return <Eye className="w-5 h-5 text-yellow-500" />;
    case "Low":
      return <CheckCircle className="w-5 h-5 text-blue-500" />;
    default:
      return <HelpCircle className="w-5 h-5 text-gray-500" />;
  }
};

const GetNote = ({ note }) => {
  return (
    <div className="mb-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-red-300 dark:border-red-700">
      <div className="flex items-center gap-6 text-sm text-slate-600 dark:text-slate-400">
        <div className="flex items-center gap-2">
          <LuNotebookPen className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
          <span className="font-medium">Note:</span>
          <span className="font-mono text-slate-900 dark:text-slate-200">
            {note}
          </span>
        </div>
      </div>
    </div>
  );
};

const GetSampleReportNote = ({ note }) => {
  return (
    <div className="mb-4 p-4 bg-yellow-100 border-l-4 border-yellow-500 text-yellow-800 rounded-lg">
      This is a <span className="font-semibold">sample report</span> for
      demonstration purposes.
    </div>
  );
};
const getStatusClasses = (status) => {
  switch (status) {
    case "ACTIVE":
      return "from-green-500 to-green-600";
    case "UPDATING":
      return "from-orange-500 to-orange-600";
    case "FAILED":
      return "from-red-500 to-red-600";
    case "CREATING":
      return "from-green-400 to-green-400";
    case "DELETING":
      return "from-red-400 to-red-500";
    default:
      return "from-gray-400 to-gray-500";
  }
};

function formatDate(dateValue) {
  const date = new Date(dateValue);
  if (isNaN(date)) return null;

  const istOffset = 330 * 60 * 1000; // in milliseconds
  const istDate = new Date(date.getTime() - istOffset);

  const pad = (n) => (n < 10 ? "0" + n : n);
  const day = pad(istDate.getDate());
  const month = pad(istDate.getMonth() + 1);
  const year = istDate.getFullYear();
  const hours = pad(istDate.getHours());
  const minutes = pad(istDate.getMinutes());
  const seconds = pad(istDate.getSeconds());

  return `${day}/${month}/${year} ${hours}:${minutes}:${seconds}`;
}

const NoDataAvailableMessageComponent = ({ messages }) => {
  return (
    <div
      className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 text-center"
      style={{
        minHeight: "200px",
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
      }}
    >
      {messages.map((message, index) => (
        <p
          key={index}
          className={`text-lg font-semibold ${
            index === 0
              ? "text-slate-600 dark:text-slate-300"
              : "text-slate-500 dark:text-slate-400"
          }`}
        >
          {message}
        </p>
      ))}
    </div>
  );
};

const useCheckLoggedIn = () => {
  const navigate = useNavigate();

  useEffect(() => {
    const checkLoggedIn = async () => {
      try {
        const access_token = Cookies.get("access_token");
        if (access_token) {
          navigate("/dashboard");
        }
      } catch (err) {
        console.log("error: ", err);
      }
    };

    checkLoggedIn();
  }, [navigate]);
};

const fetchUserDetails = async ({ navigate }) => {
  try {
    const backend_url = process.env.REACT_APP_BACKEND_URL;
    const access_token = Cookies.get("access_token") || "";
    const username = localStorage.getItem("username") || "";
    const full_name = localStorage.getItem("full_name") || "";
    const accountDetails = localStorage.getItem("account_details");
    const eksAccountDetails = localStorage.getItem("eks_account_details");

    let parsedAccountDetails = null;
    let parsedEKSAccountDetails = null;

    if (accountDetails) {
      try {
        parsedAccountDetails = JSON.parse(accountDetails);
      } catch (error) {
        console.error("Failed to parse 'account_details' cookie:", error);
        parsedAccountDetails = null;
      }
    }

    if (eksAccountDetails) {
      try {
        parsedEKSAccountDetails = JSON.parse(eksAccountDetails);
      } catch (error) {
        console.error("Failed to parse 'eks_account_details' cookie:", error);
        parsedEKSAccountDetails = null;
      }
    }

    const payload = {
      access_token: access_token,
    };
    if (!payload.access_token) {
      notifyInfo("Session expired, login again..");
      try {
        localStorage.removeItem("username");
        localStorage.removeItem("full_name");
        localStorage.removeItem("account_details");
        localStorage.removeItem("eks_account_details");
      } catch (error) {
        console.error("Error removing cookies:", error);
      }
      navigate("/login");
      return { status: "error" };
    }
    if (
      username !== "" &&
      full_name !== "" &&
      accountDetails !== null &&
      eksAccountDetails !== null
    ) {
      return {
        status: "ok",
        userName: username,
        fullName: full_name,
        accountDetails: accountDetails,
        eksAccountDetails: eksAccountDetails,
      };
    }
    const response = await fetch(`${backend_url}/api/getuseraccount`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${access_token}`,
      },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (result?.status === "ok") {
      localStorage.setItem("username", result?.response?.username);
      localStorage.setItem("full_name", result?.response?.full_name);
      localStorage.setItem(
        "account_details",
        JSON.stringify(result?.response?.account_details)
      );
      localStorage.setItem(
        "eks_account_details",
        JSON.stringify(result?.response?.eks_account_details)
      );

      return {
        status: "ok",
        userName: result?.response?.username || "",
        fullName: result?.response?.full_name || "",
        accountDetails: result?.response?.account_details || "",
        eksAccountDetails: result?.response?.eks_account_details || "",
        isAdmin: result?.response?.is_admin || false,
      };
    } else {
      console.log("failed to fetch username");
      return { status: "failed" };
    }
  } catch (err) {
    console.log("error: ", err);
    return { status: "failed" };
  }
};

const MenuIcon = ({ src, alt }) => (
  <img src={src} alt={alt} className="w-5 h-5 mr-1 object-contain" />
);

export {
  getStatusColor,
  formatStatus,
  getPaginationConfig,
  getStatusIcon,
  getSeverityColor,
  getSeverityColorsBasicScan,
  getSeverityColorBorder,
  getSeverityIcon,
  GetNote,
  GetSampleReportNote,
  formatDate,
  getStatusClasses,
  NoDataAvailableMessageComponent,
  useCheckLoggedIn,
  fetchUserDetails,
  statusLabelMap,
  statusValueMap,
  MenuIcon,
};
