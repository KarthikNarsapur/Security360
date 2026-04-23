import { Segmented, Tooltip } from "antd";
import { FaAws } from "react-icons/fa";
import { VscAzure } from "react-icons/vsc";
import { BiLogoGoogleCloud } from "react-icons/bi";
import { MdCloud } from "react-icons/md";

const STATUS_DOT = {
  ok: "bg-green-500",
  empty: "bg-gray-400",
  error: "bg-red-500",
  skipped: "hidden",
};

const formatTimestamp = (ts) => {
  if (!ts) return "No data";
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return new Date(ts).toLocaleDateString("en-GB");
};

const CloudOption = ({ icon, label, status }) => {
  const dotClass = status ? STATUS_DOT[status.status] || STATUS_DOT.error : "";
  const tooltip = status
    ? status.status === "skipped"
      ? `${label}: Not selected`
      : status.status === "error"
        ? `${label}: Failed to load`
        : `${label}: ${formatTimestamp(status.lastScanned)}`
    : label;

  return (
    <Tooltip title={tooltip}>
      <div className="flex items-center gap-1.5 px-1">
        {icon}
        <span className="text-sm">{label}</span>
        {status && <span className={`w-2 h-2 rounded-full ${dotClass}`} />}
      </div>
    </Tooltip>
  );
};

const CloudFilter = ({ selectedCloud = "all", onCloudChange, cloudStatuses = {} }) => {
  const options = [
    {
      value: "all",
      label: (
        <CloudOption
          icon={<MdCloud className="w-4 h-4" />}
          label="All Clouds"
          status={null}
        />
      ),
    },
    {
      value: "aws",
      label: (
        <CloudOption
          icon={<FaAws className="w-4 h-4 text-orange-500" />}
          label="AWS"
          status={cloudStatuses.aws}
        />
      ),
    },
    {
      value: "azure",
      label: (
        <CloudOption
          icon={<VscAzure className="w-4 h-4 text-blue-500" />}
          label="Azure"
          status={cloudStatuses.azure}
        />
      ),
    },
    {
      value: "gcp",
      label: (
        <CloudOption
          icon={<BiLogoGoogleCloud className="w-4 h-4 text-red-500" />}
          label="GCP"
          status={cloudStatuses.gcp}
        />
      ),
    },
  ];

  return (
    <div className="sticky top-0 z-10 bg-white/90 dark:bg-slate-900/90 backdrop-blur-md py-3 px-1 rounded-xl">
      <Segmented
        options={options}
        value={selectedCloud}
        onChange={onCloudChange}
        size="large"
        className="bg-gray-100 dark:bg-slate-800"
      />
    </div>
  );
};

export default CloudFilter;
