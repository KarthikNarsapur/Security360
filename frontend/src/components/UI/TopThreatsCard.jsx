import React, { useState } from "react";
import { ImCross } from "react-icons/im";
import { Button, message, Drawer, Tag } from "antd";
// import { DownloadOutlined } from "@ant-design/icons";
import {
  DownloadIcon as DownloadOutlined,
  X,
  Shield,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  MapPin,
  Server,
  Database,
  Eye,
  CheckCircle,
} from "lucide-react";
import { notifySuccess } from "../Notification";
import {
  getSeverityColor,
  getSeverityColorBorder,
  getSeverityColorsBasicScan,
} from "../Utils";

export default function TopThreatsCard({ findings }) {
  const [selectedThreat, setSelectedThreat] = useState(null);
  const filteredFindings = findings.filter(
    (f) => f.additional_info?.affected > 0
  );
  // console.log("filtered: ", filteredFindings);
  const [isPaneOpen, setIsPaneOpen] = useState(false);

  const handleCardClick = (finding) => {
    setSelectedThreat(finding);
  };

  const closeModal = () => {
    setIsPaneOpen(false);
    setSelectedThreat(null);
  };

  const exportToJSON = () => {
    const json = JSON.stringify(selectedThreat, null, 2);
    downloadFile("findings.json", json, "application/json");
    notifySuccess("Exported to JSON!");
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

  const uniqueTypes = new Set();
  const sorted = [...filteredFindings]
    .sort((a, b) => b.severity_score - a.severity_score)
    .filter((item) => {
      if (!uniqueTypes.has(item.check_name)) {
        uniqueTypes.add(item.check_name);
        return true;
      }
      return false;
    })
    .slice(0, 4);

  const excludedKeys = ["type", "region", "account_id"];

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
            className={`font-medium ${
              value ? "text-green-600" : "text-red-600"
            }`}
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
        return (
          <span className="text-gray-700 dark:text-gray-300">{value}</span>
        );
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

      return (
        <span className="text-gray-700 dark:text-gray-300">
          {String(value)}
        </span>
      );
    };

    if (!data || typeof data !== "object") {
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
                <div className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-1">
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

  return (
    <div className="bg-white/80 dark:bg-slate-900/80 shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 rounded-2xl min-w-[305px]">
      <div className="flex items-center gap-3 mb-6">
        <div className="bg-gradient-to-r from-indigo-600 to-purple-600 p-2 rounded-xl shadow-lg shadow-red-500/20">
          <AlertTriangle className="w-5 h-5 text-white" />
        </div>
        <h2 className="text-xl font-semibold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
          Top Threats
        </h2>
      </div>

      <div className="grid grid-cols-1 gap-3 mb-4">
        {sorted.map((f, i) => (
          <button
            key={i}
            onClick={() => {
              setIsPaneOpen(true);
              handleCardClick(f);
            }}
            className={`bg-white/60 dark:bg-slate-800/60 backdrop-blur-sm border-l-4 p-4 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105 hover:bg-white/80 dark:hover:bg-slate-800/80 group border-l-${getSeverityColorBorder(
              f.severity_level
            )}`}
          >
            <div className="flex justify-between items-center">
              <span className="text-base text-slate-900 dark:text-white font-medium group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                {f.check_name.replaceAll("_", " ")}
              </span>
              {/* <span
                className={`capitalize font-semibold px-3 py-1 rounded-full text-white text-sm ${getSeverityColor(
                  f.severity_level
                )}`}
              >
                {f.severity_level}
              </span> */}
              <Tag className={getSeverityColor(f.severity_level)}>
                {f.severity_level}
              </Tag>
            </div>
          </button>
        ))}
      </div>

      <Drawer
        title={null}
        placement="right"
        width={600}
        onClose={closeModal}
        open={isPaneOpen}
        className="threat-drawer"
        styles={{
          body: { padding: 0 },
          header: { display: "none" },
          width: "20%",
        }}
      >
        {selectedThreat && (
          <div className="h-full flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b bg-white/95 dark:bg-slate-900/95 backdrop-blur-lg sticky top-0 z-10">
              <div className="flex items-center gap-3">
                {/* <div
                  className={`p-2 rounded-lg ${getSeverityColor(
                    selectedThreat.severity_level
                  )}`}
                >
                  <AlertTriangle className="w-5 h-5 text-white" />
                </div> */}
                <div>
                  <h2 className="text-xl font-semibold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
                    {selectedThreat.check_name.replaceAll("_", " ")}
                  </h2>
                  <div className="flex items-center gap-2 mt-1">
                    <span
                      className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold text-white ${getSeverityColor(
                        selectedThreat.severity_level
                      )}`}
                    >
                      {selectedThreat.severity_level}
                    </span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Button
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                  icon={<DownloadOutlined className="w-4 h-4" />}
                  onClick={exportToJSON}
                >
                  Export to JSON
                </Button>
                <button
                  onClick={closeModal}
                  className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5 text-slate-600 dark:text-slate-400" />
                </button>
              </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto">
              <div className="p-6 space-y-8">
                {/* Overview Section */}
                <div className="bg-gray-50/80 dark:bg-gray-800/80 backdrop-blur-sm rounded-lg p-6 border border-gray-200 dark:border-gray-700">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
                    <Shield className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                    Overview
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                        Threat Type
                      </label>
                      <p className="text-gray-900 dark:text-gray-100 mt-1 font-semibold">
                        {selectedThreat.check_name.replaceAll("_", " ")}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                        Severity Level
                      </label>
                      <div className="mt-1">
                        <span
                          className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold text-white ${getSeverityColor(
                            selectedThreat.severity_level
                          )}`}
                        >
                          {selectedThreat.severity_level}
                        </span>
                      </div>
                    </div>
                    {selectedThreat.severity_score && (
                      <div>
                        <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                          Severity Score
                        </label>
                        <p className="text-gray-900 dark:text-gray-100 mt-1 font-semibold">
                          {selectedThreat.severity_score}/10
                        </p>
                      </div>
                    )}
                    {selectedThreat.region && (
                      <div>
                        <label className="text-sm font-medium text-gray-600 dark:text-gray-400 flex items-center gap-1">
                          <MapPin className="w-4 h-4" />
                          Region
                        </label>
                        <p className="text-gray-900 dark:text-gray-100 mt-1 font-mono">
                          {selectedThreat.region}
                        </p>
                      </div>
                    )}
                    {selectedThreat.resource_id && (
                      <div className="md:col-span-2">
                        <label className="text-sm font-medium text-gray-600 dark:text-gray-400 flex items-center gap-1">
                          <Database className="w-4 h-4" />
                          Resource ID
                        </label>
                        <p className="text-gray-900 dark:text-gray-100 mt-1 font-mono text-sm break-all">
                          {selectedThreat.resource_id}
                        </p>
                      </div>
                    )}
                  </div>
                </div>

                {/* Description Section */}
                {selectedThreat.description && (
                  <div className="bg-blue-50/80 dark:bg-blue-900/20 backdrop-blur-sm border border-blue-200 dark:border-blue-800 rounded-lg p-6">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
                      <Eye className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                      Description
                    </h3>
                    <p className="text-blue-800 dark:text-blue-200">
                      {selectedThreat.description}
                    </p>
                  </div>
                )}

                {/* Remediation Section */}
                {selectedThreat.remediation && (
                  <div className="bg-green-50/80 dark:bg-green-900/20 backdrop-blur-sm border border-green-200 dark:border-green-800 rounded-lg p-6">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
                      <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                      Remediation
                    </h3>
                    <p className="text-green-800 dark:text-green-200">
                      {selectedThreat.remediation}
                    </p>
                  </div>
                )}

                {/* Additional Information */}
                {selectedThreat.additional_info && (
                  <div className="bg-orange-50/80 dark:bg-orange-900/20 backdrop-blur-sm border border-orange-200 dark:border-orange-800 rounded-lg p-6">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                      Additional Information
                    </h3>
                    <JsonRenderer data={selectedThreat.additional_info} />
                  </div>
                )}

                {/* Full Threat Details */}
                <div className="bg-gray-50/80 dark:bg-gray-800/80 backdrop-blur-sm border border-gray-200 dark:border-gray-700 rounded-lg p-6">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
                    <Server className="w-5 h-5 text-gray-600 dark:text-gray-400" />
                    Complete Threat Data
                  </h3>
                  <JsonRenderer data={selectedThreat} />
                </div>
              </div>
            </div>
          </div>
        )}
      </Drawer>
      {/* <pre className="text-xs bg-gray-100 dark:bg-gray-800 text-black dark:text-white p-4 rounded overflow-x-auto whitespace-pre-wrap">
            {JSON.stringify(selectedThreat, null, 2)}
          </pre> */}
      {/* <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded text-sm text-black dark:text-white space-y-2">
            {selectedThreat &&
              Object.entries(selectedThreat).map(([key, value], idx) => (
                <div
                  key={idx}
                  className="flex justify-between border-b border-gray-300 dark:border-gray-700 py-1"
                >
                  <span className="font-semibold capitalize text-gray-700 dark:text-gray-300">
                    {key.replaceAll("_", " ")}
                  </span>
                  <span className="text-right break-words max-w-[60%] text-gray-900 dark:text-white">
                    {typeof value === "object"
                      ? JSON.stringify(value, null, 1)
                      : value?.toString()}
                  </span>
                </div>
              ))}
          </div> */}
    </div>
  );
}
