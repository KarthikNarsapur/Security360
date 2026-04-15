import { useState } from "react";
import { Drawer, Tag, theme } from "antd";
import {
  X,
  Shield,
  CheckCircle,
  XCircle,
  AlertTriangle,
  HelpCircle,
  Calendar,
  MapPin,
  Server,
  Database,
  Eye,
  ChevronRight,
  ChevronDown,
} from "lucide-react";
import { getStatusColor, getSeverityColor } from "../Utils";

export default function FindingsDetailsPopup({ selected, onClose }) {
  if (!selected) return null;
   const { token } = theme.useToken();

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
                    <div className="text-sm">
                      {typeof item === "object" && item !== null ? (
                        <JsonRenderer data={item} level={currentLevel + 1} />
                      ) : (
                        renderValue(
                          `${uniqueKey}-${index}`,
                          item,
                          currentLevel + 1
                        )
                      )}
                    </div>
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
    <Drawer
      title={
        <div className="flex items-center justify-between p-6 border-b bg-white/95 dark:bg-slate-900/95 backdrop-blur-lg sticky top-0 z-10">
          <div className="flex items-center gap-3">
            <div>
              <h2 className="text-xl font-semibold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
                {selected.type
                  ? selected.check_name.replaceAll("_", " ")
                  : "Finding Details"}
              </h2>
              <div className="flex items-center gap-2 mt-1">
                {selected.id && (
                  <span className="font-mono text-sm text-gray-600 dark:text-gray-400">
                    {selected.id}
                  </span>
                )}
                {selected.severity_level && (
                  <Tag className={getSeverityColor(selected.severity_level)}>
                    {selected.severity_level}
                  </Tag>
                )}
                {selected.status && (
                  <Tag className={getStatusColor(selected.status)}>
                    {selected.status === "partially_failed"
                      ? "Partially Failed"
                      : selected.status.charAt(0).toUpperCase() +
                        selected.status.slice(1)}
                  </Tag>
                )}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-slate-600 dark:text-slate-400" />
          </button>
        </div>
      }
      placement="right"
      width={600}
      onClose={onClose}
      closable={false}
      open={true}
      className="finding-drawer"
      styles={{
        body: { padding: 0 },
        wrapper: {
          borderLeft: `2px solid ${token.drawerBorderColor}`,
        },
      }}
    >
      <div className="h-full flex flex-col">
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
                {selected.type && (
                  <div>
                    <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                      Finding Type
                    </label>
                    <p className="text-gray-900 dark:text-gray-100 mt-1 font-semibold">
                      {selected.check_name.replaceAll("_", " ")}
                    </p>
                  </div>
                )}
                {selected.severity_level && (
                  <div>
                    <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                      Severity Level
                    </label>
                    <div className="mt-1">
                      <Tag
                        className={getSeverityColor(selected.severity_level)}
                      >
                        {selected.severity_level}
                      </Tag>
                    </div>
                  </div>
                )}
                {selected.severity_score && (
                  <div>
                    <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                      Severity Score
                    </label>
                    <p className="text-gray-900 dark:text-gray-100 mt-1 font-semibold">
                      {selected.severity_score}/100
                    </p>
                  </div>
                )}
                {selected.region && (
                  <div>
                    <label className="text-sm font-medium text-gray-600 dark:text-gray-400 flex items-center gap-1">
                      <MapPin className="w-4 h-4" />
                      Region
                    </label>
                    <p className="text-gray-900 dark:text-gray-100 mt-1 font-mono">
                      {selected.region}
                    </p>
                  </div>
                )}
                {selected.resource_id && (
                  <div className="md:col-span-2">
                    <label className="text-sm font-medium text-gray-600 dark:text-gray-400 flex items-center gap-1">
                      <Database className="w-4 h-4" />
                      Resource ID
                    </label>
                    <p className="text-gray-900 dark:text-gray-100 mt-1 font-mono text-sm break-all">
                      {selected.resource_id}
                    </p>
                  </div>
                )}
                {selected.account_id && (
                  <div>
                    <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                      Account ID
                    </label>
                    <p className="text-gray-900 dark:text-gray-100 mt-1 font-mono">
                      {selected.account_id}
                    </p>
                  </div>
                )}
                {selected.last_updated && (
                  <div>
                    <label className="text-sm font-medium text-gray-600 dark:text-gray-400 flex items-center gap-1">
                      <Calendar className="w-4 h-4" />
                      Last Updated
                    </label>
                    <p className="text-gray-900 dark:text-gray-100 mt-1">
                      {new Date(selected.last_updated).toLocaleString()}
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Description Section */}
            {selected.description && (
              <div className="bg-blue-50/80 dark:bg-blue-900/20 backdrop-blur-sm border border-blue-200 dark:border-blue-800 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
                  <Eye className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  Description
                </h3>
                <p className="text-blue-800 dark:text-blue-200">
                  {selected.description}
                </p>
              </div>
            )}

            {/* Problem Statement Section */}
            {selected.problem_statement && (
              <div className="bg-orange-50/80 dark:bg-orange-900/20 backdrop-blur-sm border border-orange-200 dark:border-orange-800 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                  Problem Statement
                </h3>
                <p className="text-orange-800 dark:text-orange-200">
                  {selected.problem_statement}
                </p>
              </div>
            )}

            {/* Recommendation Section */}
            {selected.recommendation && (
              <div className="bg-green-50/80 dark:bg-green-900/20 backdrop-blur-sm border border-green-200 dark:border-green-800 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
                  <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
                  Recommendation
                </h3>
                <p className="text-green-800 dark:text-green-200">
                  {selected.recommendation}
                </p>
              </div>
            )}

            {/* Remediation Steps */}
            {selected.remediation_steps &&
              selected.remediation_steps.length > 0 && (
                <div className="bg-yellow-50/80 dark:bg-yellow-900/20 backdrop-blur-sm border border-yellow-200 dark:border-yellow-800 rounded-lg p-6">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
                    Remediation Steps
                  </h3>
                  <ol className="space-y-2">
                    {selected.remediation_steps.map((step, index) => (
                      <li
                        key={index}
                        className="text-yellow-800 dark:text-yellow-200 flex gap-3"
                      >
                        <span className="font-medium text-yellow-600 dark:text-yellow-400 min-w-[1.5rem]">
                          {index + 1}.
                        </span>
                        <span>{step.replace(/^\d+\.\s*/, "")}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              )}

            {/* Affected Resources */}
            {selected.resources_affected &&
              selected.resources_affected.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-red-600 mb-4 flex items-center gap-2">
                    <Server className="w-5 h-5 text-red-500" />
                    Affected Resources ({selected.resources_affected.length})
                  </h3>
                  <div className="space-y-4">
                    {selected.resources_affected.map((resource, index) => (
                      <div
                        key={index}
                        className="bg-red-50/80 dark:bg-red-900/20 backdrop-blur-sm border border-red-200 dark:border-red-800 rounded-lg p-6"
                      >
                        <div className="flex items-start justify-between mb-4">
                          <div>
                            <h4 className="font-semibold text-red-900 dark:text-red-100 flex items-center gap-2">
                              <Database className="w-4 h-4" />
                              {resource.resource_id || `Resource ${index + 1}`}
                            </h4>
                            {resource.region && (
                              <p className="text-sm text-red-700 dark:text-red-300 flex items-center gap-1 mt-1">
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
                        <div className="border-t border-red-200 dark:border-red-700 pt-4">
                          <h5 className="font-medium text-red-900 dark:text-red-100 mb-3">
                            Resource Details
                          </h5>
                          <JsonRenderer data={resource} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            {/* Additional Information */}
            {selected.additional_info && (
              <div className="bg-indigo-50/80 dark:bg-indigo-900/20 backdrop-blur-sm border border-indigo-200 dark:border-indigo-800 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
                  <HelpCircle className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                  Additional Information
                </h3>
                <JsonRenderer data={selected.additional_info} />
              </div>
            )}

            {/* Complete Finding Data */}
            {/* <div className="bg-gray-50/80 dark:bg-gray-800/80 backdrop-blur-sm border border-gray-200 dark:border-gray-700 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
                <Server className="w-5 h-5 text-gray-600 dark:text-gray-400" />
                Complete Finding Data
              </h3>
              <JsonRenderer data={selected} />
            </div> */}
          </div>
        </div>
      </div>
    </Drawer>
  );
}
