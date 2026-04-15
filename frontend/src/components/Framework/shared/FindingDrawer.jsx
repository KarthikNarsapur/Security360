// components/Framework/shared/FindingDrawer.jsx
import { Drawer, Tag, theme } from "antd";
import {
  Shield,
  CheckCircle,
  AlertTriangle,
  HelpCircle,
  Server,
  Database,
  MapPin,
  X,
} from "lucide-react";
import JsonRenderer from "./JsonRenderer";
import { getSeverityColor } from "../../../utils/frameworkUtils";

/**
 * Reusable finding detail drawer — same layout as CIS drawer but
 * extracted as a standalone component and works for any framework.
 *
 * Props:
 *   open      — boolean
 *   onClose   — fn()
 *   finding   — table row object (contains fullData)
 *   regionLabel — override label for region column (default "Region", OWASP uses "URL")
 */
const FindingDrawer = ({ open, onClose, finding, regionLabel = "Region" }) => {
  const { token } = theme.useToken();

  if (!finding) return null;
  const rule = finding.fullData;

  return (
    <Drawer
      title={
        <div className="flex items-center justify-between p-6 border-b bg-white sticky top-0 z-10">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">
              {finding.check_name}
            </h2>
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              {finding.id && (
                <span className="font-mono text-sm text-gray-500">
                  {finding.id}
                </span>
              )}
              {finding.service && (
                <span className="text-xs bg-indigo-50 text-indigo-700 px-2 py-0.5 rounded-full border border-indigo-100">
                  {finding.service}
                </span>
              )}
              <Tag className={getSeverityColor(finding.severity_level)}>
                {finding.severity_level}
              </Tag>
              {finding.framework && (
                <span className="text-xs bg-purple-50 text-purple-700 px-2 py-0.5 rounded-full border border-purple-100">
                  {finding.framework}
                </span>
              )}
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors ml-4 flex-shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      }
      placement="right"
      width={600}
      closable={false}
      onClose={onClose}
      open={open}
      styles={{
        body: { padding: 0 },
        wrapper: { borderLeft: `2px solid ${token.colorBorderSecondary}` },
      }}
    >
      <div className="h-full flex flex-col">
        <div className="flex-1 overflow-y-auto">
          {rule ? (
            <div className="p-6 space-y-8">
              {/* Overview */}
              <div className="bg-gray-50 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  <Shield className="w-5 h-5" /> Overview
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label className="text-sm font-medium text-gray-600">
                      Problem Statement
                    </label>
                    <p className="text-gray-900 mt-1">
                      {rule.problem_statement}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-600">
                      Severity Score
                    </label>
                    <div className="flex items-center gap-2 mt-1">
                      <div className="flex-1 bg-gray-200 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${
                            rule.severity_score >= 90
                              ? "bg-red-500"
                              : rule.severity_score >= 70
                                ? "bg-orange-500"
                                : rule.severity_score >= 50
                                  ? "bg-yellow-500"
                                  : "bg-blue-500"
                          }`}
                          style={{ width: `${rule.severity_score}%` }}
                        />
                      </div>
                      <span className="text-sm font-semibold text-gray-900">
                        {rule.severity_score}/100
                      </span>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-600">
                      Total Scanned
                    </label>
                    <p className="text-gray-900 mt-1">
                      {finding.total_scanned}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-600">
                      Affected Resources
                    </label>
                    <p
                      className={`mt-1 font-semibold ${finding.affected > 0 ? "text-red-600" : "text-green-600"}`}
                    >
                      {finding.affected}
                    </p>
                  </div>
                  {rule.control_id && (
                    <div>
                      <label className="text-sm font-medium text-gray-600">
                        Control ID
                      </label>
                      <p className="text-gray-900 mt-1 font-mono text-indigo-700">
                        {rule.control_id}
                      </p>
                    </div>
                  )}
                  {finding.region && finding.region !== "global" && (
                    <div>
                      <label className="text-sm font-medium text-gray-600 flex items-center gap-1">
                        <MapPin className="w-3 h-3" /> {regionLabel}
                      </label>
                      <p className="text-gray-900 mt-1 font-mono text-sm">
                        {finding.region}
                      </p>
                    </div>
                  )}
                </div>
              </div>

              {/* Affected Resources */}
              {rule.resources_affected?.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                    <Server className="w-5 h-5 text-red-500" />
                    Affected Resources ({rule.resources_affected.length})
                  </h3>
                  <div className="space-y-4">
                    {rule.resources_affected.map((resource, index) => (
                      <div
                        key={index}
                        className="bg-red-50 border border-red-200 rounded-lg p-6"
                      >
                        <div className="flex items-start justify-between mb-4">
                          <h4 className="font-semibold text-red-900 flex items-center gap-2">
                            <Database className="w-4 h-4" />
                            {resource.resource_name ||
                              resource.resource_id ||
                              `Resource ${index + 1}`}
                          </h4>
                        </div>
                        <div className="border-t border-red-200 pt-4">
                          <JsonRenderer data={resource} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendation */}
              {rule.recommendation && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-green-500" />{" "}
                    Recommendation
                  </h3>
                  <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                    <p className="text-green-800">{rule.recommendation}</p>
                  </div>
                </div>
              )}

              {/* Remediation Steps */}
              {rule.remediation_steps?.length > 0 && finding.affected > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5 text-orange-500" />{" "}
                    Remediation Steps
                  </h3>
                  <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                    <ol className="space-y-2">
                      {rule.remediation_steps.map((step, index) => (
                        <li key={index} className="text-orange-800 flex gap-3">
                          <span className="font-medium text-orange-600 min-w-[1.5rem]">
                            {index + 1}.
                          </span>
                          <span>{step.replace(/^\d+\.\s*/, "")}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                </div>
              )}

              {/* Additional Info */}
              {rule.additional_info && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                    <HelpCircle className="w-5 h-5 text-blue-500" /> Additional
                    Information
                  </h3>
                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                    <JsonRenderer data={rule.additional_info} />
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-6 text-center text-gray-500">
              <HelpCircle className="w-12 h-12 mx-auto mb-4 text-gray-400" />
              <p>No detailed information available for this finding.</p>
            </div>
          )}
        </div>
      </div>
    </Drawer>
  );
};

export default FindingDrawer;
