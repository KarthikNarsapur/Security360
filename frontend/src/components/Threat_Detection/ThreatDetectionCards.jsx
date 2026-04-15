import React from "react";
import { Tag, Popconfirm, Drawer } from "antd";
import {
  EyeOff,
  X,
  Shield,
  Server,
  CheckCircle,
  User,
  Clock,
} from "lucide-react";

import { LoadingSkeletonThreatDetection } from "../LoadingSkeleton";
import {
  GetSampleReportNote,
  NoDataAvailableMessageComponent,
  getSeverityColor,
} from "../Utils";

const ThreatDetectionCards = ({
  lastScannedDetails,
  loading,
  s3FetchLoading,
  filteredCombinedFindings,
  isThreatDetectionSampleReport,
  hiddenFindings,
  handleHideFinding,
  handleCardClick,
  showModal,
  closeModal,
  selectedFinding,
  token,
}) => {
  return (
    <div>
      {/* last scanned details */}
      {lastScannedDetails && (
        <div className="mb-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-indigo-100 dark:border-slate-700">
          <div className="flex items-center gap-6 text-sm text-slate-600 dark:text-slate-400">
            <div className="flex items-center gap-2">
              <User className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
              <span className="font-medium">Account ID:</span>
              <span className="font-mono text-slate-900 dark:text-white">
                {lastScannedDetails?.account_id || "Not available"}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
              <span className="font-medium">Last Scanned:</span>
              <span className="text-slate-900 dark:text-white">
                {lastScannedDetails?.timestamp
                  ? new Date(
                      lastScannedDetails.timestamp.replace("Z", "")
                    ).toLocaleString("en-GB", {
                      hour12: true,
                    })
                  : "Not available"}
              </span>
            </div>
          </div>
        </div>
      )}

      {(loading || s3FetchLoading) && <LoadingSkeletonThreatDetection />}

      {!loading &&
        !s3FetchLoading &&
        (filteredCombinedFindings.length ? (
          <div>
            {isThreatDetectionSampleReport && <GetSampleReportNote />}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredCombinedFindings &&
                filteredCombinedFindings.map((finding, index) => (
                  <div
                    key={index}
                    className={`bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 cursor-pointer transition-all duration-200 hover:scale-105 hover:shadow-2xl border-l-4 ${
                      finding?.severity?.toLowerCase() === "critical"
                        ? "border-l-red-600 dark:border-l-red-600"
                        : finding?.severity?.toLowerCase() === "high"
                        ? "border-l-orange-500 dark:border-l-orange-500"
                        : finding?.severity?.toLowerCase() === "medium"
                        ? "border-l-yellow-500 dark:border-l-yellow-500"
                        : finding?.severity?.toLowerCase() === "low"
                        ? "border-l-green-500 dark:border-l-green-500"
                        : "border-l-gray-500 dark:border-l-gray-500"
                    } ${hiddenFindings.includes(index) ? "hidden" : ""} `}
                    onClick={() => handleCardClick(finding)}
                  >
                    <div className="absolute top-4 right-4 z-10">
                      <Popconfirm
                        title="Are you sure you want to hide this finding?"
                        onConfirm={(e) =>
                          handleHideFinding(e, finding?.finding_title)
                        }
                        okText="Yes"
                        cancelText="No"
                        onCancel={(e) => e.stopPropagation()}
                      >
                        <button
                          className="p-2 dark:text-white rounded-lg text-xs hover:text-blue-500 dark:hover:text-blue-500 transition-colors"
                          title="Hide"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <EyeOff className="w-4 h-4" />
                        </button>
                      </Popconfirm>
                      {/* <button
                        onClick={(e) =>
                          handleHideFinding(e, finding?.finding_title)
                        }
                        className="p-2 dark:text-white rounded-lg text-xs hover:text-blue-500 dark:hover:text-blue-500 transition-colors"
                        title="Hide"
                      >
                        <EyeOff className="w-4 h-4" />
                      </button> */}
                    </div>

                    <div className="space-y-4">
                      {finding?.finding_title && (
                        <h3 className="text-lg font-semibold text-slate-900 dark:text-white pr-16">
                          {finding.finding_title}
                        </h3>
                      )}

                      <div className="space-y-3">
                        {finding?.riskScore && (
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium text-slate-600 dark:text-slate-400">
                              Risk Score:
                            </span>
                            <span className="text-sm font-bold text-slate-900 dark:text-white">
                              {finding.riskScore}
                            </span>
                          </div>
                        )}

                        {finding?.severity && (
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium text-slate-600 dark:text-slate-400">
                              Severity:
                            </span>
                            <Tag className={getSeverityColor(finding.severity)}>
                              {finding.severity}
                            </Tag>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        ) : (
          <NoDataAvailableMessageComponent
            messages={[
              "No data available",
              "Select accounts and regions, then click 'Run Scan' to scan your AWS accounts.",
              "If no accounts appear in the dropdown, please add them from the Home page of Infra Scan.",
            ]}
          />
        ))}

      <Drawer
        title={
          <div className="flex items-center justify-between p-6 border-b bg-white sticky top-0 z-10">
            <div className="flex items-center gap-3">
              <div>
                <h2 className="text-xl font-semibold text-gray-900">
                  {selectedFinding?.finding_title || "Threat Finding"}
                </h2>
                <div className="flex items-center gap-2 mt-1">
                  {selectedFinding?.findingId && (
                    <span className="font-mono text-sm text-gray-600">
                      {selectedFinding.findingId}
                    </span>
                  )}
                  {selectedFinding?.severity && (
                    <Tag className={getSeverityColor(selectedFinding.severity)}>
                      {selectedFinding.severity}
                    </Tag>
                  )}
                </div>
              </div>
            </div>
            <button
              onClick={closeModal}
              className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        }
        placement="right"
        width={600}
        onClose={closeModal}
        open={showModal}
        closable={false}
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
            <div className="flex-1 overflow-y-auto p-6 space-y-8">
              <div className="bg-gray-50 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  <Shield className="w-5 h-5" />
                  Overview
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {selectedFinding?.riskScore && (
                    <div>
                      <label className="text-sm font-medium text-gray-600">
                        Risk Score
                      </label>
                      <p className="text-gray-900 mt-1 font-semibold">
                        {selectedFinding.riskScore} / 10
                      </p>
                    </div>
                  )}
                  {selectedFinding?.severity && (
                    <div>
                      <label className="text-sm font-medium text-gray-600">
                        Severity Level
                      </label>
                      <div className="mt-1">
                        <Tag
                          className={getSeverityColor(selectedFinding.severity)}
                        >
                          {selectedFinding.severity}
                        </Tag>
                      </div>
                    </div>
                  )}
                  {selectedFinding?.problem_statement && (
                    <div className="md:col-span-2">
                      <label className="text-sm font-medium text-gray-600">
                        Problem Statement
                      </label>
                      <p className="text-gray-900 mt-1">
                        {selectedFinding.problem_statement}
                      </p>
                    </div>
                  )}
                </div>
              </div>

              {Array.isArray(selectedFinding?.affected_resources) &&
                selectedFinding.affected_resources.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                      <Server className="w-5 h-5 text-red-500" />
                      Affected Resources (
                      {selectedFinding.affected_resources.length})
                    </h3>
                    <div className="space-y-4">
                      {selectedFinding.affected_resources.map(
                        (resource, index) => (
                          <div
                            key={index}
                            className="bg-red-50 border border-red-200 rounded-lg p-6"
                          >
                            <div className="flex items-start justify-between mb-4">
                              <div>
                                <h4 className="font-semibold text-red-900 flex items-center gap-2">
                                  <Server className="w-4 h-4" />
                                  {resource.resource_type ||
                                    resource.service ||
                                    resource.type ||
                                    `Resource ${index + 1}`}
                                </h4>
                              </div>
                            </div>
                            <div className="space-y-2">
                              {Object.entries(resource).map(
                                ([key, value]) =>
                                  key !== "resource_type" &&
                                  key !== "service" &&
                                  key !== "type" &&
                                  value && (
                                    <div
                                      key={key}
                                      className="flex justify-between"
                                    >
                                      <span className="font-medium text-red-800">
                                        {key.charAt(0).toUpperCase() +
                                          key.slice(1).replace("_", " ")}
                                        :
                                      </span>
                                      <span className="text-red-700">
                                        {value}
                                      </span>
                                    </div>
                                  )
                              )}
                            </div>
                          </div>
                        )
                      )}
                    </div>
                  </div>
                )}

              {selectedFinding?.steps_to_resolve &&
                selectedFinding.steps_to_resolve.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                      <CheckCircle className="w-5 h-5 text-green-500" />
                      Steps to Resolve
                    </h3>
                    <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                      <ol className="space-y-2">
                        {selectedFinding.steps_to_resolve.map((step, index) => (
                          <li key={index} className="text-green-800 flex gap-3">
                            <span className="font-medium text-green-600 min-w-[1.5rem]">
                              {index + 1}.
                            </span>
                            <span>{step}</span>
                          </li>
                        ))}
                      </ol>
                    </div>
                  </div>
                )}
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};

export default ThreatDetectionCards;
