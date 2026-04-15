import React from "react";
import FindingsTable from "../components/UI/FindingsTable";
import FindingsDetailsPopup from "./UI/FindingsDetailsPopup";
import { User, Clock, Search } from "lucide-react";
import { GetSampleReportNote, NoDataAvailableMessageComponent } from "./Utils";
import { fetchUserDetails } from "./Utils";
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

const FindingsComponent = ({
  findings,
  selectedFinding,
  onSelect,
  onClose,
  meta,
  fullName,
  securityServicesScanResults,
  globalServicesScanResults,
  modal,
  darkMode,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
  isSummaryScanSampleReport,
  setIsSummaryScanSampleReport,
  isSampleReport,
  setIsSampleReport,
}) => {
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
  // console.log("meta: ", meta);
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="p-6 pl-12">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="mb-8">
            <div className="mt-2 flex items-center justify-between">
              <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent flex items-center gap-3">
                Findings Table
              </h1>
            </div>

            {/* Metadata */}
            {meta.account_id && meta.timestamp && (
              <div className="mt-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-indigo-100 dark:border-slate-700">
                <div className="flex items-center gap-6 text-sm text-slate-600 dark:text-slate-400">
                  <div className="flex items-center gap-2">
                    <User className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                    <span className="font-medium">Account ID:</span>
                    <span className="font-mono text-slate-900 dark:text-white">
                      {meta.account_id ? meta.account_id : "N/A"}
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
          </div>

          {isSummaryScanSampleReport && <GetSampleReportNote />}

          {/* Findings Table */}
          {findings.length ? (
            <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 border border-indigo-100 dark:border-slate-700">
              <div className="p-6 border-b border-indigo-100 dark:border-slate-700">
                <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
                  Security Findings
                </h2>
              </div>
              <div className="">
                <FindingsTable
                  findings={findings}
                  onSelect={onSelect}
                  meta={meta}
                  fullName={fullName}
                  securityServicesScanResults={securityServicesScanResults}
                  globalServicesScanResults={globalServicesScanResults}
                  modal={modal}
                  darkMode={darkMode}
                  isSampleReport={isSampleReport}
                  setIsSampleReport={setIsSampleReport}
                />
              </div>
            </div>
          ) : (
            <NoDataAvailableMessageComponent
              messages={[
                "No data available",
                "Run a scan from the summary page to view the security findings for your AWS account.",
              ]}
            />
          )}

          {/* Findings Details Popup */}
          {selectedFinding && (
            <FindingsDetailsPopup
              selected={selectedFinding}
              onClose={onClose}
            />
          )}
        </div>
      </div>
    </div>
  );
};

export default FindingsComponent;
