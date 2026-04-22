import { useEffect, useState } from "react";
import FindingsTable from "../../UI/FindingsTable";
import FindingsDetailsPopup from "../../UI/FindingsDetailsPopup";
import { User, Clock } from "lucide-react";
import {
  GetSampleReportNote,
  NoDataAvailableMessageComponent,
  fetchUserDetails,
} from "../../Utils";
import { useNavigate } from "react-router-dom";

const AzureFindings = ({
  results,
  meta,
  accountDetails,
  modal,
  darkMode,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) => {
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [isSummaryScanSampleReport] = useState(false);
  const [isSampleReport, setIsSampleReport] = useState(false);
  const navigate = useNavigate();

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

  const fullName = localStorage.getItem("full_name") || "";

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="p-6 pl-12">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="mb-8">
            <div className="mt-2 flex items-center justify-between">
              <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent flex items-center gap-3">
                Azure Findings Table
              </h1>
            </div>

            {/* Metadata */}
            {meta?.account_id && meta?.timestamp && (
              <div className="mt-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-blue-100 dark:border-slate-700">
                <div className="flex items-center gap-6 text-sm text-slate-600 dark:text-slate-400">
                  <div className="flex items-center gap-2">
                    <User className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                    <span className="font-medium">Subscription ID:</span>
                    <span className="font-mono text-slate-900 dark:text-white">
                      {meta.account_id || "N/A"}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                    <span className="font-medium">Last Scanned:</span>
                    <span className="text-slate-900 dark:text-white">
                      {meta.timestamp
                        ? new Date(
                            meta.timestamp.replace("Z", "")
                          ).toLocaleString("en-GB", { hour12: true })
                        : "N/A"}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {isSummaryScanSampleReport && <GetSampleReportNote />}

          {/* Findings Table */}
          {results.length ? (
            <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 border border-blue-100 dark:border-slate-700">
              <div className="p-6 border-b border-blue-100 dark:border-slate-700">
                <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
                  Security Findings
                </h2>
              </div>
              <div>
                <FindingsTable
                  findings={results}
                  onSelect={setSelectedFinding}
                  meta={meta}
                  fullName={fullName}
                  securityServicesScanResults={[]}
                  globalServicesScanResults={{}}
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
                "No data available.",
                "Run a scan from the Azure Summary page to view security findings for your Azure subscriptions.",
              ]}
            />
          )}

          {/* Findings Details Popup */}
          {selectedFinding && (
            <FindingsDetailsPopup
              selected={selectedFinding}
              onClose={() => setSelectedFinding(null)}
            />
          )}
        </div>
      </div>
    </div>
  );
};

export default AzureFindings;
