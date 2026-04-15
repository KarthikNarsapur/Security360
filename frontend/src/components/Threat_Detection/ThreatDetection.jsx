import React, { useEffect, useState } from "react";
import { Button, Drawer, Tag, Popconfirm, theme, Modal, Input } from "antd";
import { LoadingSkeletonThreatDetection } from "../LoadingSkeleton";
import {
  notifySuccess,
  notifyError,
  notifyInfo,
  notifyRedirectToContact,
} from "../Notification";
import RegionDropdown from "../UI/DropDown/RegionDropdown";
import Spinner from "../UI/Spinner";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  Play,
  User,
  Clock,
  CheckCircle,
  EyeOff,
  X,
  Server,
} from "lucide-react";
import {
  getStatusColor,
  getStatusIcon,
  getSeverityColor,
  getSeverityIcon,
  GetNote,
  NoDataAvailableMessageComponent,
  fetchUserDetails,
  GetSampleReportNote,
} from "../Utils";
import { LuNotebookPen } from "react-icons/lu";
import AccountDropdown from "../UI/DropDown/AccountDropdown";
import Cookies from "js-cookie";
import ScanTypeDropdown from "../UI/DropDown/ScanTypeDropdown";
import ThreatDetectionCards from "./ThreatDetectionCards";
import VpcFlowLogModal from "./VpcFlowLogModal";

function ThreatDetection({
  accountDetails,
  modal,
  darkMode,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) {
  const [showModal, setShowModal] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [combinedFindings, setCombinedFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [s3FetchLoading, setS3FetchLoading] = useState(false);
  const [isfetched, setIsFetched] = useState(false);
  const [lastScannedDetails, setLastScannedDetails] = useState(null);
  const [isErrorDisplayed, setIsErrorDisplayed] = useState(false);
  const [selectedRegions, setSelectedRegions] = useState([]);
  const [selectedAccounts, setSelectedAccounts] = useState([]);
  const [selectedReportAccount, setSelectedReportAccount] = useState([]); //for report account
  const [selectedScanTypes, setSelectedScanTypes] = useState([]);
  const [selectedReportScanTypes, setSelectedReportScanTypes] = useState([]); //for report account
  const [showVpcLogModal, setShowVpcLogModal] = useState(false);
  const [vpcFlowLogNames, setVpcFlowLogNames] = useState({});
  const [optionsMap, setOptionsMap] = useState({});

  const [isThreatDetectionSampleReport, setIsThreatDetectionSampleReport] =
    useState(false);
  const [hiddenFindings, setHiddenFindings] = useState(() => {
    const saved = localStorage.getItem("hiddenThreatDetection");
    return saved ? JSON.parse(saved) : [];
  });
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

  useEffect(() => {
    localStorage.setItem(
      "hiddenThreatDetection",
      JSON.stringify(hiddenFindings)
    );
  }, [hiddenFindings]);

  const handleHideFinding = (e, findingId) => {
    e.stopPropagation();
    setHiddenFindings((prev) => [...prev, findingId]);
    notifySuccess("Finding hidden successfully");
  };

  let findings = [];
  let prevVPCFlowLogsFindings = [];
  let prevCloudtrailLogsFindings = [];

  const handleCardClick = (finding) => {
    setSelectedFinding(finding);
    setShowModal(true);
  };

  const closeModal = () => {
    setShowModal(false);
    setSelectedFinding(null);
  };

  const handleRegionChange = (regions) => {
    setSelectedRegions(regions);
  };

  const handleAccountChange = (accounts) => {
    setSelectedAccounts(accounts);
  };

  const areAllVpcNamesFilled = () => {
    for (const acc of selectedAccounts) {
      const parsedAcc = JSON.parse(acc);
      for (const region of selectedRegions) {
        if (!vpcFlowLogNames?.[parsedAcc.account_id]?.[region]) return false;
      }
    }
    return true;
  };

  const handleReportAccountChange = async (
    accounts,
    isSample = false,
    scanTypes = selectedReportScanTypes
  ) => {
    const previousValue = selectedReportAccount;
    const scanTypePreviousValue = selectedReportScanTypes;
    // console.log("selected scan type: ", selectedReportScanTypes);
    if (!isSample) {
      setSelectedReportAccount(accounts);
      setSelectedReportScanTypes(scanTypes);
      if (!scanTypes || scanTypes.length === 0) {
        notifyError("Select at least one scan type to view report");
        return;
      }
      if (!accounts || accounts.length == 0) {
        notifyError("Select at least one account to view report");
        return;
      }
    }

    const backend_url = process.env.REACT_APP_BACKEND_URL;
    // console.log("accounts: ", accounts);

    try {
      setS3FetchLoading(true);
      setIsThreatDetectionSampleReport(isSample);

      const parsedAccount = isSample ? {} : JSON.parse(accounts || "{}");
      const payload = {
        account_id: parsedAccount.account_id || "",
        username: localStorage.getItem("username"),
        type: "threat_detection",
        threat_detection_scan_type: scanTypes,
        is_sample: isSample,
      };

      // Call backend API to get report for selected account
      const response = await fetch(`${backend_url}/api/get-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const apiResponse = await response.json();

      if (apiResponse?.status === "ok") {
        isSample && setSelectedReportAccount();

        const data = apiResponse.data || {};
        // console.log("data: ", data);
        let allError = true;
        let passedScanTypes = [];
        for (const scanType of scanTypes) {
          const finding =
            scanType === "vpc"
              ? data?.VPC_flow_logs_findings
              : data?.cloudtrail_logs_findings;

          // console.log("finding: ", finding);

          if (finding?.status === "error") {
            notifyError(finding?.error_message);
          } else {
            allError = false;
            passedScanTypes.push(scanType);
          }
        }
        // console.log("passed: ", passedScanTypes);
        setSelectedReportScanTypes(passedScanTypes);
        if (allError) {
          console.log("allerror: ", allError);
          setSelectedReportAccount(previousValue);
          // setSelectedReportScanTypes(scanTypePreviousValue);
          setIsThreatDetectionSampleReport(false);
        }

        // Extract findings
        const vpcFlowLogs = data.VPC_flow_logs_findings?.results || [];
        const cloudtrailLogs = data.cloudtrail_logs_findings?.results || [];

        setCombinedFindings([...vpcFlowLogs, ...cloudtrailLogs]);

        setLastScannedDetails({
          timestamp:
            data.cloudtrail_logs_findings?.timestamp ||
            data.VPC_flow_logs_findings?.timestamp ||
            "",
          account_id:
            data.cloudtrail_logs_findings?.account_id ||
            data.VPC_flow_logs_findings?.account_id ||
            "",
        });
      } else {
        notifyError(apiResponse?.error_message || "Failed to get report");
        setSelectedReportAccount(previousValue);
        setIsThreatDetectionSampleReport(false);
      }
    } catch (err) {
      console.error("Failed to get report:", err);
      // notifyError("Failed to get report");
      setSelectedReportAccount(previousValue);
      setIsThreatDetectionSampleReport(false);
    } finally {
      setS3FetchLoading(false);
    }
  };

  // ------------ scan --------------
  const handleScan = async (trigger = "run_scan") => {
    const access_token = Cookies.get("access_token");

    const backend_url = process.env.REACT_APP_BACKEND_URL;

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
      vpcFlowLogNames: vpcFlowLogNames || {},
    };

    if (!access_token || !payload.username) {
      notifyInfo("Session expired, login again..");
      navigate("/login");
    }
    if (!selectedScanTypes || selectedScanTypes.length === 0) {
      notifyError("Please select at least Scan Type");
      return;
    }
    if (!payload.accounts || payload.accounts.length === 0) {
      notifyError("Please select at least one account");
      return;
    }
    if (!payload.regions || payload.regions.length === 0) {
      notifyError("Please select at least one region");
      return;
    }
    // if (!payload.start_date || !payload.end_date) {
    //   notifyError("Please select a date range");
    //   setLoading(false);
    //   return;
    // }
    if (selectedScanTypes.includes("vpc") && trigger == "run_scan") {
      setShowVpcLogModal(true);
      return;
    }

    try {
      setLoading(true);
      findings = [];

      for (const scanType of selectedScanTypes) {
        // if vpc selected, ensure we have names before proceeding
        const response = await fetch(
          `${backend_url}/api/scan${scanType.toLowerCase()}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          }
        );
        const result = await response.json();
        if (result?.status === "ok") {
          setSelectedRegions([]);
          setSelectedAccounts([]);

          if (Array.isArray(result.notifications?.success)) {
            result.notifications.success.forEach((msg) => notifySuccess(msg));
          }
          if (Array.isArray(result.notifications?.error)) {
            result.notifications.error.forEach((msg) => notifyError(msg));
          }

          findings = [...findings, ...(result?.findings || [])];
        } else {
          console.log(`Error in ${scanType} finding`);
          if (result?.error_message) {
            notifyError(result.error_message);
          }
          if (result?.fail_type || "" === "contact_us") {
            notifyRedirectToContact(navigate, 5);
          }
        }
      }
      setCombinedFindings(findings);
    } catch (err) {
      console.log("Failed to load report: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const filteredCombinedFindings = combinedFindings.filter(
    (f) => !hiddenFindings.includes(f.finding_title)
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="p-6 pl-12">
        <div className="max-w-7xl mx-auto">
          <div className="mb-8">
            <div className="mt-2 flex items-center justify-between">
              <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent flex items-center gap-3">
                {/* <Shield className="w-8 h-8 text-indigo-600" /> */}
                Inteligent Threat Detection
              </h1>
              <div className="flex items-center gap-4">
                {/* scan type dropdown */}
                <div className="w-40">
                  <ScanTypeDropdown
                    onScanTypeChange={setSelectedScanTypes}
                    selectedScanTypes={selectedScanTypes}
                    disabled={loading}
                  />
                </div>
                {/* account dropdown */}
                <div className="w-60">
                  <AccountDropdown
                    onAccountChange={handleAccountChange}
                    selectedAccounts={selectedAccounts}
                    accountOptions={infra_accounts}
                    disabled={loading}
                  />
                </div>
                {/* region dropdown */}
                <div className="w-60">
                  <RegionDropdown
                    onRegionChange={handleRegionChange}
                    selectedRegions={selectedRegions}
                    disabled={loading}
                  />
                </div>
                {/* run scan button */}
                <Button
                  type="primary"
                  icon={loading ? null : <Play className="w-4 h-4" />}
                  onClick={() => handleScan("run_scan")}
                  disabled={loading}
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                >
                  {loading ? (
                    <span>
                      Running Scan&nbsp;&nbsp;
                      <Spinner />
                    </span>
                  ) : (
                    <span>Run Scan</span>
                  )}
                </Button>
              </div>
            </div>
          </div>

          {/* note */}
          {/* <div>
            <GetNote note="VPC Flow Logs should be enabled via Amazon CloudWatch Logs and the name should be sec360-vpc-flow-logs" />
          </div> */}

          {/* Horizontal line after dropdowns and run scan button */}
          <div className="mt-6 border-t border-gray-200 dark:border-gray-700"></div>

          {/* dropdown for selecting account to view report */}
          <div className="my-6 flex items-center gap-4">
            <span className="text-sm font-medium text-slate-600 dark:text-slate-400">
              View Report for Account:
            </span>
            {/* scan type dropdown for report */}
            <div className="w-40">
              <ScanTypeDropdown
                onScanTypeChange={(value) => {
                  setSelectedReportScanTypes(value);
                  handleReportAccountChange(
                    selectedReportAccount,
                    false,
                    value
                  );
                }}
                selectedScanTypes={selectedReportScanTypes}
                disabled={s3FetchLoading || loading}
                placeholder="Select scan types for report"
              />
            </div>
            <div className="w-60">
              {/* account dropdown */}
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
              disabled={isThreatDetectionSampleReport}
              className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 font-semibold px-6 rounded-xl rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 disabled:opacity-70 disabled:text-white"
            >
              {s3FetchLoading && isThreatDetectionSampleReport ? (
                <span>
                  Loading Sample Report&nbsp;&nbsp;
                  <Spinner />
                </span>
              ) : (
                <span>View Sample Report</span>
              )}
            </Button>
          </div>
          {/* Findings cards */}
          <ThreatDetectionCards
            lastScannedDetails={lastScannedDetails}
            loading={loading}
            s3FetchLoading={s3FetchLoading}
            filteredCombinedFindings={filteredCombinedFindings}
            isThreatDetectionSampleReport={isThreatDetectionSampleReport}
            hiddenFindings={hiddenFindings}
            handleHideFinding={handleHideFinding}
            handleCardClick={handleCardClick}
            showModal={showModal}
            closeModal={closeModal}
            selectedFinding={selectedFinding}
            token={token}
          />

          {/* Vpc flogs Name input Modal */}
          <VpcFlowLogModal
            open={showVpcLogModal}
            onClose={() => setShowVpcLogModal(false)}
            onDone={() => {
              setShowVpcLogModal(false);
              handleScan("vpc_flow_log_modal");
            }}
            accounts={selectedAccounts}
            regions={selectedRegions}
            vpcFlowLogNames={vpcFlowLogNames}
            setVpcFlowLogNames={setVpcFlowLogNames}
            areAllVpcNamesFilled={areAllVpcNamesFilled}
            setShowVpcLogModal={setShowVpcLogModal}
            showVpcLogModal={showVpcLogModal}
            selectedAccounts={selectedAccounts}
            selectedRegions={selectedRegions}
            optionsMap={optionsMap}
            setOptionsMap={setOptionsMap}
          />
        </div>
      </div>
    </div>
  );
}

export default ThreatDetection;
