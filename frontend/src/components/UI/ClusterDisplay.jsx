import React, { useEffect, useState } from "react";
import RegionDropdown from "./DropDown/RegionDropdown";
import { Button, Modal } from "antd";
import { Play } from "lucide-react";
import Cookies from "js-cookie";
import ClusterSetupModal from "./ClusterSetupModal";
import { notifyError, notifyInfo, notifySuccess } from "../Notification";
import { useNavigate } from "react-router-dom";
import {
  getStatusClasses,
  fetchUserDetails,
  NoDataAvailableMessageComponent,
} from "../Utils";
import AccountDropdown from "./DropDown/AccountDropdown";

const ClusterDisplay = ({
  accountDetails,
  modal,
  darkMode,
  clusters,
  setClusters,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) => {
  const [selectedRegions, setSelectedRegions] = useState([]);
  const [selectedAccounts, setSelectedAccounts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [selectedClusterName, setSelectedClusterName] = useState("");
  const [selectedClusterData, setSelectedClusterData] = useState({});
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

  const eks_accounts =
    JSON.parse(localStorage.getItem("eks_account_details") || "[]") || [];
  const username = localStorage.getItem("username") || "";

  const backend_url = process.env.REACT_APP_BACKEND_URL;

  const handleRegionChange = (regions) => {
    setSelectedRegions(regions);
  };

  const handleAccountChange = (accounts) => {
    setSelectedAccounts(accounts);
  };

  const listEKSClusters = async () => {
    const access_token = Cookies.get("access_token");

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
      username: localStorage.getItem("username"),
      regions: selectedRegions,
      accounts: parsedAccounts || [],
    };

    if (!access_token || !payload.username) {
      notifyInfo("Session expired, login again...");
      navigate("/login");
      return;
    }
    if (!payload.regions || payload.regions.length === 0) {
      notifyInfo("Please select at least one region");
      return;
    }

    if (!payload.accounts || payload.accounts.length === 0) {
      notifyError("Please select at least one account");
      return;
    }

    try {
      setLoading(true);
      const response = await fetch(`${backend_url}/api/listeksclusters`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json();

      // show all toasters notifications
      if (Array.isArray(result.notifications?.success)) {
        result.notifications.success.forEach((msg) => {
          notifySuccess(msg);
        });
      }

      if (Array.isArray(result.notifications?.error)) {
        result.notifications.error.forEach((msg) => {
          notifyError(msg);
        });
      }
      if (result?.status == "ok") {
        setSelectedRegions([]);
        setSelectedAccounts([]);
        setClusters(result.eks_clusters);
      } else {
        console.log("Failed to get clusters");
        notifyError(result.error_message || "Failed to get clusters");
      }
    } catch (err) {
      console.log("Error listing clusters", err);
    } finally {
      setLoading(false);
    }
  };

  const handleGetStarted = (clusterName) => {
    const selectedCluster = clusters.find(
      (cluster) => cluster.cluster_name === clusterName
    );
    setSelectedClusterName(clusterName);
    setSelectedClusterData(selectedCluster || {});
    setModalVisible(true);
  };

  return (
    <div className="p-6 pl-12 bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 min-h-screen">
      <div className="mb-8">
        <div className="mt-2 flex items-center justify-between">
          <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
            EKS Clusters
          </h1>

          <div className="flex items-center gap-4">
            {/* account dropdown */}
            <div className="w-60">
              <AccountDropdown
                onAccountChange={handleAccountChange}
                selectedAccounts={selectedAccounts}
                accountOptions={eks_accounts}
                disabled={loading}
              />
            </div>

            {/* region dropdown */}
            <div className="w-80">
              <RegionDropdown
                onRegionChange={handleRegionChange}
                selectedRegions={selectedRegions}
              />
            </div>
            <Button
              type="primary"
              icon={loading ? null : <Play className="w-4 h-4" />}
              onClick={listEKSClusters}
              loading={loading}
              disabled={loading}
              className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 disabled:text-white"
            >
              {loading ? (
                <span>Listing Clusters...</span>
              ) : (
                <span>List Clusters</span>
              )}
            </Button>
          </div>
        </div>
      </div>

      {/* Cluster Cards */}
      {clusters?.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {clusters.map((cluster, idx) => (
            <div
              key={idx}
              className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 cursor-pointer transition-all duration-200 hover:scale-105 hover:shadow-2xl"
            >
              {/* name */}
              <h2 className="text-xl font-bold text-indigo-700 dark:text-indigo-300 mb-2">
                {cluster.cluster_name || "Unnamed Cluster"}
              </h2>
              {/* status */}
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-600 dark:text-slate-400">
                  Status:
                </span>
                <span
                  className={`text-sm font-bold text-white px-3 py-1 rounded-full bg-gradient-to-r ${getStatusClasses(
                    cluster.status
                  )}`}
                >
                  {cluster.status}
                </span>
              </div>
              {/* version */}
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-600 dark:text-slate-400">
                  Version:
                </span>
                <span className="text-sm font-bold text-slate-900 dark:text-white">
                  {cluster.version}
                </span>
              </div>
              {/* created at */}
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-600 dark:text-slate-400">
                  Created At:
                </span>
                <span className="text-sm font-bold text-slate-900 dark:text-white">
                  {new Date(cluster.created_at).toLocaleString()}
                </span>
              </div>
              {/* account */}
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-600 dark:text-slate-400">
                  Account:
                </span>
                <span className="text-sm font-bold text-slate-900 dark:text-white">
                  {cluster.account_id}
                  {cluster.account_name ? ` (${cluster.account_name})` : ""}
                </span>
              </div>

              {/* region */}
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-600 dark:text-slate-400">
                  Region:
                </span>
                <span className="text-sm font-bold text-slate-900 dark:text-white">
                  {cluster.region}
                </span>
              </div>

              <Button
                type="default"
                onClick={() => handleGetStarted(cluster.cluster_name)}
                className="mt-4 bg-indigo-600 hover:bg-indigo-700 text-white font-medium px-4 py-2 rounded-lg transition-all rounded-xl"
              >
                Get Started
              </Button>
            </div>
          ))}
        </div>
      ) : (
        <NoDataAvailableMessageComponent
          messages={[
            "No clusters found",
            "Please select region and click 'List Clusters' to retrieve the cluster list.",
          ]}
        />
      )}

      {/* Modal */}
      <ClusterSetupModal
        visible={modalVisible}
        onClose={() => setModalVisible(false)}
        clusterName={selectedClusterName}
        clusterData={selectedClusterData}
        modal={modal}
        darkMode={darkMode}
      />
    </div>
  );
};

export default ClusterDisplay;
