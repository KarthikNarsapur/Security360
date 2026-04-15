"use client";

import { useEffect, useState } from "react";
import { IoArrowBack } from "react-icons/io5";
import { FaTrash, FaEdit, FaCheck, FaTimes } from "react-icons/fa";
import Cookies from "js-cookie";
import { useNavigate } from "react-router-dom";
import { notifyError, notifyInfo, notifySuccess } from "./Notification";
import { fetchUserDetails } from "./Utils";
import { Spin } from "antd";
import { LoadingOutlined } from "@ant-design/icons";

function AccountsPage() {
  const navigate = useNavigate();

  const [infraAccounts, setInfraAccounts] = useState([]);
  const [eksAccounts, setEksAccounts] = useState([]);
  const [editingAccount, setEditingAccount] = useState(null);
  const [newAccountName, setNewAccountName] = useState("");
  const [isSaving, setIsSaving] = useState(false);
  const [deletingAccount, setDeletingAccount] = useState(null);

  useEffect(() => {
    const getUserData = async () => {
      const result = await fetchUserDetails({ navigate });
    };
    getUserData();
  }, []);

  // Load accounts from cookies
  useEffect(() => {
    try {
      const infra = JSON.parse(localStorage.getItem("account_details") || "[]") || [];
      const eks = JSON.parse(localStorage.getItem("eks_account_details") || "[]") || [];
      setInfraAccounts(infra);
      setEksAccounts(eks);
    } catch (e) {
      console.error("Error reading accounts from cookies:", e);
      setInfraAccounts([]);
      setEksAccounts([]);
    }
  }, []);

  const handleDeleteAccount = async (accountId, roleArn, roleType) => {
    const confirmDelete = window.confirm(
      `Are you sure you want to delete the role with Account ID: ${accountId} and Role ARN: ${roleArn}?`
    );
    if (!confirmDelete) return;

    setDeletingAccount({ accountId, roleArn }); // set loading

    try {
      const backend_url = process.env.REACT_APP_BACKEND_URL;
      const payload = {
        access_token: Cookies.get("access_token"),
        roles: [
          {
            account_id: accountId,
            role_arn: roleArn,
          },
        ],
        role_type: roleType,
      };

      if (!payload.access_token) {
        notifyInfo("Session expired, login again..");
        navigate("/login");
        return;
      }

      const response = await fetch(`${backend_url}/api/deleterole`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const result = await response.json();

      if (result?.status === "ok") {
        // Update local state
        if (roleType === "infra") {
          setInfraAccounts((prev) =>
            prev.filter(
              (a) => !(a.account_id === accountId && a.role_arn === roleArn)
            )
          );
        } else {
          setEksAccounts((prev) =>
            prev.filter(
              (a) => !(a.account_id === accountId && a.role_arn === roleArn)
            )
          );
        }

        // Update cookies to keep them the source of truth
        const accountDetailsKey =
          roleType === "infra" ? "account_details" : "eks_account_details";
        const existing =
          JSON.parse(localStorage.getItem(accountDetailsKey) || "[]") || [];
        const updated = existing.filter(
          (a) => !(a.account_id === accountId && a.role_arn === roleArn)
        );
        localStorage.setItem(accountDetailsKey, JSON.stringify(updated));

        notifySuccess("Role deleted successfully");
      } else {
        notifyError(result.error_message || "Failed to delete role");
      }
    } catch (error) {
      notifyError("Error deleting role");
      console.error("Delete error:", error);
    } finally {
      setDeletingAccount(null);
    }
  };

  const handleEditClick = (item, roleType) => {
    setEditingAccount({ ...item, roleType });
    setNewAccountName(item.account_name || item.name || "");
  };

  const handleCancelEdit = () => {
    setEditingAccount(null);
    setNewAccountName("");
  };

  const handleSaveEdit = async () => {
    if (!newAccountName.trim()) {
      notifyError("Account name cannot be empty");
      return;
    }

    setIsSaving(true);

    try {
      const backend_url = process.env.REACT_APP_BACKEND_URL;
      const payload = {
        access_token: Cookies.get("access_token"),
        role_type: editingAccount.roleType,
        roles: [
          {
            role_arn: editingAccount.role_arn,
            account_id: editingAccount.account_id,
            account_name: newAccountName, // updated name
          },
        ],
      };
      if (!payload.access_token) {
        notifyInfo("Session expired, login again..");
        navigate("/login");
        return;
      }

      const response = await fetch(`${backend_url}/api/updaterole`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const result = await response.json();

      if (result?.status === "ok") {
        const updateList = (list, setFn, cookieKey) => {
          const updated = list.map((a) =>
            a.account_id === editingAccount.account_id &&
              a.role_arn === editingAccount.role_arn
              ? { ...a, account_name: newAccountName }
              : a
          );
          setFn(updated);
          localStorage.setItem(cookieKey, JSON.stringify(updated));
        };

        if (editingAccount.roleType === "infra") {
          updateList(infraAccounts, setInfraAccounts, "account_details");
        } else {
          updateList(eksAccounts, setEksAccounts, "eks_account_details");
        }

        notifySuccess("Account name updated successfully");
        handleCancelEdit();
      } else {
        notifyError(result.error_message || "Failed to update account name");
      }
    } catch (err) {
      console.error("Save error:", err);
      notifyError("Error updating account name");
    } finally {
      setIsSaving(false);
    }
  };

  const handleBackToDashboard = () => {
    navigate("/dashboard");
  };

  const getAccountName = (item) => {
    return item?.account_name || item?.name || item?.accountName || "-";
  };

  // function for account roles
  const renderAccountRoles = (accounts, roleType) => {
    if (!accounts || accounts.length === 0) {
      return (
        <div className="text-center py-8">
          <p className="text-slate-600 dark:text-slate-400 text-lg">
            No {roleType === "infra" ? "Infra" : "Kubernetes"} account roles
            found
          </p>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        {accounts.map((item, idx) => {
          const isEditing =
            editingAccount &&
            editingAccount.account_id === item.account_id &&
            editingAccount.role_arn === item.role_arn;

          return (
            <div
              key={`${item.account_id}-${item.role_arn}-${idx}`}
              className="flex items-center justify-between p-4 bg-gradient-to-r from-slate-50 to-slate-100 dark:from-slate-800 dark:to-slate-700 rounded-xl"
            >
              <div className="flex-1">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Editable Account Name */}
                  <div>
                    <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                      Account Name
                    </label>
                    {isEditing ? (
                      <input
                        type="text"
                        value={newAccountName}
                        onChange={(e) => setNewAccountName(e.target.value)}
                        className="mt-1 w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                        disabled={isSaving}
                      />
                    ) : (
                      <p className="text-lg font-semibold text-slate-900 dark:text-white">
                        {getAccountName(item)}
                      </p>
                    )}
                  </div>

                  <div>
                    <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                      Account ID
                    </label>
                    <p className="text-lg font-semibold text-slate-900 dark:text-white">
                      {item.account_id}
                    </p>
                  </div>

                  <div>
                    <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                      Role ARN
                    </label>
                    <p className="text-lg font-semibold text-slate-900 dark:text-white break-all">
                      {item.role_arn}
                    </p>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="ml-4 flex space-x-3">
                {isEditing ? (
                  isSaving ? (
                    // Loading spinner
                    <div className="flex items-center justify-center space-x-2">
                      <Spin
                        indicator={
                          <LoadingOutlined
                            style={{
                              fontSize: 20,
                              background:
                                "linear-gradient(90deg, #4f46e5, #4338ca)",
                              WebkitBackgroundClip: "text",
                              WebkitTextFillColor: "transparent",
                            }}
                            spin
                          />
                        }
                      />
                      <span className="text-indigo-600 dark:text-slate-200 text-sm font-medium">
                        Saving...
                      </span>
                    </div>
                  ) : (
                    <>
                      {/* Save */}
                      <div className="relative group flex flex-col items-center">
                        <button
                          onClick={handleSaveEdit}
                          disabled={isSaving}
                          className={`p-2 rounded-lg ${isSaving
                            ? "text-green-400 cursor-wait"
                            : "text-green-600 hover:text-green-700 hover:bg-green-50 dark:hover:bg-green-900/20"
                            } transition-all duration-200`}
                        >
                          <FaCheck className="w-5 h-5" />
                        </button>
                        <span className="tooltip-text">Save</span>
                      </div>

                      {/* Cancel */}
                      <div className="relative group flex flex-col items-center">
                        <button
                          onClick={handleCancelEdit}
                          className="p-2 text-slate-600 hover:text-slate-800 hover:bg-slate-50 dark:hover:bg-slate-900/20 rounded-lg transition-all duration-200"
                        >
                          <FaTimes className="w-5 h-5" />
                        </button>
                        <span className="tooltip-text">Cancel</span>
                      </div>
                    </>
                  )
                ) : (
                  <>
                    {/* Edit Button */}
                    <div className="relative group flex flex-col items-center">
                      <button
                        onClick={() => handleEditClick(item, roleType)}
                        className="p-2 text-indigo-600 hover:text-indigo-700 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 rounded-lg transition-all duration-200"
                      >
                        <FaEdit className="w-5 h-5" />
                      </button>
                      <span className="tooltip-text">Edit</span>
                    </div>

                    {/* Delete Button */}
                    <div className="relative group flex flex-col items-center">
                      {deletingAccount &&
                        deletingAccount.accountId === item.account_id &&
                        deletingAccount.roleArn === item.role_arn ? (
                        <div className="flex items-center justify-center space-x-2">
                          <Spin
                            indicator={
                              <LoadingOutlined
                                style={{
                                  fontSize: 20,
                                  color: "#dc2626",
                                }}
                                spin
                              />
                            }
                          />
                          <span className="text-red-600 dark:text-red-400 text-sm font-medium">
                            Deleting...
                          </span>
                        </div>
                      ) : (
                        <button
                          onClick={() =>
                            handleDeleteAccount(
                              item.account_id,
                              item.role_arn,
                              roleType
                            )
                          }
                          className="p-2 text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-all duration-200"
                        >
                          <FaTrash className="w-5 h-5" />
                        </button>
                      )}
                      {!deletingAccount && (
                        <span className="tooltip-text">Delete</span>
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 p-8 flex flex-col items-center">
      <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-2xl shadow-indigo-500/10 w-full max-w-4xl relative overflow-hidden">
        {/* Header with gradient and back button */}
        <div className="h-32 bg-gradient-to-r from-indigo-600 via-indigo-700 to-indigo-800 dark:from-slate-800 dark:via-slate-700 dark:to-slate-600 relative flex items-center px-8">
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent"></div>

          {/* Back Button */}
          <button
            onClick={handleBackToDashboard}
            className="relative z-10 mr-4 p-2 bg-white/20 hover:bg-white/30 backdrop-blur-sm rounded-lg transition-all duration-200 text-white hover:text-indigo-100"
          >
            <IoArrowBack className="w-6 h-6" />
          </button>

          {/* Title & Subtitle to the right of back button */}
          <div className="relative z-10">
            <h1 className="text-3xl font-bold text-white">Accounts</h1>
            <p className="text-indigo-100 dark:text-slate-300 mt-1">
              Manage your linked Infra and Kubernetes account roles.
            </p>
          </div>
        </div>
      </div>

      {/* Accounts Details */}
      <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-2xl shadow-indigo-500/10 w-full max-w-4xl mt-6 p-8 space-y-10">
        {/* Infra Accounts */}
        <section className="space-y-6">
          <h2 className="text-2xl font-bold text-slate-900 dark:text-white">
            Infra Account Roles
          </h2>
          {renderAccountRoles(
            infraAccounts,
            "infra",
            handleDeleteAccount,
            getAccountName
          )}
        </section>

        {/* Kubernetes Accounts */}
        <section className="space-y-6">
          <h2 className="text-2xl font-bold text-slate-900 dark:text-white">
            Kubernetes Account Roles
          </h2>
          {renderAccountRoles(
            eksAccounts,
            "eks",
            handleDeleteAccount,
            getAccountName
          )}
        </section>
      </div>
    </div>
  );
}

export default AccountsPage;
