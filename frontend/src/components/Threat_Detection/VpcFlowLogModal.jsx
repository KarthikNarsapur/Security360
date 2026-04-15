import { useEffect, useState } from "react";
import { Modal, Button, Select, Spin, Tooltip } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import Cookies from "js-cookie";
import { notifyError, notifyInfo, notifySuccess } from "../Notification";
import Spinner from "../UI/Spinner";
import { useNavigate } from "react-router-dom";

const VpcFlowLogModal = ({
  open,
  onClose,
  onDone,
  accounts,
  regions,
  vpcFlowLogNames,
  setVpcFlowLogNames,
  areAllVpcNamesFilled,
  setShowVpcLogModal,
  showVpcLogModal,
  selectedAccounts,
  selectedRegions,
  optionsMap,
  setOptionsMap,
}) => {
  // Map shape: { [accountId]: { [region]: string[] } }
  // const [optionsMap, setOptionsMap] = useState({});
  // Loading state per pair key "accountId|region"
  const [loadingPairs, setLoadingPairs] = useState({});

  const navigate = useNavigate();

  const getKey = (accountId, region) => `${accountId}|${region}`;
  const fetchVpcFlowLogs = async (pairs) => {
    const isOpen = typeof open === "boolean" ? open : !!showVpcLogModal;
    if (!isOpen) return;

    const backend_url = process.env.REACT_APP_BACKEND_URL;
    const access_token = Cookies.get("access_token") || "";
    const username = localStorage.getItem("username") || "";
    if (!access_token || !username) {
      notifyInfo("Session expired, login again..");
      navigate("/login");
      return;
    }

    const payload = {
      username,
      accounts: (selectedAccounts || [])
        .map((acc) => {
          try {
            return JSON.parse(acc);
          } catch {
            return acc;
          }
        })
        .filter((acc) => pairs.some((p) => p.account_id === acc.account_id)),
      regions: Array.from(new Set(pairs.map((p) => p.region))),
    };

    // Mark all account-region pairs as loading
    const nextLoading = {};
    pairs.forEach(({ account_id, region }) => {
      if (account_id && region) nextLoading[`${account_id}|${region}`] = true;
    });
    setLoadingPairs((prev) => ({ ...prev, ...nextLoading }));

    try {
      const response = await fetch(`${backend_url}/api/list-vpc-flow-logs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json();

      if (result?.status === "ok") {
        const data = result.response || {};
        const nextOptionsMap = {};
        Object.entries(data).forEach(([accountId, regionsMap]) => {
          nextOptionsMap[accountId] = {};
          Object.entries(regionsMap).forEach(([region, flowLogs]) => {
            nextOptionsMap[accountId][region] = Array.isArray(flowLogs)
              ? flowLogs
                .filter((fl) => fl.logGroupName)
                .map((fl) => fl.logGroupName)
              : [];
          });
        });
        setOptionsMap(nextOptionsMap);

        // notifications
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
      } else {
        console.log("Failed to fetch VPC Flow Logs");
        notifyError(result?.error_message || "Failed to fetch VPC Flow Logs");
      }
    } catch (err) {
      console.log("Error fetching VPC Flow Logs:", err);
      notifyError("Failed to fetch VPC Flow Logs");
    } finally {
      setLoadingPairs((prev) => {
        const copy = { ...prev };
        pairs.forEach(({ account_id, region }) => {
          delete copy[`${account_id}|${region}`];
        });
        return copy;
      });
    }
  };
  useEffect(() => {
    const isOpen = typeof open === "boolean" ? open : !!showVpcLogModal;
    if (!isOpen) return;

    const allPairs = (selectedAccounts || [])
      .map((acc) => {
        try {
          return JSON.parse(acc);
        } catch {
          return acc;
        }
      })
      .flatMap((parsedAcc) =>
        (selectedRegions || []).map((region) => ({
          account_id: parsedAcc?.account_id || "",
          region,
        }))
      )
      .filter((p) => p.account_id && p.region);

    // Only fetch pairs that are missing in optionsMap
    const missingPairs = allPairs.filter(
      ({ account_id, region }) => !optionsMap[account_id]?.[region]
    );

    if (missingPairs.length) {
      fetchVpcFlowLogs(missingPairs);
    }
  }, [open, showVpcLogModal]);

  const refreshSinglePair = async (accountId, region) => {
    await fetchVpcFlowLogs([{ account_id: accountId, region }]);
  };

  return (
    <div>
      <Modal
        open={typeof open === "boolean" ? open : showVpcLogModal}
        onCancel={onClose ? onClose : () => setShowVpcLogModal(false)}
        closable={false}
        title={
          <div className="text-lg font-semibold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
            Select CloudWatch VPC Flow Log Groups
          </div>
        }
        footer={[
          <Button
            key="cancel"
            onClick={onClose ? onClose : () => setShowVpcLogModal(false)}
            className="!bg-gradient-to-r from-slate-600 to-slate-700 hover:from-slate-700 hover:to-slate-800 text-white hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
          >
            Cancel
          </Button>,
          <Button
            key="done"
            type="primary"
            onClick={onDone}
            disabled={!areAllVpcNamesFilled()}
            className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 disabled:opacity-70 disabled:text-white"
          >
            Done
          </Button>,
        ]}
        className="rounded-2xl shadow-xl"
        styles={{
          body: {
            maxHeight: "60vh",
            overflowY: "auto",
            padding: "1rem",
          },
        }}
      >
        <div className="space-y-6">
          {selectedAccounts.map((acc) => {
            const parsedAcc = (() => {
              try {
                return JSON.parse(acc);
              } catch {
                return acc;
              }
            })();
            const accountId =
              parsedAcc?.account_id || parsedAcc?.accountId || parsedAcc?.id;

            return selectedRegions.map((region) => {
              const key = getKey(accountId, region);
              const options =
                optionsMap?.[accountId]?.[region]?.map((name) => ({
                  label: name,
                  value: name,
                })) || [];

              const value = vpcFlowLogNames?.[accountId]?.[region] || undefined;

              const isLoading = !!loadingPairs[key];

              return (
                <div
                  key={`${accountId}-${region}`}
                  className="bg-white/80 dark:bg-slate-900/80 p-4 rounded-xl shadow-sm border border-indigo-100 dark:border-slate-700"
                >
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    {accountId} — {region}
                  </label>

                  <div className="flex items-center gap-3">
                    <Select
                      showSearch
                      placeholder="Select VPC Flow Log group"
                      optionFilterProp="label"
                      filterOption={(input, option) =>
                        (option?.label || "")
                          .toLowerCase()
                          .includes(input.toLowerCase())
                      }
                      options={options}
                      value={value}
                      onChange={(selected) => {
                        setVpcFlowLogNames((prev) => ({
                          ...prev,
                          [accountId]: {
                            ...(prev[accountId] || {}),
                            [region]: selected,
                          },
                        }));
                      }}
                      style={{ width: "100%" }}
                      disabled={isLoading}
                      notFoundContent={
                        isLoading ? (
                          <Spinner />
                        ) : options.length === 0 ? (
                          <span className="text-gray-400">
                            No VPC Flow Logs available
                          </span>
                        ) : null
                      }
                    />

                    <Tooltip title="Reload VPC Flow Logs">
                      <Button
                        onClick={() => refreshSinglePair(accountId, region)}
                        disabled={isLoading}
                        className="flex items-center justify-center"
                      >
                        {isLoading ? <Spinner /> : <ReloadOutlined />}
                      </Button>
                    </Tooltip>
                  </div>
                </div>
              );
            });
          })}
        </div>
      </Modal>
    </div>
  );
};

export default VpcFlowLogModal;
